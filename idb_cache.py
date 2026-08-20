#!/usr/bin/env python3
"""Publish and restore immutable warm IDB cache generations."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import uuid
from pathlib import Path

from analysis_config import resolve_analysis_config
from init_gamebin import iter_configured_binaries
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    contained_path,
    file_inventory,
    inventory_sha256,
    load_json_object,
    normalized_relative_path,
    reject_reparse_components,
    reject_reparse_points,
    sha256_bytes,
    sha256_file,
    verify_inventory,
    write_canonical_json,
)
from release_workflow_lib.manifests import require_gamever


SCHEMA_VERSION = 1
GENERATION_SUFFIX_PATTERN = re.compile(r"^[0-9]+-[0-9]+$")
GENERATION_PATTERN = re.compile(r"^[0-9a-f]{64}-[0-9]+-[0-9]+$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class IdbCacheError(RuntimeError):
    pass


def _require_text(value: str, label: str) -> str:
    normalized = str(value).strip()
    if not normalized:
        raise IdbCacheError(f"{label} must not be empty")
    return normalized


def _require_generation(value: str) -> str:
    generation = _require_text(value, "generation")
    if not GENERATION_PATTERN.fullmatch(generation):
        raise IdbCacheError(f"invalid cache generation: {generation}")
    return generation


def _require_cache_key(value: str) -> str:
    cache_key = _require_text(value, "cache key").lower()
    if not SHA256_PATTERN.fullmatch(cache_key):
        raise IdbCacheError(f"invalid cache key: {value}")
    return cache_key


def _cache_root(persisted_root: Path, gamever: str) -> Path:
    return contained_path(Path(persisted_root), "idb-cache", gamever)


def _generation_root(persisted_root: Path, gamever: str, generation: str) -> Path:
    return contained_path(_cache_root(persisted_root, gamever), "generations", _require_generation(generation))


def _binary_records(repo_root: Path, gamever: str) -> list[dict]:
    repo_root = Path(repo_root).resolve()
    bin_root = (repo_root / "bin" / gamever).resolve()
    config_path = resolve_analysis_config(gamever, repo_root=repo_root)
    records = []
    for module, platform, binary_path in iter_configured_binaries(repo_root, gamever, config_path):
        binary_path = Path(binary_path).resolve()
        try:
            relative = normalized_relative_path(binary_path.relative_to(bin_root).as_posix())
        except ValueError as exc:
            raise IdbCacheError(f"configured binary escapes bin/{gamever}: {binary_path}") from exc
        if not binary_path.is_file():
            raise IdbCacheError(f"configured binary is missing: {binary_path}")
        records.append(
            {
                "module": module,
                "platform": platform,
                "path": relative,
                "size": binary_path.stat().st_size,
                "sha256": sha256_file(binary_path),
            }
        )
    if not records:
        raise IdbCacheError(f"no configured binaries found for GAMEVER {gamever}")
    return records


def _identity(gamever: str, ida_version: str, binaries: list[dict]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "gamever": gamever,
        "ida_version": _require_text(ida_version, "IDA version"),
        "binaries": binaries,
    }


def _cache_key(gamever: str, ida_version: str, binaries: list[dict]) -> str:
    return sha256_bytes(canonical_json_bytes(_identity(gamever, ida_version, binaries)))


def _ready_payload(*, gamever: str, generation: str, cache_key: str, manifest_sha256: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "gamever": gamever,
        "generation": generation,
        "cache_key": cache_key,
        "manifest_sha256": manifest_sha256,
    }


def _write_ready(persisted_root: Path, gamever: str, payload: dict) -> None:
    cache_root = _cache_root(persisted_root, gamever)
    reject_reparse_components(Path(persisted_root), cache_root)
    write_canonical_json(cache_root / "READY.json", payload)


def _load_generation(
    *,
    persisted_root: Path,
    gamever: str,
    generation: str,
    expected_cache_key: str | None = None,
    expected_manifest_sha256: str | None = None,
) -> tuple[dict, Path]:
    generation = _require_generation(generation)
    generation_root = _generation_root(persisted_root, gamever, generation)
    manifest_path = generation_root / "manifest.json"
    payload_root = generation_root / "payload"
    reject_reparse_components(Path(persisted_root), generation_root)
    if not generation_root.is_dir() or not manifest_path.is_file() or not payload_root.is_dir():
        raise IdbCacheError(f"published IDB cache generation is incomplete: {generation}")
    reject_reparse_points(generation_root)
    manifest = load_json_object(manifest_path)
    manifest_sha256 = sha256_file(manifest_path)
    if expected_manifest_sha256 is not None and manifest_sha256 != _require_cache_key(expected_manifest_sha256):
        raise IdbCacheError(f"IDB cache manifest digest mismatch for generation {generation}")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise IdbCacheError(f"unsupported IDB cache schema for generation {generation}")
    if manifest.get("gamever") != gamever or manifest.get("generation") != generation:
        raise IdbCacheError(f"IDB cache generation identity mismatch: {generation}")
    cache_key = _require_cache_key(manifest.get("cache_key", ""))
    if expected_cache_key is not None and cache_key != _require_cache_key(expected_cache_key):
        raise IdbCacheError(f"IDB cache key mismatch for generation {generation}")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise IdbCacheError(f"IDB cache file inventory is missing for generation {generation}")
    try:
        actual_inventory_sha256 = verify_inventory(payload_root, files)
    except ReleaseWorkflowError as exc:
        raise IdbCacheError(f"IDB cache inventory verification failed for generation {generation}: {exc}") from exc
    if actual_inventory_sha256 != manifest.get("inventory_sha256"):
        raise IdbCacheError(f"IDB cache inventory digest mismatch for generation {generation}")
    binaries = manifest.get("binaries")
    if not isinstance(binaries, list) or not binaries:
        raise IdbCacheError(f"IDB cache binary manifest is missing for generation {generation}")
    return manifest, payload_root


def _pointer_candidate(persisted_root: Path, gamever: str) -> tuple[str, str] | None:
    ready_path = _cache_root(persisted_root, gamever) / "READY.json"
    if not ready_path.is_file():
        return None
    try:
        ready = load_json_object(ready_path)
        if ready.get("schema_version") != SCHEMA_VERSION or ready.get("gamever") != gamever:
            return None
        generation = _require_generation(ready.get("generation", ""))
        manifest_sha256 = _require_cache_key(ready.get("manifest_sha256", ""))
        return generation, manifest_sha256
    except (IdbCacheError, ReleaseWorkflowError):
        return None


def _find_generation(persisted_root: Path, gamever: str, cache_key: str) -> tuple[dict, str] | None:
    candidates = []
    pointer = _pointer_candidate(persisted_root, gamever)
    if pointer is not None:
        candidates.append(pointer)
    generations_root = _cache_root(persisted_root, gamever) / "generations"
    if generations_root.is_dir():
        for path in sorted(generations_root.iterdir(), key=lambda item: item.name, reverse=True):
            if path.is_dir() and GENERATION_PATTERN.fullmatch(path.name):
                candidate = (path.name, None)
                if not any(existing[0] == path.name for existing in candidates):
                    candidates.append(candidate)
    for generation, manifest_sha256 in candidates:
        try:
            manifest, _payload = _load_generation(
                persisted_root=persisted_root,
                gamever=gamever,
                generation=generation,
                expected_cache_key=cache_key,
                expected_manifest_sha256=manifest_sha256,
            )
        except (IdbCacheError, ReleaseWorkflowError):
            continue
        manifest_digest = sha256_file(_generation_root(persisted_root, gamever, generation) / "manifest.json")
        return manifest, manifest_digest
    return None


def probe_cache(*, repo_root: Path, persisted_root: Path, gamever: str, ida_version: str) -> dict:
    try:
        gamever = require_gamever(gamever)
        binaries = _binary_records(repo_root, gamever)
        cache_key = _cache_key(gamever, ida_version, binaries)
        found = _find_generation(Path(persisted_root), gamever, cache_key)
        if found is None:
            return {"cache_hit": False, "cache_key": cache_key, "generation": None}
        manifest, manifest_sha256 = found
        _write_ready(
            Path(persisted_root),
            gamever,
            _ready_payload(
                gamever=gamever,
                generation=manifest["generation"],
                cache_key=cache_key,
                manifest_sha256=manifest_sha256,
            ),
        )
        return {"cache_hit": True, "cache_key": cache_key, "generation": manifest["generation"]}
    except IdbCacheError:
        raise
    except (OSError, ReleaseWorkflowError, ValueError) as exc:
        raise IdbCacheError(str(exc)) from exc


def publish_cache(
    *,
    repo_root: Path,
    persisted_root: Path,
    gamever: str,
    ida_version: str,
    generation_suffix: str,
) -> dict:
    incoming = None
    try:
        gamever = require_gamever(gamever)
        if not GENERATION_SUFFIX_PATTERN.fullmatch(str(generation_suffix)):
            raise IdbCacheError(f"invalid generation suffix: {generation_suffix}")
        repo_root = Path(repo_root).resolve()
        persisted_root = Path(persisted_root)
        binaries = _binary_records(repo_root, gamever)
        cache_key = _cache_key(gamever, ida_version, binaries)
        generation = f"{cache_key}-{generation_suffix}"
        generations_root = _cache_root(persisted_root, gamever) / "generations"
        reject_reparse_components(persisted_root, generations_root)
        generations_root.mkdir(parents=True, exist_ok=True)
        incoming = generations_root / f".incoming-{generation}-{uuid.uuid4().hex}"
        final = _generation_root(persisted_root, gamever, generation)
        if final.exists():
            manifest, _payload = _load_generation(
                persisted_root=persisted_root,
                gamever=gamever,
                generation=generation,
                expected_cache_key=cache_key,
            )
            manifest_sha256 = sha256_file(final / "manifest.json")
        else:
            payload_root = incoming / "payload"
            manifest_binaries = []
            source_bin_root = repo_root / "bin" / gamever
            for binary in binaries:
                relative = normalized_relative_path(binary["path"])
                source_binary = contained_path(source_bin_root, *Path(relative).parts)
                source_database = Path(f"{source_binary}.i64")
                locks = (Path(f"{source_binary}.id0"), Path(f"{source_database}.id0"))
                if not source_database.is_file():
                    raise IdbCacheError(f"warm IDB is missing for configured binary: {source_binary}")
                if any(lock.exists() for lock in locks):
                    raise IdbCacheError(f"warm IDB is locked for configured binary: {source_binary}")
                target_binary = contained_path(payload_root, *Path(relative).parts)
                target_binary.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_binary, target_binary)
                target_database = Path(f"{target_binary}.i64")
                shutil.copy2(source_database, target_database)
                manifest_binaries.append(
                    {
                        **binary,
                        "database_path": normalized_relative_path(f"{relative}.i64"),
                        "database_size": source_database.stat().st_size,
                        "database_sha256": sha256_file(source_database),
                    }
                )
            files = file_inventory(payload_root)
            manifest = {
                **_identity(gamever, ida_version, manifest_binaries),
                "cache_key": cache_key,
                "generation": generation,
                "files": files,
                "inventory_sha256": inventory_sha256(files),
            }
            write_canonical_json(incoming / "manifest.json", manifest)
            verify_inventory(payload_root, files)
            os.replace(incoming, final)
            incoming = None
            manifest_sha256 = sha256_file(final / "manifest.json")
        _write_ready(
            persisted_root,
            gamever,
            _ready_payload(
                gamever=gamever,
                generation=generation,
                cache_key=cache_key,
                manifest_sha256=manifest_sha256,
            ),
        )
        return {"cache_key": cache_key, "generation": generation, "manifest_sha256": manifest_sha256}
    except IdbCacheError:
        raise
    except (OSError, ReleaseWorkflowError, ValueError) as exc:
        raise IdbCacheError(str(exc)) from exc
    finally:
        if incoming is not None and incoming.exists():
            shutil.rmtree(incoming, ignore_errors=True)


def _atomic_copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def restore_cache(
    *,
    repo_root: Path,
    persisted_root: Path,
    gamever: str,
    generation: str,
    expected_cache_key: str,
) -> dict:
    try:
        gamever = require_gamever(gamever)
        expected_cache_key = _require_cache_key(expected_cache_key)
        manifest, payload_root = _load_generation(
            persisted_root=Path(persisted_root),
            gamever=gamever,
            generation=generation,
            expected_cache_key=expected_cache_key,
        )
        destination_bin_root = Path(repo_root).resolve() / "bin" / gamever
        for binary in manifest["binaries"]:
            relative = normalized_relative_path(binary.get("path", ""))
            database_relative = normalized_relative_path(binary.get("database_path", ""))
            if database_relative != f"{relative}.i64":
                raise IdbCacheError(f"invalid database path for cached binary {relative}")
            _atomic_copy(
                contained_path(payload_root, *Path(relative).parts),
                contained_path(destination_bin_root, *Path(relative).parts),
            )
            _atomic_copy(
                contained_path(payload_root, *Path(database_relative).parts),
                contained_path(destination_bin_root, *Path(database_relative).parts),
            )
        restored_binaries = _binary_records(Path(repo_root), gamever)
        restored_cache_key = _cache_key(gamever, manifest["ida_version"], restored_binaries)
        if restored_cache_key != expected_cache_key:
            raise IdbCacheError("restored IDB cache does not match the caller's configured binary identity")
        return {
            "cache_key": expected_cache_key,
            "generation": manifest["generation"],
            "ida_version": manifest["ida_version"],
        }
    except IdbCacheError:
        raise
    except (OSError, ReleaseWorkflowError, ValueError) as exc:
        raise IdbCacheError(str(exc)) from exc


def _write_github_output(path: str | None, values: dict) -> None:
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            if value is None:
                value = ""
            if isinstance(value, bool):
                value = str(value).lower()
            handle.write(f"{key.replace('_', '-')}={value}\n")


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("probe", "publish", "restore"):
        command = commands.add_parser(name)
        command.add_argument("--repo-root", default=".")
        command.add_argument("--persisted-root", required=True)
        command.add_argument("--gamever", required=True)
        command.add_argument("--github-output")
    for name in ("probe", "publish"):
        commands.choices[name].add_argument("--ida-version", required=True)
    commands.choices["publish"].add_argument("--generation-suffix", required=True)
    commands.choices["restore"].add_argument("--generation", required=True)
    commands.choices["restore"].add_argument("--cache-key", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        common = {
            "repo_root": Path(args.repo_root),
            "persisted_root": Path(args.persisted_root),
            "gamever": args.gamever,
        }
        if args.command == "probe":
            result = probe_cache(**common, ida_version=args.ida_version)
        elif args.command == "publish":
            result = publish_cache(
                **common,
                ida_version=args.ida_version,
                generation_suffix=args.generation_suffix,
            )
        else:
            result = restore_cache(
                **common,
                generation=args.generation,
                expected_cache_key=args.cache_key,
            )
    except IdbCacheError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    _write_github_output(args.github_output, result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

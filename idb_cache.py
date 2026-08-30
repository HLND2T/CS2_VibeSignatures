#!/usr/bin/env python3
"""Publish, restore, and prune immutable warm IDB cache generations."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import time
import uuid
from pathlib import Path

from analysis_config import resolve_analysis_config
from init_gamebin import iter_configured_binaries
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.filesystem import remove_tree
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
INCOMING_PREFIX = ".incoming-"
DEFAULT_KEEP_GENERATIONS = 3
DEFAULT_GENERATION_MIN_AGE_HOURS = 24 * 7
DEFAULT_INCOMING_MAX_AGE_HOURS = 24


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


def _require_sha256(value: str, label: str) -> str:
    digest = _require_text(value, label).lower()
    if not SHA256_PATTERN.fullmatch(digest):
        raise IdbCacheError(f"invalid {label}: {value}")
    return digest


def _require_cache_key(value: str) -> str:
    return _require_sha256(value, "cache key")


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


def _cache_identity_binaries(binaries: list[dict]) -> list[dict]:
    identity = []
    for binary in binaries:
        if not isinstance(binary, dict):
            raise IdbCacheError("IDB cache binary manifest contains an invalid record")
        size = binary.get("size")
        if not isinstance(size, int) or size < 0:
            raise IdbCacheError("IDB cache binary manifest contains an invalid size")
        identity.append(
            {
                "module": _require_text(binary.get("module", ""), "binary module"),
                "platform": _require_text(binary.get("platform", ""), "binary platform"),
                "path": normalized_relative_path(binary.get("path", "")),
                "size": size,
                "sha256": _require_sha256(binary.get("sha256", ""), "binary SHA-256"),
            }
        )
    return identity


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
    ready_path = cache_root / "READY.json"
    reject_reparse_components(Path(persisted_root), ready_path)
    expected = canonical_json_bytes(payload)
    try:
        if ready_path.read_bytes() == expected:
            return
    except OSError:
        pass
    write_canonical_json(ready_path, payload)


def _load_generation(
    *,
    persisted_root: Path,
    gamever: str,
    generation: str,
    expected_cache_key: str | None = None,
    expected_manifest_sha256: str | None = None,
    expected_ida_version: str | None = None,
) -> tuple[dict, Path, str]:
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
    if expected_manifest_sha256 is not None and manifest_sha256 != _require_sha256(
        expected_manifest_sha256, "manifest SHA-256"
    ):
        raise IdbCacheError(f"IDB cache manifest digest mismatch for generation {generation}")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise IdbCacheError(f"unsupported IDB cache schema for generation {generation}")
    if manifest.get("gamever") != gamever or manifest.get("generation") != generation:
        raise IdbCacheError(f"IDB cache generation identity mismatch: {generation}")
    binaries = manifest.get("binaries")
    if not isinstance(binaries, list) or not binaries:
        raise IdbCacheError(f"IDB cache binary manifest is missing for generation {generation}")
    cache_key = _require_cache_key(manifest.get("cache_key", ""))
    if expected_cache_key is not None and cache_key != _require_cache_key(expected_cache_key):
        raise IdbCacheError(f"IDB cache key mismatch for generation {generation}")
    ida_version = _require_text(manifest.get("ida_version", ""), "IDA version")
    if expected_ida_version is not None and ida_version != _require_text(expected_ida_version, "expected IDA version"):
        raise IdbCacheError(
            f"IDB cache IDA version mismatch for generation {generation}: "
            f"producer={ida_version} consumer={expected_ida_version}"
        )
    if _cache_key(gamever, ida_version, _cache_identity_binaries(binaries)) != cache_key:
        raise IdbCacheError(f"IDB cache manifest identity disagrees with its cache key: {generation}")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise IdbCacheError(f"IDB cache file inventory is missing for generation {generation}")
    try:
        actual_inventory_sha256 = verify_inventory(payload_root, files)
    except ReleaseWorkflowError as exc:
        raise IdbCacheError(f"IDB cache inventory verification failed for generation {generation}: {exc}") from exc
    if actual_inventory_sha256 != manifest.get("inventory_sha256"):
        raise IdbCacheError(f"IDB cache inventory digest mismatch for generation {generation}")
    _verify_binary_inventory(binaries, files)
    return manifest, payload_root, manifest_sha256


def _verify_binary_inventory(binaries: list[dict], files: list[dict]) -> None:
    file_records = {item.get("path"): item for item in files if isinstance(item, dict)}
    if len(file_records) != len(files):
        raise IdbCacheError("IDB cache inventory contains duplicate or invalid file records")
    expected_paths = set()
    for binary in binaries:
        if not isinstance(binary, dict):
            raise IdbCacheError("IDB cache binary manifest contains an invalid record")
        relative = normalized_relative_path(binary.get("path", ""))
        database_relative = normalized_relative_path(binary.get("database_path", ""))
        if database_relative != f"{relative}.i64":
            raise IdbCacheError(f"invalid database path for cached binary {relative}")
        expected_paths.update((relative, database_relative))
        expected_binary = {
            "path": relative,
            "size": binary.get("size"),
            "sha256": binary.get("sha256"),
        }
        expected_database = {
            "path": database_relative,
            "size": binary.get("database_size"),
            "sha256": binary.get("database_sha256"),
        }
        if file_records.get(relative) != expected_binary:
            raise IdbCacheError(f"cached binary inventory disagrees with its manifest: {relative}")
        if file_records.get(database_relative) != expected_database:
            raise IdbCacheError(f"cached IDB inventory disagrees with its manifest: {database_relative}")
    if set(file_records) != expected_paths:
        raise IdbCacheError("IDB cache payload contains files outside the configured binary manifest")


def _pointer_candidate(persisted_root: Path, gamever: str) -> tuple[str, str] | None:
    ready_path = _cache_root(persisted_root, gamever) / "READY.json"
    if not ready_path.is_file():
        return None
    try:
        ready = load_json_object(ready_path)
        if ready.get("schema_version") != SCHEMA_VERSION or ready.get("gamever") != gamever:
            return None
        generation = _require_generation(ready.get("generation", ""))
        manifest_sha256 = _require_sha256(ready.get("manifest_sha256", ""), "manifest SHA-256")
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
            manifest, _payload, manifest_digest = _load_generation(
                persisted_root=persisted_root,
                gamever=gamever,
                generation=generation,
                expected_cache_key=cache_key,
                expected_manifest_sha256=manifest_sha256,
            )
        except (IdbCacheError, ReleaseWorkflowError):
            continue
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
        incoming = generations_root / f"{INCOMING_PREFIX}{generation}-{uuid.uuid4().hex}"
        final = _generation_root(persisted_root, gamever, generation)
        if final.exists():
            manifest, _payload, manifest_sha256 = _load_generation(
                persisted_root=persisted_root,
                gamever=gamever,
                generation=generation,
                expected_cache_key=cache_key,
            )
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
                    }
                )
            files = file_inventory(payload_root)
            file_records = {item["path"]: item for item in files}
            for binary in manifest_binaries:
                database = file_records[binary["database_path"]]
                binary["database_size"] = database["size"]
                binary["database_sha256"] = database["sha256"]
            _verify_binary_inventory(manifest_binaries, files)
            manifest = {
                **_identity(gamever, ida_version, manifest_binaries),
                "cache_key": cache_key,
                "generation": generation,
                "files": files,
                "inventory_sha256": inventory_sha256(files),
            }
            write_canonical_json(incoming / "manifest.json", manifest)
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
        active_exception = sys.exc_info()[1]
        if incoming is not None and incoming.exists():
            try:
                remove_tree(incoming)
            except OSError as exc:
                message = f"failed to remove incomplete cache publication {incoming}: {exc}"
                if active_exception is None:
                    raise IdbCacheError(message) from exc
                print(f"Warning: {message}; preserving original publication failure", file=sys.stderr)


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
    ida_version: str,
) -> dict:
    try:
        gamever = require_gamever(gamever)
        expected_cache_key = _require_cache_key(expected_cache_key)
        manifest, payload_root, _manifest_sha256 = _load_generation(
            persisted_root=Path(persisted_root),
            gamever=gamever,
            generation=generation,
            expected_cache_key=expected_cache_key,
            expected_ida_version=ida_version,
        )
        destination_bin_root = Path(repo_root).resolve() / "bin" / gamever
        resolved_repo_root = Path(repo_root).resolve()
        for binary in manifest["binaries"]:
            relative = normalized_relative_path(binary.get("path", ""))
            database_relative = normalized_relative_path(binary.get("database_path", ""))
            if database_relative != f"{relative}.i64":
                raise IdbCacheError(f"invalid database path for cached binary {relative}")
            for payload_relative in (relative, database_relative):
                payload_path = contained_path(payload_root, *Path(payload_relative).parts)
                target = contained_path(destination_bin_root, *Path(payload_relative).parts)
                reject_reparse_components(resolved_repo_root, target)
                _atomic_copy(payload_path, target)
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


def prune_cache(
    *,
    persisted_root: Path,
    gamever: str,
    keep_generations: int = DEFAULT_KEEP_GENERATIONS,
    generation_min_age_hours: int = DEFAULT_GENERATION_MIN_AGE_HOURS,
    incoming_max_age_hours: int = DEFAULT_INCOMING_MAX_AGE_HOURS,
    now: float | None = None,
) -> dict:
    try:
        gamever = require_gamever(gamever)
        if keep_generations < 1:
            raise IdbCacheError("keep_generations must be at least 1")
        if generation_min_age_hours < 0 or incoming_max_age_hours < 0:
            raise IdbCacheError("cache retention ages must not be negative")
        persisted_root = Path(persisted_root)
        generations_root = _cache_root(persisted_root, gamever) / "generations"
        reject_reparse_components(persisted_root, generations_root)
        if not generations_root.is_dir():
            return {"removed_generations": [], "removed_incoming": []}
        current_time = time.time() if now is None else float(now)
        pointer = _pointer_candidate(persisted_root, gamever)
        ready_generation = pointer[0] if pointer is not None else None
        generations = []
        incoming = []
        for path in generations_root.iterdir():
            if not path.is_dir():
                continue
            if GENERATION_PATTERN.fullmatch(path.name):
                generations.append(path)
            elif path.name.startswith(INCOMING_PREFIX):
                incoming.append(path)
        generations.sort(key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
        protected = {path.name for path in generations[:keep_generations]}
        if ready_generation is not None:
            protected.add(ready_generation)

        def old_enough(path: Path, hours: int) -> bool:
            return current_time - path.stat().st_mtime >= hours * 60 * 60

        removed_generations = []
        for path in generations:
            if path.name in protected or not old_enough(path, generation_min_age_hours):
                continue
            reject_reparse_points(path)
            remove_tree(path)
            removed_generations.append(path.name)
        removed_incoming = []
        for path in incoming:
            if not old_enough(path, incoming_max_age_hours):
                continue
            reject_reparse_points(path)
            remove_tree(path)
            removed_incoming.append(path.name)
        return {
            "removed_generations": sorted(removed_generations),
            "removed_incoming": sorted(removed_incoming),
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
    for name in ("probe", "publish", "restore", "prune"):
        command = commands.add_parser(name)
        command.add_argument("--persisted-root", required=True)
        command.add_argument("--gamever", required=True)
        command.add_argument("--github-output")
    for name in ("probe", "publish", "restore"):
        commands.choices[name].add_argument("--repo-root", default=".")
        commands.choices[name].add_argument("--ida-version", required=True)
    commands.choices["publish"].add_argument("--generation-suffix", required=True)
    commands.choices["restore"].add_argument("--generation", required=True)
    commands.choices["restore"].add_argument("--cache-key", required=True)
    commands.choices["prune"].add_argument("--keep-generations", type=int, default=DEFAULT_KEEP_GENERATIONS)
    commands.choices["prune"].add_argument(
        "--generation-min-age-hours", type=int, default=DEFAULT_GENERATION_MIN_AGE_HOURS
    )
    commands.choices["prune"].add_argument("--incoming-max-age-hours", type=int, default=DEFAULT_INCOMING_MAX_AGE_HOURS)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        common = {
            "persisted_root": Path(args.persisted_root),
            "gamever": args.gamever,
        }
        if args.command == "probe":
            result = probe_cache(**common, repo_root=Path(args.repo_root), ida_version=args.ida_version)
        elif args.command == "publish":
            result = publish_cache(
                **common,
                repo_root=Path(args.repo_root),
                ida_version=args.ida_version,
                generation_suffix=args.generation_suffix,
            )
        elif args.command == "restore":
            result = restore_cache(
                **common,
                repo_root=Path(args.repo_root),
                generation=args.generation,
                expected_cache_key=args.cache_key,
                ida_version=args.ida_version,
            )
        else:
            result = prune_cache(
                **common,
                keep_generations=args.keep_generations,
                generation_min_age_hours=args.generation_min_age_hours,
                incoming_max_age_hours=args.incoming_max_age_hours,
            )
    except IdbCacheError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    _write_github_output(args.github_output, result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

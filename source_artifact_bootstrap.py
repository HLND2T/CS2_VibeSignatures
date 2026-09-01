#!/usr/bin/env python3
"""Materialize source-owned per-symbol artifacts from canonical tracked snapshots."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
import traceback
from pathlib import Path, PurePosixPath

import yaml

import ida_analyze_bin
from gamesymbol_snapshot_lib.errors import SnapshotError
from gamesymbol_snapshot_lib.operations import build_actual_document, check_snapshot_contract
from gamesymbol_snapshot_lib.paths import is_reparse_point, path_from_key
from ida_analyze_util import (
    SymbolArtifactError,
    canonical_symbol_yaml_bytes,
    infer_symbol_artifact_category,
)


GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")
BOOTSTRAP_REPORT_SCHEMA_VERSION = 1


class SourceArtifactBootstrapError(RuntimeError):
    """The snapshot-driven source-artifact bootstrap failed closed."""


def _canonical_json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _reject_casefold_collisions(paths, *, label: str) -> None:
    seen: dict[str, str] = {}
    for raw_path in sorted(os.fspath(path).replace("\\", "/") for path in paths):
        folded = raw_path.casefold()
        previous = seen.get(folded)
        if previous is not None and previous != raw_path:
            raise SourceArtifactBootstrapError(f"{label} casefold collision: {previous!r} and {raw_path!r}")
        seen[folded] = raw_path


def _contained_repository_path(repo_root: Path, value: str | Path, *, label: str) -> Path:
    root = Path(os.path.abspath(repo_root))
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise SourceArtifactBootstrapError(f"{label} must stay inside the repository: {candidate}") from exc
    if not relative.parts:
        raise SourceArtifactBootstrapError(f"{label} must not be the repository root")

    current = root
    if current.exists() and is_reparse_point(current):
        raise SourceArtifactBootstrapError(f"{label} must not traverse a link/reparse point: {current}")
    for part in relative.parts:
        current /= part
        if current.exists() and is_reparse_point(current):
            raise SourceArtifactBootstrapError(f"{label} must not traverse a link/reparse point: {current}")
    return candidate


def _configured_sources(repo_root: Path) -> tuple[tuple[str, Path, Path], ...]:
    config_root = repo_root / "configs"
    snapshot_root = repo_root / "gamesymbols"
    if not config_root.is_dir() or not snapshot_root.is_dir():
        raise SourceArtifactBootstrapError("repository must contain configs/ and gamesymbols/")

    configs: dict[str, Path] = {}
    for path in sorted(config_root.glob("*.yaml")):
        gamever = path.stem
        if not GAMEVER_RE.fullmatch(gamever):
            raise SourceArtifactBootstrapError(f"invalid configured GAMEVER filename: {path.name}")
        configs[gamever] = path

    snapshots: dict[str, Path] = {}
    for path in sorted(snapshot_root.glob("*.yaml")):
        if path.name.endswith(".metadata.yaml"):
            continue
        gamever = path.stem
        if not GAMEVER_RE.fullmatch(gamever):
            raise SourceArtifactBootstrapError(f"invalid snapshot GAMEVER filename: {path.name}")
        snapshots[gamever] = path

    _reject_casefold_collisions(configs, label="configured GAMEVER")
    _reject_casefold_collisions(snapshots, label="snapshot GAMEVER")
    missing_snapshots = sorted(set(configs) - set(snapshots))
    extra_snapshots = sorted(set(snapshots) - set(configs))
    if missing_snapshots or extra_snapshots:
        details = []
        if missing_snapshots:
            details.append(f"missing snapshots: {', '.join(missing_snapshots)}")
        if extra_snapshots:
            details.append(f"snapshots without configs: {', '.join(extra_snapshots)}")
        raise SourceArtifactBootstrapError("configured snapshot set mismatch (" + "; ".join(details) + ")")
    if not configs:
        raise SourceArtifactBootstrapError("no configured GAMEVER snapshots found")
    return tuple((gamever, configs[gamever], snapshots[gamever]) for gamever in sorted(configs))


def _artifact_platform(key: str) -> str:
    filename = PurePosixPath(key).name
    for platform in ("windows", "linux"):
        if filename.endswith(f".{platform}.yaml"):
            return platform
    raise SourceArtifactBootstrapError(f"formal artifact path has no supported platform suffix: {key}")


def _artifact_category(key: str, payload, category_map: dict[str, str]) -> str:
    platform = _artifact_platform(key)
    category = ida_analyze_bin._lookup_expected_input_artifact_category(
        key,
        platform,
        category_map=category_map,
    )
    if category:
        if (
            category == "vfunc"
            and "vtable_name" not in payload
            and not any(field.startswith("vfunc_") for field in payload)
        ):
            return "func"
        return category
    try:
        return infer_symbol_artifact_category(payload)
    except SymbolArtifactError as exc:
        raise SourceArtifactBootstrapError(f"formal artifact has no configured Source2 category: {key}") from exc


def _load_category_map(config_path: Path) -> dict[str, str]:
    try:
        document = ida_analyze_bin._load_config_document(config_path)
    except Exception as exc:
        raise SourceArtifactBootstrapError(f"unable to load analysis config {config_path}: {exc}") from exc
    category_map = ida_analyze_bin._artifact_symbol_category_map_from_document(document)
    for module_entry in document.get("modules", []):
        if not isinstance(module_entry, dict):
            continue
        for symbol_entry in module_entry.get("symbols", []):
            if not isinstance(symbol_entry, dict):
                continue
            category = str(symbol_entry.get("category", "")).strip()
            if not category:
                continue
            aliases = symbol_entry.get("alias", [])
            if not isinstance(aliases, (list, tuple)):
                aliases = [aliases]
            for alias in aliases:
                text = str(alias or "").strip()
                if not text:
                    continue
                for normalized in {
                    text,
                    text.replace("::", "_"),
                    text.replace("::", "_").replace(".", "_"),
                }:
                    previous = category_map.get(normalized)
                    if previous is not None and previous != category:
                        raise SourceArtifactBootstrapError(
                            f"symbol category alias collision for {normalized!r}: {previous!r} and {category!r}"
                        )
                    category_map[normalized] = category
    if not category_map:
        raise SourceArtifactBootstrapError(f"analysis config has no symbol categories: {config_path}")
    return category_map


def _materialize_gamever(
    *,
    repo_root: Path,
    staging_root: Path,
    gamever: str,
    config_path: Path,
    snapshot_path: Path,
) -> tuple[dict, list[dict]]:
    _contained_repository_path(repo_root, config_path, label="analysis config")
    _contained_repository_path(repo_root, snapshot_path, label="snapshot")
    context = check_snapshot_contract(
        gamever,
        repo_root / "bin",
        config_path,
        snapshot_path,
        artifactdir=staging_root,
    )
    source_files = context.document["files"]
    source_paths = tuple(source_files)
    if set(source_paths) != set(context.contract.formal_paths).intersection(source_paths):
        raise SourceArtifactBootstrapError(f"snapshot {gamever} contains a non-formal artifact path")
    _reject_casefold_collisions((f"{gamever}/{key}" for key in source_paths), label="artifact path")
    category_map = _load_category_map(config_path)

    for key in sorted(source_files):
        target = path_from_key(context.contract.artifact_game_root, key)
        category = _artifact_category(key, source_files[key], category_map)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(canonical_symbol_yaml_bytes(source_files[key], category=category))

    rebuilt = build_actual_document(
        context.contract,
        strict=True,
        schema_version=context.document["schema_version"],
        last_publish_time=context.document.get("last_publish_time"),
        binaries=context.document.get("binaries"),
    )
    if rebuilt["files"] != source_files:
        raise SourceArtifactBootstrapError(f"central serialization changed snapshot payload semantics for {gamever}")

    inventory = []
    for key in sorted(source_files):
        path = path_from_key(context.contract.artifact_game_root, key)
        raw = path.read_bytes()
        inventory.append(
            {
                "path": f"{gamever}/{key}",
                "size": len(raw),
                "sha256": _sha256(raw),
            }
        )
    summary = {
        "game_version": gamever,
        "file_count": len(inventory),
        "inventory_sha256": _sha256(_canonical_json_bytes(inventory)),
    }
    return summary, inventory


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def bootstrap_source_artifacts(
    *,
    repo_root: str | Path = ".",
    artifact_root: str | Path = "bin_artifacts",
    report_path: str | Path | None = None,
    publish: bool = True,
) -> dict:
    repo_root = Path(os.path.abspath(repo_root))
    if not repo_root.is_dir():
        raise SourceArtifactBootstrapError(f"repository root does not exist: {repo_root}")
    destination = _contained_repository_path(repo_root, artifact_root, label="artifact root")
    if destination.exists() and publish:
        raise SourceArtifactBootstrapError(f"artifact root already exists: {destination}")
    if not destination.parent.is_dir():
        raise SourceArtifactBootstrapError(f"artifact root parent does not exist: {destination.parent}")

    report = None
    if report_path is not None:
        report = _contained_repository_path(repo_root, report_path, label="bootstrap report")
        if report == destination or destination in report.parents:
            raise SourceArtifactBootstrapError("bootstrap report must be outside the artifact root")

    sources = _configured_sources(repo_root)
    staging_root = Path(tempfile.mkdtemp(prefix=f".{destination.name}.bootstrap-", dir=destination.parent))
    try:
        summaries = []
        inventory = []
        for gamever, config_path, snapshot_path in sources:
            summary, game_inventory = _materialize_gamever(
                repo_root=repo_root,
                staging_root=staging_root,
                gamever=gamever,
                config_path=config_path,
                snapshot_path=snapshot_path,
            )
            summaries.append(summary)
            inventory.extend(game_inventory)

        result = {
            "schema_version": BOOTSTRAP_REPORT_SCHEMA_VERSION,
            "artifact_root": destination.relative_to(repo_root).as_posix(),
            "published": bool(publish),
            "game_version_count": len(summaries),
            "file_count": len(inventory),
            "aggregate_inventory_sha256": _sha256(_canonical_json_bytes(inventory)),
            "game_versions": summaries,
            "files": inventory,
        }
        if publish:
            os.replace(staging_root, destination)
        if report is not None:
            _atomic_write(report, _canonical_json_bytes(result))
        return result
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root)


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-repo-root", default=".")
    parser.add_argument("-artifactdir", default="bin_artifacts")
    parser.add_argument("-report")
    parser.add_argument("-check", action="store_true", help="Validate and materialize only in temporary storage")
    parser.add_argument("-debug", action="store_true")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        result = bootstrap_source_artifacts(
            repo_root=args.repo_root,
            artifact_root=args.artifactdir,
            report_path=args.report,
            publish=not args.check,
        )
    except (
        SourceArtifactBootstrapError,
        SnapshotError,
        SymbolArtifactError,
        OSError,
        UnicodeError,
        yaml.YAMLError,
    ) as exc:
        print(f"Error: {exc}")
        if args.debug:
            traceback.print_exc()
        return 1

    for item in result["game_versions"]:
        print(f"{item['game_version']}: files={item['file_count']} inventory={item['inventory_sha256']}")
    action = "validated" if args.check else "published"
    print(
        f"Source artifacts {action}: game_versions={result['game_version_count']} "
        f"files={result['file_count']} aggregate={result['aggregate_inventory_sha256']}"
    )
    if args.report:
        print(f"Bootstrap report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Repository contract for source-owned per-symbol YAML artifacts."""

from __future__ import annotations

import hashlib
import json
import argparse
import subprocess
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotConfigError
from gamesymbol_snapshot_lib.paths import ensure_real_tree, is_reparse_point, path_from_key
from source_artifact_schema import SymbolArtifactError, canonical_symbol_yaml_bytes, infer_symbol_artifact_category


class ArtifactContractError(ValueError):
    """A source-owned artifact tree violates its repository contract."""


@dataclass(frozen=True)
class ArtifactInventoryItem:
    path: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class ArtifactContractReport:
    game_version: str
    artifact_root: str
    file_count: int
    required_count: int
    optional_count: int
    inventory_sha256: str
    files: tuple[ArtifactInventoryItem, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "game_version": self.game_version,
            "artifact_root": self.artifact_root,
            "file_count": self.file_count,
            "required_count": self.required_count,
            "optional_count": self.optional_count,
            "inventory_sha256": self.inventory_sha256,
            "files": [item.to_dict() for item in self.files],
        }


def _digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _category_map(config_path: Path) -> dict[str, str]:
    try:
        document = yaml.safe_load(config_path.read_bytes()) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ArtifactContractError(f"unable to read analysis config {config_path}: {exc}") from exc
    categories: dict[str, str] = {}
    for module in document.get("modules", []) if isinstance(document, dict) else []:
        if not isinstance(module, dict):
            continue
        for symbol in module.get("symbols", []) or []:
            if not isinstance(symbol, dict):
                continue
            name = str(symbol.get("name", "")).strip()
            category = str(symbol.get("category", "")).strip()
            if name and category:
                categories[name] = category
            aliases = symbol.get("alias", [])
            if not isinstance(aliases, (list, tuple)):
                aliases = [aliases]
            for alias in aliases:
                text = str(alias or "").strip()
                if text:
                    categories.setdefault(text.replace("::", "_"), category)
    return categories


def _symbol_name(path: str) -> str:
    filename = Path(path).name
    for suffix in (".windows.yaml", ".linux.yaml", ".yaml"):
        if filename.endswith(suffix):
            return filename[: -len(suffix)]
    return filename


def _category_for(path: str, payload: object, categories: dict[str, str]) -> str:
    category = categories.get(_symbol_name(path))
    if category:
        if (
            category == "vfunc"
            and isinstance(payload, dict)
            and "vtable_name" not in payload
            and not any(key.startswith("vfunc_") for key in payload)
        ):
            return "func"
        return category
    try:
        return infer_symbol_artifact_category(payload)
    except SymbolArtifactError as exc:
        raise ArtifactContractError(f"unable to determine Source2 category for {path}") from exc


def _reject_case_collisions(paths: list[str]) -> None:
    spellings: dict[str, str] = {}
    for path in sorted(paths):
        folded = path.casefold()
        prior = spellings.get(folded)
        if prior is not None and prior != path:
            raise ArtifactContractError(f"artifact path casefold collision: {prior!r} and {path!r}")
        spellings[folded] = path


def _git_tracked_paths(repo_root: Path, prefix: str) -> set[str]:
    arguments = ["git", "-C", str(repo_root), "ls-files"]
    if prefix:
        arguments.extend(["--", prefix])
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ArtifactContractError(result.stderr.strip() or "git ls-files failed")
    return {line.replace("\\", "/") for line in result.stdout.splitlines() if line}


def _reject_legacy_tracked_outputs(repo_root: Path) -> None:
    tracked = _git_tracked_paths(repo_root, "")
    legacy = sorted(
        path
        for path in tracked
        if path.startswith("bin/")
        and path.lower().endswith(".yaml")
        or path.startswith(("gamesymbols/", "gamedata/", "release-manifests/"))
    )
    if legacy:
        raise ArtifactContractError(
            "legacy generated outputs must not be tracked:\n" + "\n".join(f"  {path}" for path in legacy)
        )


def _iter_tree_files(game_root: Path):
    if not game_root.exists():
        return
    for current, directories, files in os.walk(game_root, followlinks=False):
        current_path = Path(current)
        for directory in list(directories):
            child = current_path / directory
            if is_reparse_point(child):
                raise ArtifactContractError(f"artifact must not traverse a link/reparse point: {child}")
        for filename in files:
            path = current_path / filename
            if is_reparse_point(path):
                raise ArtifactContractError(f"artifact must not be a link/reparse point: {path}")
            if path.suffix.lower() != ".yaml":
                raise ArtifactContractError(f"non-YAML file in artifact tree: {path}")
            yield path


def build_game_artifact_inventory(
    *,
    repo_root: str | Path,
    config_path: str | Path,
    game_version: str,
    artifact_root: str | Path = "bin_artifacts",
    require_tracked: bool = False,
) -> ArtifactContractReport:
    repo_root = Path(repo_root).resolve()
    config_path = Path(config_path)
    if not config_path.is_absolute():
        config_path = repo_root / config_path
    artifact_root = Path(artifact_root)
    if not artifact_root.is_absolute():
        artifact_root = repo_root / artifact_root
    artifact_root = artifact_root.resolve()
    game_root = artifact_root / str(game_version)
    try:
        ensure_real_tree(artifact_root, game_root)
    except SnapshotConfigError as exc:
        raise ArtifactContractError(str(exc)) from exc
    if not config_path.is_file():
        raise ArtifactContractError(f"analysis config is missing: {config_path}")

    try:
        contract = load_contract(
            config_path,
            str(game_version),
            artifact_root.parent / "bin",
            artifactdir=artifact_root,
        )
    except SnapshotConfigError as exc:
        raise ArtifactContractError(f"invalid analysis contract: {exc}") from exc
    formal_paths = set(contract.formal_paths)
    required_paths = set(contract.required_paths)
    actual_paths = set()
    for path in _iter_tree_files(game_root):
        relative = path.relative_to(game_root).as_posix()
        actual_paths.add(relative)
    _reject_case_collisions(sorted(actual_paths))
    extra = sorted(actual_paths - formal_paths)
    missing = sorted(required_paths - actual_paths)
    if extra:
        raise ArtifactContractError("extra/stale artifacts:\n" + "\n".join(f"  {path}" for path in extra))
    if missing:
        raise ArtifactContractError("missing required artifacts:\n" + "\n".join(f"  {path}" for path in missing))

    categories = _category_map(config_path)
    items: list[ArtifactInventoryItem] = []
    for key in sorted(actual_paths):
        target = path_from_key(game_root, key)
        try:
            raw = target.read_bytes()
            payload = yaml.safe_load(raw)
            canonical = canonical_symbol_yaml_bytes(payload, category=_category_for(key, payload, categories))
        except (OSError, UnicodeError, yaml.YAMLError, SymbolArtifactError) as exc:
            raise ArtifactContractError(f"invalid canonical artifact {key}: {exc}") from exc
        if raw != canonical:
            raise ArtifactContractError(f"artifact is not canonical: {key}")
        items.append(
            ArtifactInventoryItem(
                f"bin_artifacts/{game_version}/{key}",
                len(raw),
                f"sha256:{hashlib.sha256(raw).hexdigest()}",
            )
        )

    if require_tracked:
        prefix = f"bin_artifacts/{game_version}/"
        tracked = _git_tracked_paths(repo_root, prefix)
        actual_tracked = {item.path for item in items}
        if tracked != actual_tracked:
            raise ArtifactContractError(
                f"tracked artifact inventory mismatch: tracked={sorted(tracked)!r} actual={sorted(actual_tracked)!r}"
            )

    return ArtifactContractReport(
        str(game_version),
        str(artifact_root),
        len(items),
        len(required_paths),
        len(actual_paths - required_paths),
        _digest([item.to_dict() for item in items]),
        tuple(items),
    )


def validate_repository_artifact_contract(
    *,
    repo_root: str | Path = ".",
    game_versions: list[str] | tuple[str, ...] | None = None,
    artifact_root: str | Path = "bin_artifacts",
    require_tracked: bool = True,
) -> dict[str, object]:
    repo_root = Path(repo_root).resolve()
    _reject_legacy_tracked_outputs(repo_root)
    artifact_root_path = Path(artifact_root)
    if artifact_root_path.is_absolute() or artifact_root_path.as_posix().strip("/") != "bin_artifacts":
        raise ArtifactContractError("repository artifact root must be bin_artifacts")
    if game_versions is None:
        config_root = repo_root / "configs"
        game_versions = tuple(sorted(path.stem for path in config_root.glob("*.yaml")))
    configured_versions = set(game_versions)
    tracked_artifacts = _git_tracked_paths(repo_root, "bin_artifacts/")
    unconfigured = sorted(
        path
        for path in tracked_artifacts
        if len(Path(path).parts) < 3 or Path(path).parts[1] not in configured_versions
    )
    if unconfigured:
        raise ArtifactContractError(
            "tracked artifacts for unconfigured GAMEVER:\n" + "\n".join(f"  {path}" for path in unconfigured)
        )
    reports = []
    for game_version in game_versions:
        config_path = repo_root / "configs" / f"{game_version}.yaml"
        reports.append(
            build_game_artifact_inventory(
                repo_root=repo_root,
                config_path=config_path,
                game_version=game_version,
                artifact_root=artifact_root,
                require_tracked=require_tracked,
            ).to_dict()
        )
    files = [item for report in reports for item in report["files"]]
    return {
        "schema_version": 1,
        "artifact_root": Path(artifact_root).as_posix(),
        "game_version_count": len(reports),
        "file_count": len(files),
        "inventory_sha256": _digest(files),
        "game_versions": reports,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-repo-root", default=".")
    parser.add_argument("-gamever", action="append")
    parser.add_argument("-artifactdir", default="bin_artifacts")
    parser.add_argument("-allow-untracked", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = validate_repository_artifact_contract(
            repo_root=args.repo_root,
            game_versions=args.gamever,
            artifact_root=args.artifactdir,
            require_tracked=not args.allow_untracked,
        )
    except (ArtifactContractError, OSError, UnicodeError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

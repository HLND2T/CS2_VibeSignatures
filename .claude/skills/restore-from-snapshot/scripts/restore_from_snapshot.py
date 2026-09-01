#!/usr/bin/env python3
"""Restore repository symbol YAML from a trusted or explicitly forced snapshot."""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPOSITORY_ROOT))

from analysis_config import AnalysisConfigError, resolve_analysis_config  # noqa: E402
from gamesymbol_snapshot_lib.codec import canonical_yaml_bytes, parse_snapshot_bytes  # noqa: E402
from gamesymbol_snapshot_lib.errors import SnapshotConfigError, SnapshotMismatchError  # noqa: E402
from gamesymbol_snapshot_lib.operations import restore_snapshot  # noqa: E402
from gamesymbol_snapshot_lib.paths import ensure_real_tree, iter_yaml_paths, path_from_key  # noqa: E402

GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")


class RestoreSnapshotError(Exception):
    """Raised when snapshot restoration cannot safely continue."""


def repository_root() -> Path:
    """Require execution from the repository that owns this project-level skill."""
    expected = REPOSITORY_ROOT
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=expected,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RestoreSnapshotError(f"unable to run git rev-parse: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RestoreSnapshotError(f"git rev-parse failed with exit code {result.returncode}: {detail}")
    actual = Path(result.stdout.strip()).resolve()
    if actual != expected:
        raise RestoreSnapshotError(f"skill is not running in its owning repository: {actual}")
    return actual


def load_versions(config_path: Path) -> list[str]:
    """Load ordered, unique GAMEVER tags from download.yaml."""
    try:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise RestoreSnapshotError(f"unable to read {config_path}: {exc}") from exc
    downloads = document.get("downloads") if isinstance(document, dict) else None
    if not isinstance(downloads, list):
        raise RestoreSnapshotError("download.yaml field 'downloads' must be a list")
    versions = []
    for index, entry in enumerate(downloads):
        tag = entry.get("tag") if isinstance(entry, dict) else None
        if not isinstance(tag, str) or not GAMEVER_RE.fullmatch(tag):
            raise RestoreSnapshotError(f"download.yaml downloads[{index}].tag is not a valid GAMEVER")
        versions.append(tag)
    if not versions:
        raise RestoreSnapshotError("download.yaml contains no GAMEVER entries")
    duplicates = sorted({version for version in versions if versions.count(version) > 1})
    if duplicates:
        raise RestoreSnapshotError(f"download.yaml contains duplicate GAMEVER entries: {', '.join(duplicates)}")
    return versions


def find_snapshot(root: Path, gamever: str) -> Path | None:
    """Return the tracked snapshot for one exact GAMEVER."""
    snapshot = root / "gamesymbols" / f"{gamever}.yaml"
    return snapshot if snapshot.is_file() else None


def find_base_snapshot(root: Path, gamever: str, versions: list[str]) -> Path | None:
    """Return the newest earlier tracked snapshot in download.yaml order."""
    target_index = versions.index(gamever)
    for candidate in reversed(versions[:target_index]):
        snapshot = find_snapshot(root, candidate)
        if snapshot is not None:
            return snapshot
    return None


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
        if temporary and temporary.exists():
            temporary.unlink()


def force_restore_base_snapshot(root: Path, gamever: str, base_gamever: str, snapshot: Path) -> None:
    """Replace target YAMLs without target-version or config-contract trust checks."""
    try:
        document = parse_snapshot_bytes(snapshot.read_bytes())
    except (OSError, SnapshotConfigError) as exc:
        raise RestoreSnapshotError(f"unable to read forced base snapshot {snapshot}: {exc}") from exc
    if document["game_version"] != base_gamever:
        raise RestoreSnapshotError(
            f"base snapshot filename GAMEVER {base_gamever} does not match payload {document['game_version']}"
        )

    artifactdir = root / "bin_artifacts"
    game_root = artifactdir / gamever
    game_root.mkdir(parents=True, exist_ok=True)
    try:
        ensure_real_tree(artifactdir, game_root)
        targets = [
            (path_from_key(game_root, key), canonical_yaml_bytes(payload)) for key, payload in document["files"].items()
        ]
        for path in list(iter_yaml_paths(game_root)):
            path.unlink()
        for target, data in targets:
            _atomic_write(target, data)
    except (OSError, SnapshotConfigError) as exc:
        raise RestoreSnapshotError(f"forced base snapshot restore failed: {exc}") from exc


def restore(root: Path, gamever: str, force_base_gamever: str | None = None, *, replace: bool = False) -> dict:
    """Restore one trusted snapshot or explicitly force an earlier snapshot."""
    versions = load_versions(root / "download.yaml")
    if gamever not in versions:
        raise RestoreSnapshotError(f"GAMEVER {gamever} is absent from download.yaml")
    snapshot = find_snapshot(root, gamever)
    suggested = find_base_snapshot(root, gamever, versions) if snapshot is None else None
    if force_base_gamever is not None:
        if replace:
            raise RestoreSnapshotError("--replace cannot be combined with --force-base-snapshot")
        if snapshot is not None:
            raise RestoreSnapshotError(
                f"GAMEVER {gamever} already has a trusted snapshot; forced restore is not allowed"
            )
        if not GAMEVER_RE.fullmatch(force_base_gamever):
            raise RestoreSnapshotError(f"invalid base GAMEVER: {force_base_gamever}")
        base_snapshot = find_snapshot(root, force_base_gamever)
        if base_snapshot is None:
            raise RestoreSnapshotError(f"base snapshot gamesymbols/{force_base_gamever}.yaml does not exist")
        force_restore_base_snapshot(root, gamever, force_base_gamever, base_snapshot)
        return {"mode": "forced-base", "gamever": gamever, "base_gamever": force_base_gamever}
    if snapshot is None:
        return {
            "mode": "unavailable",
            "gamever": gamever,
            "suggested_base_gamever": suggested.stem if suggested is not None else None,
        }
    try:
        config = resolve_analysis_config(gamever, repo_root=root)
        restore_snapshot(
            gamever,
            root / "bin",
            config,
            snapshot,
            replace=replace,
            artifactdir=root / "bin_artifacts",
        )
    except (AnalysisConfigError, SnapshotConfigError, SnapshotMismatchError, OSError) as exc:
        raise RestoreSnapshotError(str(exc)) from exc
    return {"mode": "trusted", "gamever": gamever, "replaced": replace}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gamever", help="Exact target GAMEVER")
    parser.add_argument("--replace", action="store_true", help="Replace all target YAML for a trusted snapshot")
    parser.add_argument(
        "--force-base-snapshot",
        metavar="BASE_GAMEVER",
        help="Replace target YAML from gamesymbols/BASE_GAMEVER.yaml without target trust checks",
    )
    args = parser.parse_args(argv)
    try:
        result = restore(
            repository_root(),
            args.gamever,
            args.force_base_snapshot,
            replace=args.replace,
        )
    except RestoreSnapshotError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if result["mode"] == "trusted":
        suffix = " with replacement" if result["replaced"] else ""
        print(f"Symbol snapshot: restored and round-trip verified{suffix}")
    elif result["mode"] == "forced-base":
        print(f"Symbol snapshot: force-restored without trust checks from gamesymbols/{result['base_gamever']}.yaml")
    else:
        print("Symbol snapshot: unavailable; no YAML restored")
        if result["suggested_base_gamever"] is not None:
            print(f"Suggested base snapshot: gamesymbols/{result['suggested_base_gamever']}.yaml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

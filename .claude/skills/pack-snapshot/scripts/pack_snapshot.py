#!/usr/bin/env python3
"""Pack and verify one repository game-symbol snapshot."""

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPOSITORY_ROOT))

from analysis_config import AnalysisConfigError, resolve_analysis_config  # noqa: E402
from gamesymbol_snapshot_lib.errors import SnapshotConfigError, SnapshotMismatchError  # noqa: E402
from gamesymbol_snapshot_lib.operations import pack_snapshot, verify_snapshot  # noqa: E402

GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")


class PackSnapshotError(Exception):
    """Raised when a project snapshot cannot be packed safely."""


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
        raise PackSnapshotError(f"unable to run git rev-parse: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise PackSnapshotError(f"git rev-parse failed with exit code {result.returncode}: {detail}")
    actual = Path(result.stdout.strip()).resolve()
    if actual != expected:
        raise PackSnapshotError(f"skill is not running in its owning repository: {actual}")
    return actual


def pack(root: Path, gamever: str) -> dict:
    """Pack the exact configured YAML set and verify the written snapshot."""
    if not GAMEVER_RE.fullmatch(gamever):
        raise PackSnapshotError(f"invalid GAMEVER: {gamever}")
    try:
        config = resolve_analysis_config(gamever, repo_root=root)
        bindir = root / "bin"
        artifactdir = root / "bin_artifacts"
        snapshot = root / "gamesymbols" / f"{gamever}.yaml"
        data = pack_snapshot(gamever, bindir, config, snapshot, artifactdir=artifactdir)
        verify_snapshot(gamever, bindir, config, snapshot, artifactdir=artifactdir)
    except (AnalysisConfigError, SnapshotConfigError, SnapshotMismatchError, OSError) as exc:
        raise PackSnapshotError(str(exc)) from exc
    return {"gamever": gamever, "snapshot": snapshot, "size": len(data)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gamever", help="Exact GAMEVER to pack")
    args = parser.parse_args(argv)
    try:
        result = pack(repository_root(), args.gamever)
    except PackSnapshotError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    relative = result["snapshot"].relative_to(REPOSITORY_ROOT).as_posix()
    print(f"Packed snapshot: {relative} ({result['size']} bytes)")
    print("Snapshot verification: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

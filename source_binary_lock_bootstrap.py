#!/usr/bin/env python3
"""One-shot migration from historical snapshots to source-owned binary locks."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml

from binary_lock import (
    BinaryLockError,
    build_binary_lock,
    canonical_json_bytes,
    verify_binary_root,
    write_binary_lock,
)
from gamesymbol_snapshot_lib.config import SnapshotConfigError, load_contract
from release_workflow_lib.hashing import sha256_bytes
from trusted_yaml import load_yaml


GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class SourceBinaryLockBootstrapError(RuntimeError):
    """Raised when historical binary lock migration cannot be proven safe."""


def _git_blob(repo_root: Path, revision: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "cat-file", "blob", f"{revision}:{path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise SourceBinaryLockBootstrapError(detail or f"unable to read historical Git blob: {path}")
    return result.stdout


def bootstrap_binary_locks(
    *,
    repo_root: str | Path,
    snapshot_revision: str,
    output_root: str | Path = "binary_locks",
    check: bool = False,
    verify_local_binaries: bool = False,
) -> dict:
    repo_root = Path(repo_root).resolve()
    snapshot_revision = snapshot_revision.lower()
    if not repo_root.is_dir() or not SHA_RE.fullmatch(snapshot_revision):
        raise SourceBinaryLockBootstrapError("repository root or snapshot revision is invalid")
    output_root = Path(output_root)
    if not output_root.is_absolute():
        output_root = repo_root / output_root
    output_root = output_root.resolve(strict=False)
    try:
        output_root.relative_to(repo_root)
    except ValueError as exc:
        raise SourceBinaryLockBootstrapError("binary lock output root must stay inside the repository") from exc
    if output_root == repo_root:
        raise SourceBinaryLockBootstrapError("binary lock output root must not be the repository root")

    config_paths = sorted((repo_root / "configs").glob("*.yaml"))
    if not config_paths:
        raise SourceBinaryLockBootstrapError("repository has no configured GAMEVER files")
    download_payload = (repo_root / "download.yaml").read_bytes()
    records = []
    expected_names = set()
    for config_path in config_paths:
        game_version = config_path.stem
        if not GAMEVER_RE.fullmatch(game_version):
            raise SourceBinaryLockBootstrapError(f"invalid configured GAMEVER filename: {config_path.name}")
        expected_names.add(f"{game_version}.json")
        try:
            contract = load_contract(
                config_path,
                game_version,
                repo_root / "bin",
                artifactdir=repo_root / "bin_artifacts",
            )
        except SnapshotConfigError as exc:
            raise SourceBinaryLockBootstrapError(f"unable to load binary targets for {game_version}: {exc}") from exc
        snapshot_payload = _git_blob(repo_root, snapshot_revision, f"gamesymbols/{game_version}.yaml")
        try:
            snapshot = load_yaml(snapshot_payload) or {}
        except (UnicodeError, yaml.YAMLError) as exc:
            raise SourceBinaryLockBootstrapError(f"historical snapshot is invalid: {game_version}") from exc
        binaries = snapshot.get("binaries") if isinstance(snapshot, dict) else None
        if not isinstance(binaries, dict):
            raise SourceBinaryLockBootstrapError(f"historical snapshot has no binary inventory: {game_version}")
        try:
            document = build_binary_lock(
                game_version=game_version,
                download_payload=download_payload,
                binary_targets=contract.binary_targets,
                binaries=binaries,
            )
            if verify_local_binaries:
                verify_binary_root(document, repo_root / "bin" / game_version)
        except BinaryLockError as exc:
            raise SourceBinaryLockBootstrapError(f"binary lock validation failed for {game_version}: {exc}") from exc
        payload = canonical_json_bytes(document)
        path = output_root / f"{game_version}.json"
        if check:
            try:
                actual = path.read_bytes()
            except OSError as exc:
                raise SourceBinaryLockBootstrapError(f"unable to read binary lock {path}: {exc}") from exc
            if actual != payload:
                raise SourceBinaryLockBootstrapError(f"binary lock drifted from historical source: {game_version}")
        else:
            write_binary_lock(path, document)
        records.append(
            {
                "game_version": game_version,
                "path": path.relative_to(repo_root).as_posix(),
                "binary_count": sum(len(platforms) for platforms in binaries.values()),
                "sha256": f"sha256:{sha256_bytes(payload)}",
            }
        )

    if output_root.is_dir():
        actual_names = {path.name for path in output_root.glob("*.json")}
        if actual_names != expected_names:
            raise SourceBinaryLockBootstrapError("binary lock file set does not match configured GAMEVERs")
    return {
        "schema_version": 1,
        "snapshot_revision": snapshot_revision,
        "game_version_count": len(records),
        "binary_count": sum(item["binary_count"] for item in records),
        "locks": records,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--snapshot-revision", required=True)
    parser.add_argument("--output-root", default="binary_locks")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify-local-binaries", action="store_true")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = bootstrap_binary_locks(
            repo_root=args.repo_root,
            snapshot_revision=args.snapshot_revision,
            output_root=args.output_root,
            check=args.check,
            verify_local_binaries=args.verify_local_binaries,
        )
    except (OSError, SourceBinaryLockBootstrapError) as exc:
        print(f"Binary lock bootstrap error: {exc}", file=sys.stderr)
        return 1
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

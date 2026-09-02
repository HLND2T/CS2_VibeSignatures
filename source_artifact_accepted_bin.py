#!/usr/bin/env python3
"""Restore or verify binary-only cache data against a source-owned lock."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path, PurePosixPath

from binary_lock import BinaryLockError, load_binary_lock, verify_binary_root
from gamesymbol_snapshot_lib.config import load_contract


class AcceptedBinBridgeError(RuntimeError):
    """The bridge cache cannot establish the exact source binary identity."""


def _load_context(repo_root: Path, gamever: str):
    repo_root = repo_root.resolve()
    contract = load_contract(
        repo_root / "configs" / f"{gamever}.yaml",
        gamever,
        repo_root / "bin",
        artifactdir=repo_root / "bin_artifacts",
    )
    lock = load_binary_lock(
        repo_root / "binary_locks" / f"{gamever}.json",
        game_version=gamever,
        download_payload=(repo_root / "download.yaml").read_bytes(),
        binary_targets=contract.binary_targets,
    )
    return repo_root, contract, lock


def _report(*, gamever: str, lock_sha256: str, cache_hit: bool) -> dict:
    return {
        "schema_version": 1,
        "gamever": gamever,
        "binary_lock_sha256": lock_sha256,
        "cache_hit": cache_hit,
    }


def restore_accepted_bin(*, repo_root: Path, persisted_root: Path, gamever: str, required: bool) -> dict:
    repo_root, contract, lock = _load_context(repo_root, gamever)
    persisted_game_root = persisted_root.resolve() / "bin" / gamever
    try:
        verify_binary_root(lock.document, persisted_game_root)
    except (OSError, BinaryLockError) as exc:
        if required:
            raise AcceptedBinBridgeError(f"required accepted-bin cache is unavailable or invalid: {exc}") from exc
        return _report(gamever=gamever, lock_sha256=lock.sha256, cache_hit=False)

    destination_root = contract.binary_game_root
    for module, platforms in lock.document["binaries"].items():
        for expected in platforms.values():
            filename = PurePosixPath(expected["path"]).name
            source = persisted_game_root / module / filename
            destination = destination_root / module / filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    verify_binary_root(lock.document, destination_root)
    return _report(gamever=gamever, lock_sha256=lock.sha256, cache_hit=True)


def verify_workspace(*, repo_root: Path, gamever: str) -> dict:
    _repo_root, contract, lock = _load_context(repo_root, gamever)
    verify_binary_root(lock.document, contract.binary_game_root)
    return _report(gamever=gamever, lock_sha256=lock.sha256, cache_hit=True)


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    restore = commands.add_parser("restore")
    restore.add_argument("--repo-root", default=".")
    restore.add_argument("--persisted-root", required=True)
    restore.add_argument("--gamever", required=True)
    restore.add_argument("--required", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("--repo-root", default=".")
    verify.add_argument("--gamever", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "restore":
            result = restore_accepted_bin(
                repo_root=Path(args.repo_root),
                persisted_root=Path(args.persisted_root),
                gamever=args.gamever,
                required=args.required,
            )
        else:
            result = verify_workspace(repo_root=Path(args.repo_root), gamever=args.gamever)
    except (AcceptedBinBridgeError, BinaryLockError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

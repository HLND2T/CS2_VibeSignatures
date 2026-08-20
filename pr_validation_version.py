#!/usr/bin/env python3
"""Resolve the GAMEVER analyzed by PR validation before warm-cache dispatch."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

from trusted_yaml import load_yaml_file


SNAPSHOT_PATTERN = re.compile(r"^gamesymbols/[^/]+\.yaml$")


class PrValidationVersionError(RuntimeError):
    pass


def _snapshot_gamever(path: str) -> str:
    if not SNAPSHOT_PATTERN.fullmatch(path):
        raise PrValidationVersionError(f"invalid tracked snapshot path: {path}")
    return PurePosixPath(path).stem


def select_validation_gamever(
    pr_gamever: str,
    tracked_snapshots: list[str],
    latest_snapshot_paths: list[str],
) -> str:
    pr_gamever = str(pr_gamever).strip()
    if not pr_gamever:
        raise PrValidationVersionError("PR GAMEVER is empty")
    tracked_snapshots = sorted(set(tracked_snapshots))
    if not tracked_snapshots:
        return pr_gamever
    same_version = f"gamesymbols/{pr_gamever}.yaml"
    if same_version in tracked_snapshots:
        return pr_gamever
    if len(tracked_snapshots) == 1:
        return _snapshot_gamever(tracked_snapshots[0])
    candidates = [path for path in latest_snapshot_paths if path in tracked_snapshots]
    if len(candidates) != 1:
        raise PrValidationVersionError(f"latest base snapshot publication is ambiguous: {', '.join(candidates)}")
    return _snapshot_gamever(candidates[0])


def _git_lines(repo_root: Path, arguments: list[str]) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise PrValidationVersionError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def resolve_validation_gamever(repo_root: Path, base_ref: str) -> str:
    repo_root = Path(repo_root).resolve()
    document = load_yaml_file(repo_root / "download.yaml")
    downloads = document.get("downloads") if isinstance(document, dict) else None
    if not isinstance(downloads, list) or not downloads or not isinstance(downloads[-1], dict):
        raise PrValidationVersionError("download.yaml has no latest download entry")
    pr_gamever = str(downloads[-1].get("tag", "")).strip()
    tracked = [
        path
        for path in _git_lines(repo_root, ["ls-tree", "-r", "--name-only", base_ref, "--", "gamesymbols"])
        if SNAPSHOT_PATTERN.fullmatch(path)
    ]
    latest_paths = []
    if len(tracked) > 1 and f"gamesymbols/{pr_gamever}.yaml" not in tracked:
        latest_change = _git_lines(
            repo_root,
            ["log", "-1", "--format=%H", "--name-only", "--first-parent", base_ref, "--", "gamesymbols"],
        )
        latest_paths = latest_change[1:] if latest_change else []
    return select_validation_gamever(pr_gamever, tracked, latest_paths)


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--github-output")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        gamever = resolve_validation_gamever(Path(args.repo_root), args.base_ref)
    except (OSError, PrValidationVersionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if args.github_output:
        with Path(args.github_output).open("a", encoding="utf-8") as handle:
            handle.write(f"gamever={gamever}\n")
    print(gamever)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

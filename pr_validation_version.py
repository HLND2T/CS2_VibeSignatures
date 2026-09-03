#!/usr/bin/env python3
"""Resolve the GAMEVER analyzed by PR validation before warm-cache dispatch."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from trusted_yaml import load_yaml_file


SNAPSHOT_PATTERN = re.compile(r"^gamesymbols/\d{4,10}[a-z]?\.yaml$")
CONFIG_PATTERN = re.compile(r"^configs/(\d{4,10}[a-z]?)\.yaml$")
SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class PrValidationVersionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ValidationSelection:
    pr_gamever: str
    gamever: str
    base_snapshot_path: str | None
    base_snapshot_commit: str | None


def _snapshot_gamever(path: str) -> str:
    if not SNAPSHOT_PATTERN.fullmatch(path):
        raise PrValidationVersionError(f"invalid tracked snapshot path: {path}")
    return PurePosixPath(path).stem


def select_validation_snapshot(
    pr_gamever: str,
    tracked_snapshots: list[str],
    latest_snapshot_paths: list[str],
) -> str | None:
    pr_gamever = str(pr_gamever).strip()
    if not pr_gamever:
        raise PrValidationVersionError("PR GAMEVER is empty")
    tracked_snapshots = sorted(set(tracked_snapshots))
    if not tracked_snapshots:
        return None
    same_version = f"gamesymbols/{pr_gamever}.yaml"
    if same_version in tracked_snapshots:
        return same_version
    if len(tracked_snapshots) == 1:
        return tracked_snapshots[0]
    if not latest_snapshot_paths:
        raise PrValidationVersionError("failed to locate the latest base snapshot publication")
    candidates = [path for path in latest_snapshot_paths if path in tracked_snapshots]
    if len(candidates) != 1:
        raise PrValidationVersionError(f"latest base snapshot publication is ambiguous: {', '.join(candidates)}")
    return candidates[0]


def select_validation_gamever(
    pr_gamever: str,
    tracked_snapshots: list[str],
    latest_snapshot_paths: list[str],
) -> str:
    snapshot = select_validation_snapshot(pr_gamever, tracked_snapshots, latest_snapshot_paths)
    return _snapshot_gamever(snapshot) if snapshot else str(pr_gamever).strip()


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


def changed_head_config_gamevers(repo_root: Path, base_ref: str, head_ref: str = "HEAD") -> list[str]:
    """Return the distinct versioned configs changed by the PR and still present at HEAD."""
    gamevers = set()
    for path in _git_lines(repo_root, ["diff", "--name-only", base_ref, head_ref, "--", "configs"]):
        match = CONFIG_PATTERN.fullmatch(path)
        if match and (repo_root / path).is_file():
            gamevers.add(match.group(1))
    return sorted(gamevers)


def resolve_validation_selection(repo_root: Path, base_ref: str) -> ValidationSelection:
    repo_root = Path(repo_root).resolve()
    base_ref = str(base_ref).strip()
    if not SHA_PATTERN.fullmatch(base_ref):
        raise PrValidationVersionError(f"base ref must be a full commit SHA: {base_ref}")
    document = load_yaml_file(repo_root / "download.yaml")
    downloads = document.get("downloads") if isinstance(document, dict) else None
    if not isinstance(downloads, list) or not downloads or not isinstance(downloads[-1], dict):
        raise PrValidationVersionError("download.yaml has no latest download entry")
    pr_gamever = str(downloads[-1].get("tag", "")).strip()
    changed_config_gamevers = changed_head_config_gamevers(repo_root, base_ref)
    if len(changed_config_gamevers) > 1:
        raise PrValidationVersionError(
            "PR changes multiple versioned configs; unable to select one validation GAMEVER: "
            + ", ".join(changed_config_gamevers)
        )
    validation_target_gamever = changed_config_gamevers[0] if changed_config_gamevers else pr_gamever
    tracked = [
        path
        for path in _git_lines(repo_root, ["ls-tree", "-r", "--name-only", base_ref, "--", "gamesymbols"])
        if SNAPSHOT_PATTERN.fullmatch(path)
    ]
    if changed_config_gamevers and f"gamesymbols/{validation_target_gamever}.yaml" not in tracked:
        raise PrValidationVersionError(
            f"PR changes configs/{validation_target_gamever}.yaml but base has no matching snapshot"
        )
    latest_paths = []
    if len(tracked) > 1 and f"gamesymbols/{validation_target_gamever}.yaml" not in tracked:
        latest_change = _git_lines(
            repo_root,
            ["log", "-1", "--format=%H", "--name-only", "--first-parent", base_ref, "--", *tracked],
        )
        if len(latest_change) < 2 or not SHA_PATTERN.fullmatch(latest_change[0]):
            raise PrValidationVersionError("failed to locate the latest base snapshot publication")
        latest_paths = latest_change[1:]
    snapshot_path = select_validation_snapshot(validation_target_gamever, tracked, latest_paths)
    if snapshot_path is None:
        return ValidationSelection(pr_gamever, validation_target_gamever, None, None)
    commit_lines = _git_lines(
        repo_root,
        ["log", "-1", "--format=%H", base_ref, "--", snapshot_path],
    )
    if len(commit_lines) != 1 or not SHA_PATTERN.fullmatch(commit_lines[0]):
        raise PrValidationVersionError(f"failed to locate the commit that published {snapshot_path}")
    return ValidationSelection(
        pr_gamever=pr_gamever,
        gamever=_snapshot_gamever(snapshot_path),
        base_snapshot_path=snapshot_path,
        base_snapshot_commit=commit_lines[0].lower(),
    )


def resolve_validation_gamever(repo_root: Path, base_ref: str) -> str:
    return resolve_validation_selection(repo_root, base_ref).gamever


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--github-output")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        selection = resolve_validation_selection(Path(args.repo_root), args.base_ref)
    except (OSError, PrValidationVersionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if args.github_output:
        with Path(args.github_output).open("a", encoding="utf-8") as handle:
            handle.write(f"pr_gamever={selection.pr_gamever}\n")
            handle.write(f"gamever={selection.gamever}\n")
            handle.write(f"base_snapshot_path={selection.base_snapshot_path or ''}\n")
            handle.write(f"base_snapshot_commit={selection.base_snapshot_commit or ''}\n")
    print(selection.gamever)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

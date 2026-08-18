#!/usr/bin/env python3
"""Classify a create-pr change set as symbols-lifecycle or plain-PR."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Iterable, Sequence

SYMBOLS_DIR_PREFIXES = (
    "configs/",
    "gamesymbols/",
    "gamedata/",
    "gamedata-generators/",
    "ida_preprocessor_scripts/",
    "cpp_tests/",
    "hl2sdk_cs2/",
    "release-manifests/",
    "gamesymbol_snapshot_lib/",
    "bin/",
)

SYMBOLS_EXACT_PATHS = frozenset({"hl2sdk_cs2"})

SYMBOLS_ROOT_FILES = frozenset(
    {
        "agent_runner.py",
        "binary_hashing.py",
        "cpp_tests_util.py",
        "format_repo_files.py",
        "generate_reference_yaml.py",
        "init_gamebin.py",
        "push_binsync_symbols.py",
        "run_cpp_tests.py",
        "trusted_yaml.py",
        "update_gamedata.py",
    }
)

SYMBOLS_ROOT_PREFIXES = (
    "analysis_",
    "gamedata_",
    "gamesymbol_",
    "ida_",
)


class ClassifyDeliveryError(Exception):
    """Raised when the change set cannot be classified safely."""


def normalize_repo_path(path: str) -> str:
    """Normalize a git path to POSIX form without a leading ./."""
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def is_symbols_related_path(path: str) -> bool:
    """Return True when a tracked path feeds the CS2 symbols pipeline."""
    normalized = normalize_repo_path(path)
    if not normalized:
        return False
    if normalized in SYMBOLS_EXACT_PATHS:
        return True
    if any(normalized.startswith(prefix) for prefix in SYMBOLS_DIR_PREFIXES):
        return True
    if "/" in normalized:
        return False
    if normalized in SYMBOLS_ROOT_FILES:
        return True
    return any(normalized.startswith(prefix) and normalized.endswith(".py") for prefix in SYMBOLS_ROOT_PREFIXES)


def classify_paths(paths: Iterable[str]) -> tuple[int, list[str]]:
    """Return (LIFECYCLE, matched paths) for a captured change set."""
    matched: list[str] = []
    seen: set[str] = set()
    for path in paths:
        normalized = normalize_repo_path(path)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        if is_symbols_related_path(normalized):
            matched.append(normalized)
    return (1 if matched else 0), matched


def parse_name_status(output: str) -> list[str]:
    """Collect old and new paths from `git diff --name-status` output."""
    paths: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            raise ClassifyDeliveryError(f"unrecognized git name-status line: {raw_line}")
        status = parts[0]
        if status.startswith(("R", "C")):
            if len(parts) != 3:
                raise ClassifyDeliveryError(f"rename/copy name-status must have two paths: {raw_line}")
            paths.extend(parts[1:])
            continue
        if len(parts) != 2:
            raise ClassifyDeliveryError(f"unrecognized git name-status line: {raw_line}")
        paths.append(parts[1])
    return paths


def git_name_status(diff_args: Sequence[str]) -> list[str]:
    """Read changed paths from git. `diff_args` follow `git diff --name-status`."""
    command = ["git", "diff", "--name-status", *diff_args]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise ClassifyDeliveryError(f"unable to run git diff: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ClassifyDeliveryError(f"{' '.join(command)} failed: {detail}")
    return parse_name_status(result.stdout)


def format_classification(lifecycle: int, matched: Sequence[str]) -> str:
    """Render the create-pr classification contract."""
    mode = "lifecycle" if lifecycle else "plain-pr"
    lines = [f"LIFECYCLE={lifecycle}", f"mode={mode}", f"matched={len(matched)}"]
    lines.extend(matched)
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--cached", action="store_true", help="Classify git diff --cached --name-status")
    source.add_argument("--committed", action="store_true", help="Classify origin/main...HEAD")
    parser.add_argument("paths", nargs="*", help="Explicit paths to classify")
    args = parser.parse_args(argv)

    try:
        if args.cached:
            if args.paths:
                raise ClassifyDeliveryError("do not pass explicit paths with --cached")
            paths = git_name_status(["--cached"])
        elif args.committed:
            if args.paths:
                raise ClassifyDeliveryError("do not pass explicit paths with --committed")
            paths = git_name_status(["origin/main...HEAD"])
        else:
            paths = list(args.paths)
        lifecycle, matched = classify_paths(paths)
    except ClassifyDeliveryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    sys.stdout.write(format_classification(lifecycle, matched))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

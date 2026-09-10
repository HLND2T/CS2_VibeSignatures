#!/usr/bin/env python3
"""Resolve the Pages deployment code commit and require it to be trusted main history."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class PagesDeploymentShaError(Exception):
    """Raised when the Pages deployment code commit cannot be trusted."""


def _run_git(repository_root: Path, *arguments: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", "-C", str(repository_root), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise PagesDeploymentShaError(f"unable to run git: {exc}") from exc


def normalize_sha(value: str, label: str) -> str:
    normalized = str(value).strip().lower()
    if not SHA_RE.fullmatch(normalized):
        raise PagesDeploymentShaError(f"{label} is not a full lowercase commit SHA")
    return normalized


def resolve_deployment_sha(source_sha: str, requested_sha: str | None) -> tuple[str, bool]:
    """Return the deployment code commit and whether it overrides the Release source commit."""
    source = normalize_sha(source_sha, "Release source SHA")
    requested = "" if requested_sha is None else str(requested_sha).strip()
    if not requested:
        return source, False
    return normalize_sha(requested, "deployment code SHA"), True


def verify_commit_on_main(repository_root: Path, deployment_sha: str, main_ref: str = "HEAD") -> None:
    """Require the deployment commit to exist and be an ancestor of the trusted main ref."""
    root = Path(repository_root)
    discovered = _run_git(root, "rev-parse", "--is-inside-work-tree")
    if discovered.returncode or discovered.stdout.strip() != "true":
        raise PagesDeploymentShaError(f"deployment code checkout is not a git work tree: {root}")
    if _run_git(root, "cat-file", "-e", f"{deployment_sha}^{{commit}}").returncode:
        raise PagesDeploymentShaError(
            f"deployment commit does not exist or is not reachable from main: {deployment_sha}"
        )
    if _run_git(root, "rev-parse", "--verify", f"{main_ref}^{{commit}}").returncode:
        raise PagesDeploymentShaError(f"trusted main ref cannot be resolved: {main_ref}")
    if _run_git(root, "merge-base", "--is-ancestor", deployment_sha, main_ref).returncode:
        raise PagesDeploymentShaError(f"deployment commit is not in trusted main history: {deployment_sha}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--requested-sha", default="")
    parser.add_argument("--repository-root", default="")
    parser.add_argument("--main-ref", default="HEAD")
    parser.add_argument("--github-output", default="")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        deployment_sha, override = resolve_deployment_sha(args.source_sha, args.requested_sha)
        if override:
            if not args.repository_root:
                raise PagesDeploymentShaError("a deployment code checkout is required for a deployment SHA override")
            verify_commit_on_main(Path(args.repository_root), deployment_sha, args.main_ref)
    except (OSError, PagesDeploymentShaError, ValueError) as exc:
        print(f"Pages deployment SHA error: {exc}", file=sys.stderr)
        return 1
    outputs = {"deployment_sha": deployment_sha, "deployment_override": "true" if override else "false"}
    output_path = args.github_output or os.environ.get("GITHUB_OUTPUT", "")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write(f"{key}={value}\n")
    for key, value in outputs.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

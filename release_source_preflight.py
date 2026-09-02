#!/usr/bin/env python3
"""Fail closed before dispatching or building an immutable source-owned Release."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from bin_artifact_contract import ArtifactContractError, build_game_artifact_inventory
from trusted_pr_context import TrustedPrContextError, parse_source_artifact_policy


ALLOWED_REPOSITORIES = frozenset({"HLND2T/CS2_VibeSignatures"})
GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ReleaseSourcePreflightError(RuntimeError):
    """The immutable source is not eligible for a Release build."""


def _source_publish_time(repo_root: Path, source_sha: str) -> str:
    raw = _git(repo_root, "show", "-s", "--format=%cI", source_sha)
    try:
        value = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ReleaseSourcePreflightError("source commit timestamp is invalid") from exc
    if value.tzinfo is None:
        raise ReleaseSourcePreflightError("source commit timestamp has no timezone")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(repo_root: Path, *arguments: str, allowed: tuple[int, ...] = (0,)) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in allowed:
        raise ReleaseSourcePreflightError(
            result.stderr.strip() or f"git {' '.join(arguments)} failed with exit code {result.returncode}"
        )
    return result.stdout.strip()


def _configured_download_versions(path: Path) -> tuple[str, ...]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        downloads = document["downloads"]
    except (OSError, UnicodeError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise ReleaseSourcePreflightError(f"download.yaml is invalid: {exc}") from exc
    versions = tuple(str(item.get("tag", "")) for item in downloads if isinstance(item, dict))
    if not versions or any(not GAMEVER_RE.fullmatch(version) for version in versions):
        raise ReleaseSourcePreflightError("download.yaml contains an invalid GAMEVER registry")
    return versions


def validate_release_source(
    *,
    repo_root: str | Path,
    repository: str,
    game_version: str,
    source_sha: str,
    default_ref: str,
) -> dict:
    repo_root = Path(repo_root).resolve()
    game_version = str(game_version)
    source_sha = str(source_sha).lower()
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseSourcePreflightError(f"repository is not allowlisted: {repository}")
    if not GAMEVER_RE.fullmatch(game_version):
        raise ReleaseSourcePreflightError(f"invalid GAMEVER: {game_version!r}")
    if not SHA_RE.fullmatch(source_sha):
        raise ReleaseSourcePreflightError("source_sha must be a full lowercase commit SHA")
    if _git(repo_root, "rev-parse", "HEAD").lower() != source_sha:
        raise ReleaseSourcePreflightError("release checkout does not match source_sha")
    ancestor = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", source_sha, default_ref],
        capture_output=True,
        check=False,
    )
    if ancestor.returncode != 0:
        if ancestor.returncode == 1:
            raise ReleaseSourcePreflightError("source_sha is not reachable from the immutable default branch")
        raise ReleaseSourcePreflightError(
            ancestor.stderr.decode(errors="replace").strip() or "git ancestry check failed"
        )
    try:
        policy = parse_source_artifact_policy((repo_root / "source_artifact_policy.yaml").read_bytes())
    except (OSError, TrustedPrContextError) as exc:
        raise ReleaseSourcePreflightError(f"source artifact policy is invalid: {exc}") from exc
    if policy.mode != "source-owned":
        raise ReleaseSourcePreflightError("release source still uses the legacy artifact policy")
    if game_version not in _configured_download_versions(repo_root / "download.yaml"):
        raise ReleaseSourcePreflightError(f"GAMEVER {game_version} is absent from download.yaml")
    config_path = repo_root / "configs" / f"{game_version}.yaml"
    if not config_path.is_file():
        raise ReleaseSourcePreflightError(f"new GAMEVER source artifact bootstrap required: missing {config_path.name}")
    try:
        inventory = build_game_artifact_inventory(
            repo_root=repo_root,
            config_path=config_path,
            game_version=game_version,
            artifact_root=repo_root / "bin_artifacts",
            require_tracked=True,
        )
    except (ArtifactContractError, OSError, ValueError) as exc:
        raise ReleaseSourcePreflightError(f"new GAMEVER source artifact bootstrap required: {exc}") from exc
    source_tree_sha = _git(repo_root, "rev-parse", f"{source_sha}^{{tree}}")
    source_publish_time = _source_publish_time(repo_root, source_sha)
    return {
        "schema_version": 1,
        "repository": repository,
        "game_version": game_version,
        "source_sha": source_sha,
        "source_tree_sha": source_tree_sha,
        "source_publish_time": source_publish_time,
        "artifact_file_count": inventory.file_count,
        "artifact_inventory_sha256": inventory.inventory_sha256,
    }


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--gamever", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--default-ref", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        result = validate_release_source(
            repo_root=args.repo_root,
            repository=args.repository,
            game_version=args.gamever,
            source_sha=args.source_sha,
            default_ref=args.default_ref,
        )
    except ReleaseSourcePreflightError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Dispatch an immutable source-owned Release build from origin/main."""

import argparse
import json
import re
import tempfile
import subprocess
import sys
import time
from pathlib import Path

import yaml

ALLOWED_REPOSITORIES = {"HLND2T/CS2_VibeSignatures"}
GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW = "build-on-self-runner.yml"
PUBLICATION_MODES = frozenset({"verify-only", "publish"})
RUN_LIST_LIMIT = "100"
RUN_DISCOVERY_ATTEMPTS = 10
RUN_DISCOVERY_DELAY_SECONDS = 2


class TriggerError(Exception):
    """Raised when a dispatch safety precondition is not satisfied."""


def run_command(command: list[str], cwd: Path, allowed: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode not in allowed:
        detail = (result.stderr or result.stdout).strip() or f"exit code {result.returncode}"
        raise TriggerError(f"{' '.join(command)} failed: {detail}")
    return result


def repository_root() -> Path:
    expected = Path(__file__).resolve().parents[4]
    result = run_command(["git", "rev-parse", "--show-toplevel"], expected)
    actual = Path(result.stdout.strip()).resolve()
    if actual != expected:
        raise TriggerError(f"skill is not running in its owning repository: {actual}")
    return actual


def parse_repository(remote_url: str) -> str:
    patterns = (
        r"^https://github\.com/(?P<repo>[^/]+/[^/]+?)(?:\.git)?$",
        r"^git@github\.com:(?P<repo>[^/]+/[^/]+?)(?:\.git)?$",
        r"^ssh://git@github\.com/(?P<repo>[^/]+/[^/]+?)(?:\.git)?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, remote_url.strip())
        if match:
            return match.group("repo")
    raise TriggerError(f"unsupported origin URL: {remote_url}")


def require_repository(root: Path) -> str:
    remote = run_command(["git", "remote", "get-url", "origin"], root).stdout.strip()
    repository = parse_repository(remote)
    if repository not in ALLOWED_REPOSITORIES:
        raise TriggerError(f"origin repository is not allowlisted: {repository}")
    return repository


def require_github_access(root: Path, repository: str) -> None:
    run_command(["gh", "auth", "status", "--hostname", "github.com"], root)
    permission = run_command(["gh", "api", f"repos/{repository}", "--jq", ".permissions.push"], root).stdout.strip()
    if permission != "true":
        raise TriggerError(f"authenticated GitHub account cannot dispatch Actions for {repository}")
    run_command(["gh", "api", f"repos/{repository}/actions/workflows/{WORKFLOW}", "--jq", ".id"], root)


def resolve_source(root: Path) -> tuple[str, str]:
    run_command(["git", "fetch", "--no-tags", "origin", "refs/heads/main"], root)
    source_sha = run_command(["git", "rev-parse", "FETCH_HEAD"], root).stdout.strip().lower()
    if not SHA_RE.fullmatch(source_sha):
        raise TriggerError("origin/main did not resolve to a full commit SHA")
    subject = run_command(["git", "show", "-s", "--format=%s", source_sha], root).stdout.strip()
    return source_sha, subject


def available_versions(root: Path, source_sha: str) -> list[str]:
    raw = run_command(["git", "show", f"{source_sha}:download.yaml"], root).stdout
    try:
        downloads = yaml.safe_load(raw).get("downloads", [])
    except (AttributeError, yaml.YAMLError) as exc:
        raise TriggerError("download.yaml at origin/main is invalid") from exc
    versions = [str(item.get("tag", "")) for item in downloads if isinstance(item, dict)]
    if not versions or any(not GAMEVER_RE.fullmatch(version) for version in versions):
        raise TriggerError("download.yaml contains no valid release versions")
    return versions


def select_version(requested: str, versions: list[str]) -> str:
    if requested == "latest":
        return versions[-1]
    if not GAMEVER_RE.fullmatch(requested):
        raise TriggerError(f"invalid requested GAMEVER: {requested}")
    if requested not in versions:
        raise TriggerError(f"GAMEVER {requested} is absent from download.yaml at origin/main")
    return requested


def require_publication_mode(publication_mode: str) -> str:
    if publication_mode not in PUBLICATION_MODES:
        raise TriggerError(f"unsupported publication mode: {publication_mode}")
    return publication_mode


def release_run_title(gamever: str, publication_mode: str) -> str:
    return f"Release {require_publication_mode(publication_mode)} {gamever}"


def parse_json_list(raw: str, label: str) -> list[dict]:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise TriggerError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise TriggerError(f"{label} did not return a JSON list")
    return value


def list_runs(root: Path) -> list[dict]:
    result = run_command(
        [
            "gh",
            "run",
            "list",
            "--workflow",
            WORKFLOW,
            "--limit",
            RUN_LIST_LIMIT,
            "--json",
            "databaseId,displayTitle,status,url,headSha,event",
        ],
        root,
    )
    return parse_json_list(result.stdout, "gh run list")


def require_no_duplicate(root: Path, gamever: str, publication_mode: str) -> set[int]:
    runs = list_runs(root)
    title = release_run_title(gamever, publication_mode)
    for run in runs:
        if run.get("status") in {"queued", "in_progress"} and run.get("displayTitle") == title:
            raise TriggerError(f"a {publication_mode} release is already active for {gamever}: {run.get('url')}")
    return {int(run["databaseId"]) for run in runs if "databaseId" in run}


def require_main_unchanged(root: Path, source_sha: str) -> None:
    result = run_command(["git", "ls-remote", "--heads", "origin", "refs/heads/main"], root)
    remote_sha = result.stdout.split()[0].lower() if result.stdout.split() else ""
    if remote_sha != source_sha:
        raise TriggerError("origin/main advanced while validating the rebuild request; run the skill again")


def require_source_artifacts(root: Path, repository: str, gamever: str, source_sha: str) -> None:
    """Run repository artifact preflight in a detached temporary source worktree."""
    with tempfile.TemporaryDirectory(prefix="cs2-release-preflight-") as temporary:
        source_root = Path(temporary) / "source"
        run_command(["git", "worktree", "add", "--detach", str(source_root), source_sha], root)
        try:
            run_command(
                [
                    "uv",
                    "run",
                    "python",
                    "release_source_preflight.py",
                    "--repo-root",
                    str(source_root),
                    "--repository",
                    repository,
                    "--gamever",
                    gamever,
                    "--source-sha",
                    source_sha,
                    "--default-ref",
                    source_sha,
                ],
                source_root,
            )
        finally:
            run_command(["git", "worktree", "remove", "--force", str(source_root)], root)


def dispatch(
    root: Path,
    gamever: str,
    source_sha: str,
    publication_mode: str,
) -> None:
    publication_mode = require_publication_mode(publication_mode)
    run_command(
        [
            "gh",
            "workflow",
            "run",
            WORKFLOW,
            "--ref",
            "main",
            "-f",
            f"gamever={gamever}",
            "-f",
            f"source_sha={source_sha}",
            "-f",
            f"publication_mode={publication_mode}",
        ],
        root,
    )


def discover_run(
    root: Path,
    known_ids: set[int],
    *,
    gamever: str,
    source_sha: str,
    publication_mode: str,
) -> str:
    title = release_run_title(gamever, publication_mode)
    for _attempt in range(RUN_DISCOVERY_ATTEMPTS):
        for run in list_runs(root):
            run_id = int(run.get("databaseId", 0))
            if (
                run_id not in known_ids
                and run.get("displayTitle") == title
                and run.get("event") == "workflow_dispatch"
                and run.get("headSha") == source_sha
            ):
                return str(run.get("url"))
        time.sleep(RUN_DISCOVERY_DELAY_SECONDS)
    raise TriggerError("workflow was dispatched but its Actions run URL could not be discovered")


def execute(requested: str, publication_mode: str) -> dict:
    root = repository_root()
    publication_mode = require_publication_mode(publication_mode)
    repository = require_repository(root)
    require_github_access(root, repository)
    source_sha, subject = resolve_source(root)
    gamever = select_version(requested, available_versions(root, source_sha))
    known_ids = require_no_duplicate(root, gamever, publication_mode)
    require_main_unchanged(root, source_sha)
    require_source_artifacts(root, repository, gamever, source_sha)
    require_main_unchanged(root, source_sha)
    dispatch(root, gamever, source_sha, publication_mode)
    run_url = discover_run(
        root,
        known_ids,
        gamever=gamever,
        source_sha=source_sha,
        publication_mode=publication_mode,
    )
    return {
        "gamever": gamever,
        "publication_mode": publication_mode,
        "source_sha": source_sha,
        "subject": subject,
        "run_url": run_url,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gamever", help="A version in download.yaml, or latest")
    parser.add_argument(
        "--mode",
        choices=sorted(PUBLICATION_MODES),
        required=True,
        help="verify-only performs all verification without publication; publish enables protected publishers",
    )
    args = parser.parse_args(argv)
    try:
        result = execute(args.gamever, args.mode)
    except (TriggerError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Selected GAMEVER: {result['gamever']}")
    print(f"Publication mode: {result['publication_mode']}")
    print(f"SOURCE_SHA: {result['source_sha']}")
    print(f"Commit: {result['subject']}")
    print(f"Actions run: {result['run_url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

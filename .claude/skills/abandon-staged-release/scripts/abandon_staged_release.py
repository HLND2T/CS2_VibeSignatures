#!/usr/bin/env python3
"""Discover and abandon one explicitly identified unpromoted staged release."""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


ALLOWED_REPOSITORIES = {"HLND2T/CS2_VibeSignatures"}
LEGACY_ACTIONS_BOT_LOGIN = "github-actions[bot]"
TRUSTED_PR_AUTHOR_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
OUTPUT_BRANCH_RES = (
    re.compile(r"^gamesymbols/build/(?P<gamever>[0-9]{4,10}[a-z]?)/(?P<build_id>[0-9]+-[0-9]+)$"),
    re.compile(r"^gamesymbols/(?P<gamever>[0-9]{4,10}[a-z]?)/build-(?P<build_id>[0-9]+-[0-9]+)$"),
)
TARGET_RE = re.compile(r"^(?P<gamever>[0-9]{4,10}[a-z]?)/(?P<build_id>[0-9]+-[0-9]+)$")
CONFIRMATION_RE = re.compile(r"^ABANDON (?P<gamever>[0-9]{4,10}[a-z]?)/(?P<build_id>[0-9]+-[0-9]+)$")
RUN_TITLE_RE = re.compile(r"^Release build (?P<gamever>[0-9]{4,10}[a-z]?)$")
BLOCKING_READY_RE = re.compile(
    r"another ready staged build blocks (?P<gamever>[0-9]{4,10}[a-z]?): "
    r"[^\r\n]*[\\/](?P=gamever)[\\/](?P<build_id>[0-9]+-[0-9]+)"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW = "abandon-staged-release.yml"
RUN_TITLE_PREFIX = "Abandon staged release PR"
BUILD_WORKFLOW_PATH = ".github/workflows/build-on-self-runner.yml"
RUN_LIST_LIMIT = "50"
RUN_DISCOVERY_ATTEMPTS = 10
RUN_DISCOVERY_DELAY_SECONDS = 2
REASON_MAX_LENGTH = 500


class AbandonError(Exception):
    """Raised when an explicit staged-release abandonment is unsafe."""


def run_command(command: list[str], cwd: Path) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or f"exit code {result.returncode}"
        raise AbandonError(f"{' '.join(command)} failed: {detail}")
    return result


def repository_root() -> Path:
    expected = Path(__file__).resolve().parents[4]
    result = run_command(["git", "rev-parse", "--show-toplevel"], expected)
    actual = Path(result.stdout.strip()).resolve()
    if actual != expected:
        raise AbandonError(f"skill is not running in its owning repository: {actual}")
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
    raise AbandonError(f"unsupported origin URL: {remote_url}")


def require_repository(root: Path) -> str:
    remote = run_command(["git", "remote", "get-url", "origin"], root).stdout.strip()
    repository = parse_repository(remote)
    if repository not in ALLOWED_REPOSITORIES:
        raise AbandonError(f"origin repository is not allowlisted: {repository}")
    return repository


def require_github_access(root: Path, repository: str) -> None:
    run_command(["gh", "auth", "status", "--hostname", "github.com"], root)
    permission = run_command(["gh", "api", f"repos/{repository}", "--jq", ".permissions.push"], root).stdout.strip()
    if permission != "true":
        raise AbandonError(f"authenticated GitHub account cannot dispatch Actions for {repository}")
    run_command(["gh", "api", f"repos/{repository}/actions/workflows/{WORKFLOW}", "--jq", ".id"], root)


def parse_json_object(raw: str, label: str) -> dict:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AbandonError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise AbandonError(f"{label} did not return a JSON object")
    return value


def parse_json_list(raw: str, label: str) -> list[dict]:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise AbandonError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise AbandonError(f"{label} did not return a JSON list")
    return value


def resolve_main(root: Path) -> str:
    run_command(["git", "fetch", "origin", "main", "--quiet"], root)
    source_sha = run_command(["git", "rev-parse", "refs/remotes/origin/main"], root).stdout.strip().lower()
    if not SHA_RE.fullmatch(source_sha):
        raise AbandonError("origin/main did not resolve to a full commit SHA")
    run_command(["git", "cat-file", "-e", f"{source_sha}:.github/workflows/{WORKFLOW}"], root)
    return source_sha


def validate_reason(reason: str) -> str:
    reason = reason.strip()
    if not reason or len(reason) > REASON_MAX_LENGTH or any(char in reason for char in "\r\n"):
        raise AbandonError("reason must be one non-empty line of at most 500 characters")
    return reason


def parse_confirmation(confirmation: str) -> tuple[str, str]:
    match = CONFIRMATION_RE.fullmatch(confirmation)
    if not match:
        raise AbandonError("confirmation must exactly equal 'ABANDON <gamever>/<build-id>'")
    return match.group("gamever"), match.group("build_id")


def parse_run_url(target: str, repository: str) -> int | None:
    parsed = urlparse(target)
    if not parsed.scheme and not parsed.netloc:
        return None
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise AbandonError("run URL must use https://github.com")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) not in {5, 7} or parts[2:4] != ["actions", "runs"]:
        raise AbandonError("target must be GAMEVER/BUILD_ID or a GitHub Actions run/job URL")
    if len(parts) == 7 and (parts[5] != "job" or not parts[6].isdigit()):
        raise AbandonError("target must be GAMEVER/BUILD_ID or a GitHub Actions run/job URL")
    url_repository = f"{parts[0]}/{parts[1]}"
    if url_repository.lower() != repository.lower():
        raise AbandonError(f"run URL repository does not match {repository}")
    if not parts[4].isdigit() or int(parts[4]) <= 0:
        raise AbandonError("run URL contains an invalid run ID")
    return int(parts[4])


def _load_build_run(root: Path, repository: str, run_id: int) -> dict:
    raw = run_command(["gh", "api", f"repos/{repository}/actions/runs/{run_id}"], root).stdout
    run = parse_json_object(raw, "Actions run lookup")
    if run.get("id") != run_id:
        raise AbandonError("Actions run lookup returned a different run ID")
    run_repository = (run.get("repository") or {}).get("full_name")
    if run_repository != repository or run.get("path") != BUILD_WORKFLOW_PATH:
        raise AbandonError("run URL does not identify a trusted release build workflow")
    if run.get("event") not in {"workflow_dispatch", "repository_dispatch"}:
        raise AbandonError("release build run has an unsupported event type")
    if run.get("status") != "completed":
        raise AbandonError("release build run must be completed before abandonment")
    attempt = run.get("run_attempt")
    if not isinstance(attempt, int) or attempt <= 0:
        raise AbandonError("release build run attempt is invalid")
    title = RUN_TITLE_RE.fullmatch(str(run.get("display_title", "")))
    if not title:
        raise AbandonError("release build run title does not contain a valid game version")
    return {**run, "resolved_gamever": title.group("gamever")}


def _blocking_targets(log: str) -> set[tuple[str, str]]:
    return {(match.group("gamever"), match.group("build_id")) for match in BLOCKING_READY_RE.finditer(log)}


def validate_run_target(root: Path, repository: str, run_id: int, *, gamever: str, build_id: str) -> None:
    run = _load_build_run(root, repository, run_id)
    if run["resolved_gamever"] != gamever:
        raise AbandonError("run URL game version does not match confirmation")
    if f"{run_id}-{run['run_attempt']}" == build_id:
        return
    if run.get("conclusion") != "failure":
        raise AbandonError("run URL does not identify the confirmed staged build")
    log = run_command(["gh", "run", "view", str(run_id), "--repo", repository, "--log-failed"], root).stdout
    targets = _blocking_targets(log)
    expected = (gamever, build_id)
    if targets != {expected}:
        if expected not in targets:
            raise AbandonError("run URL does not report the confirmed READY build as its blocker")
        raise AbandonError("run URL reports multiple READY build identities; refusing ambiguous abandonment")


def resolve_target_identity(root: Path, repository: str, target: str, confirmation: str) -> tuple[str, str]:
    gamever, build_id = parse_confirmation(confirmation)
    direct = TARGET_RE.fullmatch(target)
    if direct:
        if (direct.group("gamever"), direct.group("build_id")) != (gamever, build_id):
            raise AbandonError("target GAMEVER/BUILD_ID does not match confirmation")
        return gamever, build_id
    run_id = parse_run_url(target, repository)
    if run_id is None:
        raise AbandonError("target must be GAMEVER/BUILD_ID or a GitHub Actions run/job URL")
    validate_run_target(root, repository, run_id, gamever=gamever, build_id=build_id)
    return gamever, build_id


def _trusted_pr_identity(pull: dict, repository: str, gamever: str, build_id: str) -> dict | None:
    head = pull.get("head") or {}
    head_repo = head.get("repo") or {}
    base = pull.get("base") or {}
    author = pull.get("user") or {}
    if pull.get("state") != "closed" or not pull.get("merged_at"):
        return None
    association = str(pull.get("author_association") or "").strip().upper()
    if author.get("login") != LEGACY_ACTIONS_BOT_LOGIN and association not in TRUSTED_PR_AUTHOR_ASSOCIATIONS:
        return None
    if head_repo.get("full_name") != repository or base.get("ref") != "main":
        return None
    branch = str(head.get("ref", ""))
    match = None
    for pattern in OUTPUT_BRANCH_RES:
        match = pattern.fullmatch(branch)
        if match:
            break
    if not match or (match.group("gamever"), match.group("build_id")) != (gamever, build_id):
        return None
    head_sha = str(head.get("sha", "")).lower()
    if not SHA_RE.fullmatch(head_sha):
        return None
    pr_number = pull.get("number")
    if not isinstance(pr_number, int) or pr_number <= 0:
        return None
    return {
        "pr_number": pr_number,
        "pr_url": str(pull.get("html_url", "")),
        "gamever": gamever,
        "build_id": build_id,
        "head_sha": head_sha,
        "output_branch": branch,
    }


def discover_pr_identity(root: Path, repository: str, gamever: str, build_id: str) -> dict:
    owner = repository.split("/", 1)[0]
    branches = (
        f"gamesymbols/build/{gamever}/{build_id}",
        f"gamesymbols/{gamever}/build-{build_id}",
    )
    pulls = []
    for branch in branches:
        result = run_command(
            [
                "gh",
                "api",
                "-X",
                "GET",
                f"repos/{repository}/pulls",
                "-f",
                "state=closed",
                "-f",
                f"head={owner}:{branch}",
                "-f",
                "base=main",
                "-f",
                "per_page=100",
            ],
            root,
        )
        pulls.extend(parse_json_list(result.stdout, f"generated-output PR discovery for {branch}"))
    trusted = [
        identity
        for pull in pulls
        if (identity := _trusted_pr_identity(pull, repository, gamever, build_id)) is not None
    ]
    if not trusted:
        raise AbandonError(f"no trusted merged generated-output PR matches {gamever}/{build_id}")
    if len(trusted) != 1:
        numbers = ", ".join(f"#{identity['pr_number']}" for identity in trusted)
        raise AbandonError(f"multiple trusted merged generated-output PRs match {gamever}/{build_id}: {numbers}")
    return trusted[0]


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


def require_no_duplicate(root: Path, pr_number: int) -> set[int]:
    runs = list_runs(root)
    title = f"{RUN_TITLE_PREFIX} #{pr_number}"
    for run in runs:
        if run.get("status") not in {"queued", "in_progress"}:
            continue
        display_title = run.get("displayTitle")
        if display_title == title:
            raise AbandonError(f"an abandonment workflow is already active for PR #{pr_number}: {run.get('url')}")
        if display_title == RUN_TITLE_PREFIX:
            raise AbandonError(
                "an abandonment workflow with a legacy-truncated title is already active: "
                f"{run.get('url')}; inspect it before dispatching PR #{pr_number}"
            )
    return {int(run["databaseId"]) for run in runs if "databaseId" in run}


def require_main_unchanged(root: Path, source_sha: str) -> None:
    if resolve_main(root) != source_sha:
        raise AbandonError("origin/main advanced during validation; rerun the skill")


def dispatch(root: Path, identity: dict) -> None:
    run_command(
        [
            "gh",
            "workflow",
            "run",
            WORKFLOW,
            "--ref",
            "main",
            "-f",
            f"pr_number={identity['pr_number']}",
            "-f",
            f"confirmation={identity['confirmation']}",
            "-f",
            f"reason={identity['reason']}",
        ],
        root,
    )


def discover_run(root: Path, known_ids: set[int], *, pr_number: int, source_sha: str) -> str:
    expected_title = f"{RUN_TITLE_PREFIX} #{pr_number}"
    unexpected: dict[int, tuple[str, str]] = {}
    for _attempt in range(RUN_DISCOVERY_ATTEMPTS):
        for run in list_runs(root):
            run_id = int(run.get("databaseId", 0))
            if run_id not in known_ids and run.get("event") == "workflow_dispatch" and run.get("headSha") == source_sha:
                display_title = str(run.get("displayTitle", ""))
                run_url = str(run.get("url", ""))
                if display_title == expected_title:
                    return run_url
                if display_title == RUN_TITLE_PREFIX:
                    unexpected[run_id] = (display_title, run_url)
        if unexpected:
            details = ", ".join(f"{url} (displayTitle={title!r})" for title, url in unexpected.values())
            raise AbandonError(
                f"workflow was dispatched, but matching Actions run(s) used an unexpected title: {details}; "
                f"expected {expected_title!r}"
            )
        time.sleep(RUN_DISCOVERY_DELAY_SECONDS)
    raise AbandonError("workflow was dispatched but its Actions run URL could not be discovered")


def execute(target: str, confirmation: str, reason: str) -> dict:
    root = repository_root()
    repository = require_repository(root)
    require_github_access(root, repository)
    source_sha = resolve_main(root)
    reason = validate_reason(reason)
    gamever, build_id = resolve_target_identity(root, repository, target, confirmation)
    identity = discover_pr_identity(root, repository, gamever, build_id)
    identity.update({"target": target, "confirmation": confirmation, "reason": reason})
    known_ids = require_no_duplicate(root, identity["pr_number"])
    require_main_unchanged(root, source_sha)
    dispatch(root, identity)
    identity["run_url"] = discover_run(root, known_ids, pr_number=identity["pr_number"], source_sha=source_sha)
    identity["source_sha"] = source_sha
    return identity


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="GAMEVER/BUILD_ID or trusted GitHub Actions run/job URL")
    parser.add_argument("--confirm", required=True, help="Exact ABANDON <gamever>/<build-id> confirmation")
    parser.add_argument("--reason", required=True, help="One-line audit reason")
    args = parser.parse_args(argv)
    try:
        result = execute(args.target, args.confirm, args.reason)
    except (AbandonError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Target: {result['target']}")
    print(f"PR: #{result['pr_number']} ({result['pr_url']})")
    print(f"GAMEVER: {result['gamever']}")
    print(f"BUILD_ID: {result['build_id']}")
    print(f"PR_HEAD_SHA: {result['head_sha']}")
    print(f"Reason: {result['reason']}")
    print(f"Actions run: {result['run_url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

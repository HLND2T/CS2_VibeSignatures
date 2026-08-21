#!/usr/bin/env python3
"""Verify CI-published snapshot commits before reusing full PR validation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$", re.ASCII)
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
VALIDATION_MODE = "published-recheck"
REGULAR_GIT_MODES = {"100644", "100755"}


class PublishedRecheckError(RuntimeError):
    pass


@dataclass(frozen=True)
class PublicationProvenance:
    expected_head_sha: str
    validated_head_sha: str
    validated_base_sha: str
    gamever: str
    snapshot_sha256: str
    gamedata_manifest_sha256: str


@dataclass(frozen=True)
class DispatchInputs:
    validation_mode: str
    pr_number: int
    provenance: PublicationProvenance


@dataclass(frozen=True)
class DispatchContext:
    repository: str
    github_sha: str
    ref_name: str
    actor: str
    sender: str


@dataclass(frozen=True)
class DispatchVerification:
    validation_path: str
    pr_number: int
    head_sha: str
    head_ref: str
    base_sha: str
    title: str
    user_login: str
    snapshot_sha256: str
    gamedata_manifest_sha256: str


def _lower_sha(value: object, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if not SHA_RE.fullmatch(normalized):
        raise PublishedRecheckError(f"{label} must be a full lowercase Git SHA")
    return normalized


def _lower_sha256(value: object, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if not SHA256_RE.fullmatch(normalized):
        raise PublishedRecheckError(f"{label} must be a lowercase SHA-256 digest")
    return normalized


def validate_dispatch_inputs(values: Mapping[str, object]) -> DispatchInputs:
    validation_mode = str(values.get("validation_mode") or "").strip()
    if validation_mode != VALIDATION_MODE:
        raise PublishedRecheckError(f"validation_mode must equal {VALIDATION_MODE!r}")
    pr_number_text = str(values.get("pr_number") or "").strip()
    if not re.fullmatch(r"[1-9][0-9]*", pr_number_text):
        raise PublishedRecheckError("pr_number must be a positive decimal integer")
    gamever = str(values.get("gamever") or "").strip()
    if not GAMEVER_RE.fullmatch(gamever):
        raise PublishedRecheckError("gamever has an invalid format")
    provenance = PublicationProvenance(
        expected_head_sha=_lower_sha(values.get("expected_head_sha"), "expected_head_sha"),
        validated_head_sha=_lower_sha(values.get("validated_head_sha"), "validated_head_sha"),
        validated_base_sha=_lower_sha(values.get("validated_base_sha"), "validated_base_sha"),
        gamever=gamever,
        snapshot_sha256=_lower_sha256(values.get("snapshot_sha256"), "snapshot_sha256"),
        gamedata_manifest_sha256=_lower_sha256(values.get("gamedata_manifest_sha256"), "gamedata_manifest_sha256"),
    )
    if provenance.expected_head_sha == provenance.validated_head_sha:
        raise PublishedRecheckError("expected_head_sha must be the child of validated_head_sha")
    return DispatchInputs(validation_mode=validation_mode, pr_number=int(pr_number_text), provenance=provenance)


def canonical_commit_message(provenance: PublicationProvenance) -> str:
    return "\n".join(
        (
            f"chore(gamesymbols): publish {provenance.gamever} snapshot",
            "",
            f"Validated-Head-SHA: {provenance.validated_head_sha}",
            f"Validated-Base-SHA: {provenance.validated_base_sha}",
            f"Snapshot-SHA256: {provenance.snapshot_sha256}",
            f"Gamedata-Manifest-SHA256: {provenance.gamedata_manifest_sha256}",
            "Co-Authored-By: Codex <codex@openai.com>",
            "",
        )
    )


def _git(repo_root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise PublishedRecheckError(detail or f"git {' '.join(arguments)} failed")
    return result.stdout


def _canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise PublishedRecheckError(f"unable to hash {path}: {exc}") from exc
    return digest.hexdigest()


def _canonical_repo_path(value: str) -> str:
    if not value or "\\" in value:
        raise PublishedRecheckError(f"invalid repository path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PublishedRecheckError(f"unsafe repository path: {value!r}")
    return path.as_posix()


def _allowed_publication_path(path: str, gamever: str) -> bool:
    path = _canonical_repo_path(path)
    return path == f"gamesymbols/{gamever}.yaml" or path.startswith(f"gamedata/{gamever}/")


def _git_gamedata_inventory(repo_root: Path, revision: str, gamever: str) -> list[dict[str, object]]:
    root = f"gamedata/{gamever}"
    prefix = root + "/"
    raw = _git(repo_root, "ls-tree", "-r", "-z", "--full-tree", revision, "--", root)
    inventory: list[dict[str, object]] = []
    seen: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            path = _canonical_repo_path(raw_path.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise PublishedRecheckError("published gamedata has a malformed Git tree entry") from exc
        if mode not in REGULAR_GIT_MODES or object_type != "blob":
            raise PublishedRecheckError(f"published gamedata has an unsupported Git tree entry: {path}")
        if not path.startswith(prefix) or path in seen:
            raise PublishedRecheckError(f"published gamedata has an invalid or duplicate path: {path}")
        blob = _git(repo_root, "cat-file", "blob", object_id)
        inventory.append({"path": path, "size": len(blob), "sha256": _sha256_bytes(blob)})
        seen.add(path)
    if not inventory:
        raise PublishedRecheckError(f"published gamedata is missing or empty: {root}")
    return sorted(inventory, key=lambda item: str(item["path"]))


def _gamedata_manifest_sha256(inventory: list[dict[str, object]]) -> str:
    return _sha256_bytes(_canonical_json_bytes({"files": inventory}))


def _commit_message(repo_root: Path, revision: str) -> str:
    raw_commit = _git(repo_root, "cat-file", "commit", revision)
    separator = raw_commit.find(b"\n\n")
    if separator < 0:
        raise PublishedRecheckError("published commit has no message separator")
    return raw_commit[separator + 2 :].decode("utf-8", errors="strict")


def verify_published_commit(repo_root: Path, provenance: PublicationProvenance) -> None:
    repo_root = repo_root.resolve()
    raw_metadata = _git(
        repo_root,
        "show",
        "-s",
        "--format=%H%x00%P%x00%an%x00%ae%x00%cn%x00%ce",
        provenance.expected_head_sha,
    )
    fields = raw_metadata.decode("utf-8", errors="strict").strip().split("\0")
    if len(fields) != 6:
        raise PublishedRecheckError("published commit metadata is malformed")
    commit_sha, parents_text, author_name, author_email, committer_name, committer_email = fields
    if _lower_sha(commit_sha.strip(), "published commit") != provenance.expected_head_sha:
        raise PublishedRecheckError("published commit did not resolve to expected_head_sha")
    parents = parents_text.split()
    if parents != [provenance.validated_head_sha]:
        raise PublishedRecheckError("published commit must have exactly validated_head_sha as its parent")
    if (author_name, author_email, committer_name, committer_email) != (
        BOT_NAME,
        BOT_EMAIL,
        BOT_NAME,
        BOT_EMAIL,
    ):
        raise PublishedRecheckError("published commit author and committer must be github-actions[bot]")
    message = _commit_message(repo_root, provenance.expected_head_sha)
    if message != canonical_commit_message(provenance):
        raise PublishedRecheckError("published commit subject or provenance trailers do not match dispatch inputs")

    changed_raw = _git(
        repo_root,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        "-z",
        provenance.expected_head_sha,
    )
    changed_paths = [
        _canonical_repo_path(item.decode("utf-8", errors="strict")) for item in changed_raw.split(b"\0") if item
    ]
    snapshot_path = f"gamesymbols/{provenance.gamever}.yaml"
    if not changed_paths or snapshot_path not in changed_paths:
        raise PublishedRecheckError("published commit must change the validated snapshot")
    rejected = [path for path in changed_paths if not _allowed_publication_path(path, provenance.gamever)]
    if rejected:
        raise PublishedRecheckError("published commit changes disallowed paths: " + ", ".join(sorted(rejected)))

    snapshot = _git(repo_root, "show", f"{provenance.expected_head_sha}:{snapshot_path}")
    if _sha256_bytes(snapshot) != provenance.snapshot_sha256:
        raise PublishedRecheckError("published snapshot SHA-256 does not match dispatch provenance")
    manifest = _gamedata_manifest_sha256(
        _git_gamedata_inventory(repo_root, provenance.expected_head_sha, provenance.gamever)
    )
    if manifest != provenance.gamedata_manifest_sha256:
        raise PublishedRecheckError("published gamedata manifest SHA-256 does not match dispatch provenance")


def verify_existing_publication(repo_root: Path, expected: PublicationProvenance) -> PublicationProvenance:
    lines = _commit_message(repo_root.resolve(), expected.expected_head_sha).splitlines()
    if len(lines) != 7:
        raise PublishedRecheckError("existing publication commit message is not canonical")
    fixed = (
        f"chore(gamesymbols): publish {expected.gamever} snapshot",
        "",
        f"Validated-Head-SHA: {expected.validated_head_sha}",
        f"Validated-Base-SHA: {expected.validated_base_sha}",
    )
    if tuple(lines[:4]) != fixed or lines[6] != "Co-Authored-By: Codex <codex@openai.com>":
        raise PublishedRecheckError("existing publication commit provenance does not match the validated head/base")
    snapshot_prefix = "Snapshot-SHA256: "
    gamedata_prefix = "Gamedata-Manifest-SHA256: "
    if not lines[4].startswith(snapshot_prefix) or not lines[5].startswith(gamedata_prefix):
        raise PublishedRecheckError("existing publication commit digest trailers are missing")
    provenance = PublicationProvenance(
        expected_head_sha=expected.expected_head_sha,
        validated_head_sha=expected.validated_head_sha,
        validated_base_sha=expected.validated_base_sha,
        gamever=expected.gamever,
        snapshot_sha256=_lower_sha256(lines[4][len(snapshot_prefix) :], "Snapshot-SHA256 trailer"),
        gamedata_manifest_sha256=_lower_sha256(lines[5][len(gamedata_prefix) :], "Gamedata-Manifest-SHA256 trailer"),
    )
    verify_published_commit(repo_root, provenance)
    return provenance


def _required_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PublishedRecheckError(f"GitHub API response is missing {label}")
    return value


def verify_dispatch(
    *,
    inputs: DispatchInputs,
    context: DispatchContext,
    pull_request: Mapping[str, Any],
    repo_root: Path,
) -> DispatchVerification:
    if context.actor != BOT_NAME or context.sender != BOT_NAME:
        raise PublishedRecheckError("published recheck dispatch must be created by github-actions[bot]")
    if context.repository not in {"HLND2T/CS2_VibeSignatures", "hzqst/CS2_VibeSignatures"}:
        raise PublishedRecheckError("published recheck is not enabled for this repository")
    if context.github_sha != inputs.provenance.expected_head_sha:
        raise PublishedRecheckError("workflow dispatch github.sha does not match expected_head_sha")
    checkout_sha = _lower_sha(
        _git(repo_root.resolve(), "rev-parse", "HEAD").decode("ascii", errors="strict").strip(),
        "published checkout SHA",
    )
    if checkout_sha != inputs.provenance.expected_head_sha:
        raise PublishedRecheckError("published checkout does not match expected_head_sha")
    if pull_request.get("number") != inputs.pr_number or pull_request.get("state") != "open":
        raise PublishedRecheckError("published recheck requires the requested pull request to remain open")
    head = _required_mapping(pull_request.get("head"), "head")
    head_repo = _required_mapping(head.get("repo"), "head.repo")
    base = _required_mapping(pull_request.get("base"), "base")
    user = _required_mapping(pull_request.get("user"), "user")
    head_sha = _lower_sha(head.get("sha"), "pull request head SHA")
    base_sha = _lower_sha(base.get("sha"), "pull request base SHA")
    head_ref = str(head.get("ref") or "")
    if head_repo.get("full_name") != context.repository:
        raise PublishedRecheckError("published recheck rejects fork pull requests")
    if head_ref != context.ref_name:
        raise PublishedRecheckError("workflow dispatch ref does not match the pull request head ref")
    if head_sha != inputs.provenance.expected_head_sha:
        raise PublishedRecheckError("pull request head advanced before published recheck")

    verify_published_commit(repo_root, inputs.provenance)
    validation_path = "published-recheck" if base_sha == inputs.provenance.validated_base_sha else "full"
    return DispatchVerification(
        validation_path=validation_path,
        pr_number=inputs.pr_number,
        head_sha=head_sha,
        head_ref=head_ref,
        base_sha=base_sha,
        title=str(pull_request.get("title") or ""),
        user_login=str(user.get("login") or ""),
        snapshot_sha256=inputs.provenance.snapshot_sha256,
        gamedata_manifest_sha256=inputs.provenance.gamedata_manifest_sha256,
    )


def verify_dispatch_stable(
    *,
    inputs: DispatchInputs,
    context: DispatchContext,
    initial_pull_request: Mapping[str, Any],
    confirmed_pull_request: Mapping[str, Any],
    repo_root: Path,
) -> DispatchVerification:
    verify_dispatch(
        inputs=inputs,
        context=context,
        pull_request=initial_pull_request,
        repo_root=repo_root,
    )
    return verify_dispatch(
        inputs=inputs,
        context=context,
        pull_request=confirmed_pull_request,
        repo_root=repo_root,
    )


def _is_link_or_reparse(path: Path) -> bool:
    info = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(getattr(info, "st_file_attributes", 0) & reparse_flag)


def _worktree_gamedata_inventory(repo_root: Path, gamever: str) -> list[dict[str, object]]:
    root = repo_root / "gamedata" / gamever
    if not root.is_dir() or _is_link_or_reparse(root):
        raise PublishedRecheckError(f"published gamedata is missing or unsafe: {root}")
    inventory: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        if _is_link_or_reparse(path):
            raise PublishedRecheckError(f"published gamedata must not contain links: {path}")
        if not path.is_file():
            continue
        relative = _canonical_repo_path(path.relative_to(repo_root).as_posix())
        inventory.append({"path": relative, "size": path.stat().st_size, "sha256": _sha256_file(path)})
    if not inventory:
        raise PublishedRecheckError(f"published gamedata is empty: {root}")
    return inventory


def _worktree_changed_paths(repo_root: Path) -> list[str]:
    tracked = _git(repo_root, "diff", "--name-only", "-z", "HEAD", "--")
    untracked = _git(repo_root, "ls-files", "--others", "--exclude-standard", "-z")
    return sorted(
        {
            _canonical_repo_path(item.decode("utf-8", errors="strict"))
            for item in (*tracked.split(b"\0"), *untracked.split(b"\0"))
            if item
        }
    )


def verify_worktree_publication(
    *, repo_root: Path, gamever: str, candidate: Path, gamedata_session: Path
) -> dict[str, str]:
    repo_root = repo_root.resolve()
    if not GAMEVER_RE.fullmatch(gamever):
        raise PublishedRecheckError("gamever has an invalid format")
    candidate = candidate.resolve()
    snapshot_target = repo_root / "gamesymbols" / f"{gamever}.yaml"
    candidate_sha256 = _sha256_file(candidate)
    if _sha256_file(snapshot_target) != candidate_sha256:
        raise PublishedRecheckError("published snapshot bytes differ from the validated candidate")
    try:
        session = json.loads(gamedata_session.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PublishedRecheckError(f"unable to read gamedata candidate session: {exc}") from exc
    if not isinstance(session, dict):
        raise PublishedRecheckError("gamedata candidate session must be an object")
    session_candidate = _lower_sha256(session.get("candidate_sha256"), "session candidate_sha256")
    session_manifest = _lower_sha256(session.get("gamedata_manifest_sha256"), "session gamedata_manifest_sha256")
    if session.get("gamever") != gamever or session_candidate != candidate_sha256:
        raise PublishedRecheckError("gamedata session does not match the validated snapshot candidate")
    actual_manifest = _gamedata_manifest_sha256(_worktree_gamedata_inventory(repo_root, gamever))
    if actual_manifest != session_manifest:
        raise PublishedRecheckError("published gamedata differs from the guarded gamedata candidate")
    changed_paths = _worktree_changed_paths(repo_root)
    rejected = [path for path in changed_paths if not _allowed_publication_path(path, gamever)]
    if rejected:
        raise PublishedRecheckError("publication changed disallowed paths: " + ", ".join(rejected))
    return {
        "snapshot_sha256": candidate_sha256,
        "gamedata_manifest_sha256": actual_manifest,
        "no_op": "true" if not changed_paths else "false",
        "changed_count": str(len(changed_paths)),
    }


def _github_api_pull_request(repository: str, pr_number: int, token: str) -> Mapping[str, Any]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/pulls/{pr_number}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "CS2-VibeSignatures-published-recheck",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise PublishedRecheckError(f"unable to query pull request metadata: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise PublishedRecheckError("GitHub pull request API returned a non-object response")
    return payload


def _dispatch_values_from_environment() -> dict[str, str]:
    return {
        key: os.environ.get(key.upper(), "")
        for key in (
            "validation_mode",
            "pr_number",
            "expected_head_sha",
            "validated_head_sha",
            "validated_base_sha",
            "gamever",
            "snapshot_sha256",
            "gamedata_manifest_sha256",
        )
    }


def _event_sender(event_path: Path) -> str:
    try:
        payload = json.loads(event_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PublishedRecheckError(f"unable to read GitHub event payload: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise PublishedRecheckError("GitHub event payload must be an object")
    sender = payload.get("sender")
    return str(sender.get("login") or "") if isinstance(sender, Mapping) else ""


def _write_github_output(path: str | None, values: Mapping[str, object]) -> None:
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            text = str(value)
            if "\n" in text or "\r" in text:
                raise PublishedRecheckError(f"GitHub output {key} must be a single line")
            handle.write(f"{key}={text}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-inputs")
    validate.add_argument("--github-output")
    verify = commands.add_parser("verify-dispatch")
    verify.add_argument("--repo-root", default=".")
    verify.add_argument("--github-output")
    commit = commands.add_parser("verify-commit")
    commit.add_argument("--repo-root", default=".")
    commit.add_argument("--github-output")
    existing = commands.add_parser("verify-existing-commit")
    existing.add_argument("--repo-root", default=".")
    existing.add_argument("--github-output")
    existing.add_argument("--github-env")
    publication = commands.add_parser("verify-publication")
    publication.add_argument("--repo-root", default=".")
    publication.add_argument("--gamever", required=True)
    publication.add_argument("--candidate", required=True)
    publication.add_argument("--gamedata-session", required=True)
    publication.add_argument("--github-output")
    return parser


def _run(args: argparse.Namespace) -> None:
    if args.command == "verify-publication":
        result = verify_worktree_publication(
            repo_root=Path(args.repo_root),
            gamever=args.gamever,
            candidate=Path(args.candidate),
            gamedata_session=Path(args.gamedata_session),
        )
        _write_github_output(args.github_output, result)
        return

    inputs = validate_dispatch_inputs(_dispatch_values_from_environment())
    if args.command == "validate-inputs":
        if os.environ.get("GITHUB_ACTOR") != BOT_NAME:
            raise PublishedRecheckError("published recheck dispatch actor must be github-actions[bot]")
        sender = _event_sender(Path(os.environ["GITHUB_EVENT_PATH"]))
        if sender != BOT_NAME:
            raise PublishedRecheckError("published recheck dispatch sender must be github-actions[bot]")
        _write_github_output(args.github_output, {"pr_number": inputs.pr_number})
        return
    if args.command == "verify-commit":
        verify_published_commit(Path(args.repo_root), inputs.provenance)
        _write_github_output(args.github_output, {"verified_head_sha": inputs.provenance.expected_head_sha})
        return
    if args.command == "verify-existing-commit":
        provenance = verify_existing_publication(Path(args.repo_root), inputs.provenance)
        _write_github_output(
            args.github_output,
            {
                "verified_head_sha": provenance.expected_head_sha,
                "snapshot_sha256": provenance.snapshot_sha256,
                "gamedata_manifest_sha256": provenance.gamedata_manifest_sha256,
            },
        )
        _write_github_output(
            args.github_env,
            {
                "SNAPSHOT_SHA256": provenance.snapshot_sha256,
                "GAMEDATA_MANIFEST_SHA256": provenance.gamedata_manifest_sha256,
            },
        )
        return

    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise PublishedRecheckError("GITHUB_TOKEN is required for pull request verification")
    context = DispatchContext(
        repository=repository,
        github_sha=_lower_sha(os.environ.get("GITHUB_SHA"), "GITHUB_SHA"),
        ref_name=os.environ.get("GITHUB_REF_NAME", ""),
        actor=os.environ.get("GITHUB_ACTOR", ""),
        sender=_event_sender(Path(os.environ["GITHUB_EVENT_PATH"])),
    )
    initial_pull_request = _github_api_pull_request(repository, inputs.pr_number, token)
    confirmed_pull_request = _github_api_pull_request(repository, inputs.pr_number, token)
    result = verify_dispatch_stable(
        inputs=inputs,
        context=context,
        initial_pull_request=initial_pull_request,
        confirmed_pull_request=confirmed_pull_request,
        repo_root=Path(args.repo_root),
    )
    is_bump = (
        result.user_login == BOT_NAME
        and result.head_ref.startswith("bump-download/")
        and result.title.startswith("chore(download): Update manifest for ")
    )
    _write_github_output(
        args.github_output,
        {
            "validation_path": result.validation_path,
            "pr_number": result.pr_number,
            "head_sha": result.head_sha,
            "head_ref": result.head_ref,
            "base_sha": result.base_sha,
            "title": result.title,
            "user_login": result.user_login,
            "requires_warmup": "false" if is_bump else "true",
            "snapshot_sha256": result.snapshot_sha256,
            "gamedata_manifest_sha256": result.gamedata_manifest_sha256,
        },
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        _run(args)
    except (KeyError, OSError, PublishedRecheckError, UnicodeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

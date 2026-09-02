#!/usr/bin/env python3
"""Publish a verified BinSync candidate using fast-forward-only remote updates."""

from __future__ import annotations

import argparse
import base64
import os
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from binsync_candidate import (
    BinSyncCandidateError,
    _digest,
    _remote_heads,
    verify_candidate,
)
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import canonical_json_bytes, load_json_object, write_canonical_json

TOKEN_ENVIRONMENT_VARIABLE = "BINSYNC_PUBLISH_TOKEN"


class BinSyncPublishError(Exception):
    """Raised when protected BinSync publication cannot proceed safely."""


def _run_git(cwd: Path, arguments: list[str], *, environment: dict | None = None) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(cwd), *arguments],
            capture_output=True,
            text=True,
            check=False,
            env=environment,
        )
    except OSError as exc:
        raise BinSyncPublishError(f"unable to run protected Git publication: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise BinSyncPublishError(detail or f"protected Git publication failed with exit {result.returncode}")
    return result.stdout.strip()


def _authenticated_git_environment(token: str) -> dict[str, str]:
    if not isinstance(token, str) or not token or token != token.strip() or "\r" in token or "\n" in token:
        raise BinSyncPublishError(f"{TOKEN_ENVIRONMENT_VARIABLE} is missing or invalid")
    credential = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {credential}",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _push_refs(repository: dict, bundle: Path, refs: list[dict], environment: dict) -> None:
    if not refs:
        return
    with tempfile.TemporaryDirectory(prefix="publish-binsync-") as temporary:
        local_repo = Path(temporary) / "repository.git"
        local_repo.mkdir()
        _run_git(local_repo, ["init", "--bare"])
        for item in refs:
            _run_git(
                local_repo,
                ["fetch", "--no-tags", str(bundle.resolve()), f"{item['ref']}:{item['ref']}"],
            )
        refspecs = [f"{item['candidate_commit']}:{item['ref']}" for item in refs]
        leases = [f"--force-with-lease={item['ref']}:{item['expected_remote_head'] or ''}" for item in refs]
        _run_git(
            local_repo,
            [
                "push",
                "--atomic",
                "--porcelain",
                "--no-verify",
                *leases,
                repository["remote_url"],
                *refspecs,
            ],
            environment=environment,
        )


def _publication_plan(manifest: dict) -> list[dict]:
    plan = []
    for repository in manifest["repositories"]:
        current_heads = _remote_heads(repository["remote_url"])
        pending = []
        already = []
        for item in repository["refs"]:
            current = current_heads.get(item["ref"])
            if current == item["candidate_commit"]:
                already.append(item)
                continue
            if current != item["expected_remote_head"]:
                raise BinSyncPublishError(
                    f"remote divergence for {repository['repository_id']} {item['ref']}: "
                    f"expected {item['expected_remote_head']}, candidate {item['candidate_commit']}, got {current}"
                )
            pending.append(item)
        plan.append({"repository": repository, "pending": pending, "already": already})
    return plan


def _verify_published_repository(repository: dict) -> None:
    current_heads = _remote_heads(repository["remote_url"])
    mismatches = [
        item["ref"] for item in repository["refs"] if current_heads.get(item["ref"]) != item["candidate_commit"]
    ]
    if mismatches:
        raise BinSyncPublishError(
            f"published BinSync refs do not match candidate for {repository['repository_id']}: {', '.join(mismatches)}"
        )


def publish_candidate(
    *,
    candidate_root: str | Path,
    repo_root: str | Path,
    token: str,
    receipt_path: str | Path,
    expected_source_sha: str | None = None,
    expected_game_version: str | None = None,
    expected_release_version: str | None = None,
    expected_build_id: str | None = None,
    expected_ida_runtime_identity: str | None = None,
    expected_actions_artifact_name: str | None = None,
) -> dict:
    """Preflight every target, publish pending refs, and write an idempotent receipt."""
    candidate_root = Path(candidate_root).resolve()
    try:
        verified = verify_candidate(
            candidate_root=candidate_root,
            repo_root=repo_root,
            expected_source_sha=expected_source_sha,
            expected_game_version=expected_game_version,
            expected_release_version=expected_release_version,
            expected_build_id=expected_build_id,
            expected_ida_runtime_identity=expected_ida_runtime_identity,
            expected_actions_artifact_name=expected_actions_artifact_name,
            check_remotes=False,
        )
        manifest = load_json_object(candidate_root / "manifest.json")
    except (BinSyncCandidateError, ReleaseWorkflowError) as exc:
        raise BinSyncPublishError(str(exc)) from exc
    environment = _authenticated_git_environment(token)

    # Complete a read-only preflight across every repository before the first write.
    plan = _publication_plan(manifest)
    repository_receipts = []
    for item in plan:
        repository = item["repository"]
        pending = item["pending"]
        bundle = candidate_root / PurePosixPath(repository["bundle"]["path"])
        if pending:
            _push_refs(repository, bundle, pending, environment)
        _verify_published_repository(repository)
        repository_receipts.append(
            {
                "repository_id": repository["repository_id"],
                "owner": repository["owner"],
                "name": repository["name"],
                "status": "published" if pending else "already-published",
                "refs": [{"ref": ref["ref"], "commit": ref["candidate_commit"]} for ref in repository["refs"]],
            }
        )

    receipt = {
        "schema_version": 1,
        "source_sha": verified["source_sha"],
        "game_version": verified["game_version"],
        "build_id": verified["build_id"],
        "candidate_publication_digest": verified["publication_digest"],
        "repositories": repository_receipts,
    }
    receipt["remote_publication_digest"] = _digest("binsync-remote-publication-receipt:v1", receipt)
    write_canonical_json(Path(receipt_path), receipt)
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--candidate-root", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--source-sha")
    parser.add_argument("--gamever")
    parser.add_argument("--release-version")
    parser.add_argument("--build-id")
    parser.add_argument("--ida-runtime-identity")
    parser.add_argument("--actions-artifact-name")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = publish_candidate(
            candidate_root=args.candidate_root,
            repo_root=args.repo_root,
            token=os.environ.get(TOKEN_ENVIRONMENT_VARIABLE, ""),
            receipt_path=args.receipt,
            expected_source_sha=args.source_sha,
            expected_game_version=args.gamever,
            expected_release_version=args.release_version,
            expected_build_id=args.build_id,
            expected_ida_runtime_identity=args.ida_runtime_identity,
            expected_actions_artifact_name=args.actions_artifact_name,
        )
    except BinSyncPublishError as exc:
        print(f"BinSync publish error: {exc}", file=sys.stderr)
        return 1
    print(canonical_json_bytes(receipt).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build and verify the trusted identity bridge for prospective PR merge trees."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from yaml import YAMLError

from trusted_yaml import load_yaml


SCHEMA_VERSION = 2
POLICY_REPO_PATH = "source_artifact_policy.yaml"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
TRUSTED_FILE_PATHS = (
    POLICY_REPO_PATH,
    "trusted_pr_context.py",
    "trusted_artifact_pr.py",
    "bin_artifact_contract.py",
    "pr_validation_mode.py",
    "pr_validation_mode.yaml",
    "pr_validation_version.py",
    "analysis_output_contract.py",
    "gamesymbol_snapshot_lib/analysis_sources.py",
    "gamesymbol_snapshot_lib/config.py",
    "gamesymbol_snapshot_lib/model.py",
    "gamesymbol_snapshot_lib/paths.py",
    "gamesymbol_snapshot_lib/pr_validation.py",
    ".github/workflows/pr-self-runner.yml",
    ".github/workflows/source-artifact-required.yml",
    "uv.lock",
)


class TrustedPrContextError(RuntimeError):
    pass


@dataclass(frozen=True)
class SourceArtifactPolicy:
    mode: str
    artifact_root: str
    artifact_contract_schema_version: int


class GitRepository:
    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()

    def _run(self, *arguments: str) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(self.path), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise TrustedPrContextError(f"git {' '.join(arguments)} failed: {message}")
        return result.stdout

    def resolve_commit(self, ref: str) -> str:
        return _validated_sha(self._run("rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip(), ref)

    def tree_sha(self, commit: str) -> str:
        return _validated_sha(self._run("rev-parse", "--verify", f"{commit}^{{tree}}").decode().strip(), commit)

    def parents(self, commit: str) -> tuple[str, ...]:
        fields = self._run("rev-list", "--parents", "-n", "1", commit).decode().strip().split()
        if not fields or fields[0] != commit:
            raise TrustedPrContextError(f"unable to resolve parents for prospective merge commit {commit}")
        return tuple(_validated_sha(value, f"parent of {commit}") for value in fields[1:])

    def read(self, ref: str, path: str) -> bytes:
        return self._run("show", f"{ref}:{path}")

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        result = subprocess.run(
            ["git", "-C", str(self.path), "merge-base", "--is-ancestor", ancestor, descendant],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode not in {0, 1}:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise TrustedPrContextError(f"git merge-base --is-ancestor failed: {message}")
        return result.returncode == 0


def _validated_sha(value: str, context: str) -> str:
    value = str(value).strip().lower()
    if not SHA_PATTERN.fullmatch(value):
        raise TrustedPrContextError(f"{context} did not resolve to a full commit or tree SHA: {value!r}")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def parse_source_artifact_policy(payload: bytes) -> SourceArtifactPolicy:
    try:
        document = load_yaml(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, YAMLError) as exc:
        raise TrustedPrContextError(f"trusted source artifact policy is invalid: {exc}") from exc
    if not isinstance(document, dict):
        raise TrustedPrContextError("trusted source artifact policy must be a mapping")
    expected_keys = {
        "schema_version",
        "mode",
        "artifact_root",
        "artifact_contract_schema_version",
    }
    unknown = set(document) - expected_keys
    missing = expected_keys - set(document)
    if unknown or missing:
        raise TrustedPrContextError(
            f"trusted source artifact policy keys mismatch: missing={sorted(missing)!r}; unknown={sorted(unknown)!r}"
        )
    if document["schema_version"] != 1:
        raise TrustedPrContextError("trusted source artifact policy schema_version must be 1")
    mode = document["mode"]
    if mode not in {"legacy", "source-owned"}:
        raise TrustedPrContextError("trusted source artifact policy mode must be legacy or source-owned")
    artifact_root = document["artifact_root"]
    if artifact_root != "bin_artifacts":
        raise TrustedPrContextError("trusted source artifact policy artifact_root must be bin_artifacts")
    contract_version = document["artifact_contract_schema_version"]
    if not isinstance(contract_version, int) or isinstance(contract_version, bool) or contract_version < 1:
        raise TrustedPrContextError("artifact_contract_schema_version must be a positive integer")
    return SourceArtifactPolicy(mode, artifact_root, contract_version)


def _canonical_document_bytes(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _build_context_document(repo, *, event_kind: str, base_sha: str, head_sha: str, merge_sha: str) -> dict:
    trusted_payloads = {path: repo.read(base_sha, path) for path in TRUSTED_FILE_PATHS}
    policy = parse_source_artifact_policy(trusted_payloads[POLICY_REPO_PATH])
    document = {
        "schema_version": SCHEMA_VERSION,
        "event_kind": event_kind,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "merge_sha": merge_sha,
        "base_tree_sha": repo.tree_sha(base_sha),
        "head_tree_sha": repo.tree_sha(head_sha),
        "merge_tree_sha": repo.tree_sha(merge_sha),
        "artifact_policy": {
            "mode": policy.mode,
            "artifact_root": policy.artifact_root,
            "artifact_contract_schema_version": policy.artifact_contract_schema_version,
            "sha256": _sha256(trusted_payloads[POLICY_REPO_PATH]),
        },
        "trusted_files": [
            {"path": path, "size": len(trusted_payloads[path]), "sha256": _sha256(trusted_payloads[path])}
            for path in TRUSTED_FILE_PATHS
        ],
    }
    document["context_sha256"] = _sha256(_canonical_document_bytes(document))
    return document


def build_trusted_pr_context(*, repo_root: str | Path, base_ref: str, head_ref: str, merge_ref: str) -> dict:
    repo = GitRepository(repo_root)
    base_sha = repo.resolve_commit(base_ref)
    head_sha = repo.resolve_commit(head_ref)
    merge_sha = repo.resolve_commit(merge_ref)
    parents = repo.parents(merge_sha)
    if parents != (base_sha, head_sha):
        raise TrustedPrContextError(
            "prospective merge parents do not match the bound base/head commits: "
            f"expected={(base_sha, head_sha)!r}; actual={parents!r}"
        )
    return _build_context_document(
        repo,
        event_kind="pull_request",
        base_sha=base_sha,
        head_sha=head_sha,
        merge_sha=merge_sha,
    )


def build_trusted_merge_group_context(*, repo_root: str | Path, base_ref: str, merge_ref: str) -> dict:
    repo = GitRepository(repo_root)
    base_sha = repo.resolve_commit(base_ref)
    merge_sha = repo.resolve_commit(merge_ref)
    if base_sha == merge_sha or not repo.is_ancestor(base_sha, merge_sha):
        raise TrustedPrContextError("merge-group head must descend from the exact bound base commit")
    return _build_context_document(
        repo,
        event_kind="merge_group",
        base_sha=base_sha,
        head_sha=merge_sha,
        merge_sha=merge_sha,
    )


def validate_trusted_pr_context(document: object) -> dict:
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise TrustedPrContextError("trusted PR context schema is invalid")
    digest = document.get("context_sha256")
    unsigned = dict(document)
    unsigned.pop("context_sha256", None)
    if digest != _sha256(_canonical_document_bytes(unsigned)):
        raise TrustedPrContextError("trusted PR context digest mismatch")
    if document.get("event_kind") not in {"pull_request", "merge_group"}:
        raise TrustedPrContextError("trusted PR context event_kind is invalid")
    for field in (
        "base_sha",
        "head_sha",
        "merge_sha",
        "base_tree_sha",
        "head_tree_sha",
        "merge_tree_sha",
    ):
        _validated_sha(document.get(field, ""), field)
    policy = document.get("artifact_policy")
    if (
        not isinstance(policy, dict)
        or set(policy) != {"mode", "artifact_root", "artifact_contract_schema_version", "sha256"}
        or policy.get("mode") not in {"legacy", "source-owned"}
        or policy.get("artifact_root") != "bin_artifacts"
        or not isinstance(policy.get("artifact_contract_schema_version"), int)
        or isinstance(policy.get("artifact_contract_schema_version"), bool)
        or policy["artifact_contract_schema_version"] < 1
        or not re.fullmatch(r"[0-9a-f]{64}", str(policy.get("sha256", "")))
    ):
        raise TrustedPrContextError("trusted PR context artifact policy is invalid")
    trusted_files = document.get("trusted_files")
    if not isinstance(trusted_files, list) or len(trusted_files) != len(TRUSTED_FILE_PATHS):
        raise TrustedPrContextError("trusted PR context file inventory is invalid")
    for expected_path, item in zip(TRUSTED_FILE_PATHS, trusted_files, strict=True):
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "size", "sha256"}
            or item.get("path") != expected_path
            or not isinstance(item.get("size"), int)
            or isinstance(item.get("size"), bool)
            or item["size"] < 0
            or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))
        ):
            raise TrustedPrContextError("trusted PR context file inventory is invalid")
    return document


def load_trusted_pr_context(path: str | Path) -> dict:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustedPrContextError(f"unable to load trusted PR context: {exc}") from exc
    return validate_trusted_pr_context(document)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _build_command(args: argparse.Namespace) -> int:
    if args.event_kind == "merge_group":
        context = build_trusted_merge_group_context(
            repo_root=args.repo_root,
            base_ref=args.base_ref,
            merge_ref=args.merge_ref,
        )
    else:
        if not args.head_ref:
            raise TrustedPrContextError("--head-ref is required for pull_request context")
        context = build_trusted_pr_context(
            repo_root=args.repo_root,
            base_ref=args.base_ref,
            head_ref=args.head_ref,
            merge_ref=args.merge_ref,
        )
    _atomic_write(Path(args.output), _canonical_document_bytes(context))
    if args.github_output:
        with Path(args.github_output).open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"trust-context-sha256={context['context_sha256']}\n")
            handle.write(f"merge-tree-sha={context['merge_tree_sha']}\n")
    print(f"trust-context-sha256={context['context_sha256']}")
    print(f"merge-tree-sha={context['merge_tree_sha']}")
    return 0


def _verify_command(args: argparse.Namespace) -> int:
    context = load_trusted_pr_context(args.input)
    expected = {
        "base_sha": args.base_ref,
        "head_sha": args.head_ref,
        "merge_sha": args.merge_ref,
    }
    for field, value in expected.items():
        if value and context[field] != _validated_sha(value, field):
            raise TrustedPrContextError(f"trusted PR context {field} mismatch")
    print(context["context_sha256"])
    return 0


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--repo-root", default=".")
    build.add_argument("--event-kind", choices=("pull_request", "merge_group"), default="pull_request")
    build.add_argument("--base-ref", required=True)
    build.add_argument("--head-ref")
    build.add_argument("--merge-ref", required=True)
    build.add_argument("--output", required=True)
    build.add_argument("--github-output")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--input", required=True)
    verify.add_argument("--base-ref")
    verify.add_argument("--head-ref")
    verify.add_argument("--merge-ref")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        return _build_command(args) if args.command == "build" else _verify_command(args)
    except (OSError, TrustedPrContextError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

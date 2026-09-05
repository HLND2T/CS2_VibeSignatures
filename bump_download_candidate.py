#!/usr/bin/env python3
"""Package and hosted-verify a credential-free download-bump candidate."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

import yaml

from binary_lock import (
    BinaryLockError,
    build_binary_lock_from_root,
    load_binary_lock,
    write_binary_lock,
)
from bump_download import BumpPlan, _yaml, append_download_entry
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotConfigError
from gamesymbol_snapshot_lib.paths import is_reparse_point
from release_workflow_lib.binary_cache import validate_binary_cache_tree
from release_workflow_lib.errors import ReleaseWorkflowError


SCHEMA_VERSION = 2
ALLOWED_REPOSITORY = "HLND2T/CS2_VibeSignatures"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$|^[1-9][0-9]*$")


class BumpDownloadCandidateError(RuntimeError):
    """A download-bump candidate or hosted publication transaction is invalid."""


def _canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def _digest(label: str, value: object) -> str:
    raw = f"source-artifact-bump-{label}:v1\n".encode() + _canonical_json_bytes(value)
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _git_bytes(repo_root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise BumpDownloadCandidateError(message or f"git {' '.join(arguments)} failed")
    return result.stdout


def _git(repo_root: Path, *arguments: str) -> str:
    return _git_bytes(repo_root, *arguments).decode("utf-8").strip()


def _validate_identity(repository: str, base_sha: str, gamever: str, source_gamever: str) -> None:
    if repository != ALLOWED_REPOSITORY:
        raise BumpDownloadCandidateError(f"download-bump repository is not allowlisted: {repository}")
    if not SHA_RE.fullmatch(base_sha):
        raise BumpDownloadCandidateError("download-bump base SHA must be a full immutable commit SHA")
    if not GAMEVER_RE.fullmatch(gamever) or not GAMEVER_RE.fullmatch(source_gamever) or gamever == source_gamever:
        raise BumpDownloadCandidateError("download-bump GAMEVER identity is invalid")


def _yaml_document(raw: bytes, label: str) -> dict:
    try:
        value = yaml.safe_load(raw)
    except (UnicodeError, yaml.YAMLError) as exc:
        raise BumpDownloadCandidateError(f"{label} is not valid YAML: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("downloads"), list):
        raise BumpDownloadCandidateError(f"{label} must contain a downloads list")
    return value


def _validate_candidate_bytes(
    *,
    base_download: bytes,
    candidate_download: bytes,
    source_config: bytes,
    candidate_config: bytes,
    gamever: str,
    source_gamever: str,
) -> None:
    base = _yaml_document(base_download, "base download.yaml")
    candidate = _yaml_document(candidate_download, "candidate download.yaml")
    base_downloads = base["downloads"]
    candidate_downloads = candidate["downloads"]
    base_without_downloads = dict(base)
    candidate_without_downloads = dict(candidate)
    base_without_downloads.pop("downloads")
    candidate_without_downloads.pop("downloads")
    if base_without_downloads != candidate_without_downloads:
        raise BumpDownloadCandidateError("download-bump candidate changed fields outside the downloads list")
    if len(candidate_downloads) != len(base_downloads) + 1 or candidate_downloads[:-1] != base_downloads:
        raise BumpDownloadCandidateError("download-bump candidate must append exactly one download entry")
    appended = candidate_downloads[-1]
    if not isinstance(appended, dict) or set(appended) != {"tag", "name", "manifests"}:
        raise BumpDownloadCandidateError("download-bump appended entry schema is invalid")
    patch_version = str(appended.get("name", ""))
    manifests = appended.get("manifests")
    if (
        str(appended.get("tag", "")) != gamever
        or not re.fullmatch(r"^[0-9]+(?:\.[0-9]+){3}$", patch_version)
        or not isinstance(manifests, dict)
        or set(map(str, manifests)) != {"2347771", "2347773"}
        or any(not str(value).isdigit() for value in manifests.values())
    ):
        raise BumpDownloadCandidateError("download-bump appended entry does not match the target default GAMEVER")
    base_gamever = patch_version.replace(".", "")
    if gamever != base_gamever and not re.fullmatch(rf"{re.escape(base_gamever)}[a-z]", gamever):
        raise BumpDownloadCandidateError("download-bump GAMEVER does not match the appended patch version")
    previous_default = next(
        (
            str(entry.get("tag", ""))
            for entry in reversed(base_downloads)
            if isinstance(entry, dict) and "branch" not in entry
        ),
        "",
    )
    if previous_default != source_gamever:
        raise BumpDownloadCandidateError("download-bump config source is not the previous default GAMEVER")
    if candidate_config != source_config:
        raise BumpDownloadCandidateError("download-bump analysis config is not an exact copy of its source GAMEVER")
    expected_document = _yaml().load(base_download.decode("utf-8"))
    append_download_entry(
        expected_document["downloads"],
        BumpPlan(
            updated=True,
            tag=gamever,
            patch_version=patch_version,
            manifests={str(key): str(value) for key, value in manifests.items()},
        ),
    )
    expected_stream = io.StringIO()
    _yaml().dump(expected_document, expected_stream)
    if candidate_download != expected_stream.getvalue().encode("utf-8"):
        raise BumpDownloadCandidateError("download-bump download.yaml bytes were not produced by the trusted appender")


def _load_candidate_contract(candidate_config: bytes, gamever: str, temporary_root: Path):
    config_path = temporary_root / "configs" / f"{gamever}.yaml"
    _atomic_write(config_path, candidate_config)
    try:
        return load_contract(
            config_path,
            gamever,
            temporary_root / "bin",
            artifactdir=temporary_root / "bin_artifacts",
        )
    except SnapshotConfigError as exc:
        raise BumpDownloadCandidateError(f"download-bump candidate config is invalid: {exc}") from exc


def _validate_candidate_binary_lock(
    *, candidate_download: bytes, candidate_config: bytes, candidate_lock: bytes, gamever: str
):
    with tempfile.TemporaryDirectory(prefix="bump-candidate-lock-") as temporary:
        temporary_root = Path(temporary)
        contract = _load_candidate_contract(candidate_config, gamever, temporary_root)
        lock_path = temporary_root / "binary_locks" / f"{gamever}.json"
        _atomic_write(lock_path, candidate_lock)
        try:
            return load_binary_lock(
                lock_path,
                game_version=gamever,
                download_payload=candidate_download,
                binary_targets=contract.binary_targets,
            )
        except BinaryLockError as exc:
            raise BumpDownloadCandidateError(f"download-bump candidate binary lock is invalid: {exc}") from exc


def enroll_bump_binary_lock(
    *,
    repo_root: str | Path,
    base_sha: str,
    gamever: str,
    source_gamever: str,
    repository: str,
    binary_root: str | Path,
) -> dict:
    """Measure a checkout-external fresh binary tree and amend the producer commit."""
    base_sha = base_sha.lower()
    _validate_identity(repository, base_sha, gamever, source_gamever)
    repo_root = Path(repo_root).resolve()
    binary_root = Path(os.path.abspath(binary_root))
    if binary_root == repo_root or repo_root in binary_root.parents:
        raise BumpDownloadCandidateError("download-bump binary enrollment root must remain outside the repository")
    if not binary_root.is_dir():
        raise BumpDownloadCandidateError(f"download-bump fresh binary root is missing: {binary_root}")
    head_sha = _git(repo_root, "rev-parse", "HEAD").lower()
    parent_sha = _git(repo_root, "rev-parse", "HEAD^1").lower()
    if not SHA_RE.fullmatch(head_sha) or parent_sha != base_sha:
        raise BumpDownloadCandidateError("download-bump enrollment commit must be a direct child of the bound base SHA")
    if _git(repo_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise BumpDownloadCandidateError("download-bump enrollment checkout must be clean before adding the lock")
    expected_status = {"M\tdownload.yaml", f"A\tconfigs/{gamever}.yaml"}
    actual_status = set(filter(None, _git(repo_root, "diff", "--name-status", base_sha, head_sha, "--").splitlines()))
    if actual_status != expected_status:
        raise BumpDownloadCandidateError(
            f"download-bump pre-enrollment changed-path allowlist mismatch: {sorted(actual_status)!r}"
        )

    candidate_download = _git_bytes(repo_root, "show", f"{head_sha}:download.yaml")
    candidate_config = _git_bytes(repo_root, "show", f"{head_sha}:configs/{gamever}.yaml")
    with tempfile.TemporaryDirectory(prefix="bump-enrollment-contract-") as temporary:
        contract = _load_candidate_contract(candidate_config, gamever, Path(temporary))
        allowed_paths = frozenset(
            f"{target.module_name}/{PurePosixPath(target.source_path).name}"
            for target in contract.binary_targets.values()
        )
        try:
            validate_binary_cache_tree(binary_root, allowed_paths, allow_excluded=False)
            document = build_binary_lock_from_root(
                game_version=gamever,
                download_payload=candidate_download,
                binary_targets=contract.binary_targets,
                binary_root=binary_root,
            )
        except (BinaryLockError, ReleaseWorkflowError) as exc:
            raise BumpDownloadCandidateError(f"unable to build download-bump binary lock: {exc}") from exc

    relative_lock_path = f"binary_locks/{gamever}.json"
    if _git(repo_root, "ls-tree", base_sha, "--", relative_lock_path):
        raise BumpDownloadCandidateError(
            f"download-bump target binary lock already exists at the bound base: {gamever}"
        )
    write_binary_lock(repo_root / relative_lock_path, document)
    _git(repo_root, "add", "--", relative_lock_path)
    _git(repo_root, "commit", "--amend", "--no-edit")
    amended_sha = _git(repo_root, "rev-parse", "HEAD").lower()
    if _git(repo_root, "rev-parse", "HEAD^1").lower() != base_sha:
        raise BumpDownloadCandidateError("download-bump amended enrollment commit changed its bound parent")
    expected_enrolled_status = {
        "M\tdownload.yaml",
        f"A\tconfigs/{gamever}.yaml",
        f"A\t{relative_lock_path}",
    }
    enrolled_status = set(
        filter(None, _git(repo_root, "diff", "--name-status", base_sha, amended_sha, "--").splitlines())
    )
    if enrolled_status != expected_enrolled_status:
        raise BumpDownloadCandidateError(
            f"download-bump enrolled changed-path allowlist mismatch: {sorted(enrolled_status)!r}"
        )
    lock = _validate_candidate_binary_lock(
        candidate_download=candidate_download,
        candidate_config=candidate_config,
        candidate_lock=_git_bytes(repo_root, "show", f"{amended_sha}:{relative_lock_path}"),
        gamever=gamever,
    )
    return {
        "schema_version": 1,
        "game_version": gamever,
        "producer_commit_sha": amended_sha,
        "binary_lock_sha256": lock.sha256,
        "binary_root": str(binary_root),
    }


def _candidate_files(candidate_root: Path, gamever: str) -> dict[str, bytes]:
    expected_paths = {
        "download.yaml": candidate_root / "files" / "download.yaml",
        f"configs/{gamever}.yaml": candidate_root / "files" / "configs" / f"{gamever}.yaml",
        f"binary_locks/{gamever}.json": candidate_root / "files" / "binary_locks" / f"{gamever}.json",
    }
    for component in (
        candidate_root,
        candidate_root / "files",
        candidate_root / "files" / "configs",
        candidate_root / "files" / "binary_locks",
    ):
        if is_reparse_point(component):
            raise BumpDownloadCandidateError(
                f"download-bump candidate must not traverse a link/reparse point: {component}"
            )
    actual_files = set()
    for current, directories, files in os.walk(candidate_root, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            path = current_path / directory
            if is_reparse_point(path):
                raise BumpDownloadCandidateError(f"download-bump candidate contains a linked directory: {path}")
        for filename in files:
            path = current_path / filename
            if is_reparse_point(path):
                raise BumpDownloadCandidateError(f"download-bump candidate contains a linked file: {path}")
            actual_files.add(path.relative_to(candidate_root).as_posix())
    allowed_package_files = {"candidate-manifest.json", *(f"files/{path}" for path in expected_paths)}
    if actual_files != allowed_package_files:
        raise BumpDownloadCandidateError(
            f"download-bump candidate package allowlist mismatch: {sorted(actual_files)!r}"
        )
    try:
        return {path: source.read_bytes() for path, source in expected_paths.items()}
    except OSError as exc:
        raise BumpDownloadCandidateError(f"unable to read download-bump candidate files: {exc}") from exc


def _inventory(files: dict[str, bytes]) -> list[dict]:
    return [{"path": path, "size": len(raw), "sha256": _sha256(raw)} for path, raw in sorted(files.items())]


def build_bump_candidate(
    *,
    repo_root: str | Path,
    base_sha: str,
    gamever: str,
    source_gamever: str,
    repository: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    output_root: str | Path,
) -> dict:
    base_sha = base_sha.lower()
    _validate_identity(repository, base_sha, gamever, source_gamever)
    repo_root = Path(repo_root).resolve()
    output_root = Path(os.path.abspath(output_root))
    if output_root.exists() or output_root == repo_root or repo_root in output_root.parents:
        raise BumpDownloadCandidateError("download-bump candidate output must be a fresh root outside the repository")
    head_sha = _git(repo_root, "rev-parse", "HEAD").lower()
    parent_sha = _git(repo_root, "rev-parse", "HEAD^1").lower()
    if not SHA_RE.fullmatch(head_sha) or parent_sha != base_sha:
        raise BumpDownloadCandidateError("download-bump producer commit must be a direct child of the bound base SHA")
    if _git(repo_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise BumpDownloadCandidateError("download-bump producer checkout must be clean after candidate commit")
    expected_status = {
        "M\tdownload.yaml",
        f"A\tconfigs/{gamever}.yaml",
        f"A\tbinary_locks/{gamever}.json",
    }
    actual_status = set(filter(None, _git(repo_root, "diff", "--name-status", base_sha, head_sha, "--").splitlines()))
    if actual_status != expected_status:
        raise BumpDownloadCandidateError(f"download-bump changed-path allowlist mismatch: {sorted(actual_status)!r}")

    files = {
        "download.yaml": _git_bytes(repo_root, "show", f"{head_sha}:download.yaml"),
        f"configs/{gamever}.yaml": _git_bytes(repo_root, "show", f"{head_sha}:configs/{gamever}.yaml"),
        f"binary_locks/{gamever}.json": _git_bytes(repo_root, "show", f"{head_sha}:binary_locks/{gamever}.json"),
    }
    base_download = _git_bytes(repo_root, "show", f"{base_sha}:download.yaml")
    source_config = _git_bytes(repo_root, "show", f"{base_sha}:configs/{source_gamever}.yaml")
    _validate_candidate_bytes(
        base_download=base_download,
        candidate_download=files["download.yaml"],
        source_config=source_config,
        candidate_config=files[f"configs/{gamever}.yaml"],
        gamever=gamever,
        source_gamever=source_gamever,
    )
    binary_lock = _validate_candidate_binary_lock(
        candidate_download=files["download.yaml"],
        candidate_config=files[f"configs/{gamever}.yaml"],
        candidate_lock=files[f"binary_locks/{gamever}.json"],
        gamever=gamever,
    )

    output_root.mkdir(parents=True)
    for path, raw in files.items():
        _atomic_write(output_root / "files" / path, raw)
    inventory = _inventory(files)
    artifact_name = f"bump-download-candidate-{gamever}-{workflow_run_id}-{workflow_run_attempt}"
    document = {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "base_sha": base_sha,
        "producer_commit_sha": head_sha,
        "game_version": gamever,
        "source_game_version": source_gamever,
        "workflow_run_id": str(workflow_run_id),
        "workflow_run_attempt": str(workflow_run_attempt),
        "actions_artifact_name": artifact_name,
        "files": inventory,
        "inventory_sha256": _digest("candidate-inventory", inventory),
        "binary_lock_sha256": binary_lock.sha256,
    }
    document["candidate_sha256"] = _digest("candidate-manifest", document)
    _atomic_write(output_root / "candidate-manifest.json", _canonical_json_bytes(document))
    return document


def load_bump_candidate(path: str | Path) -> dict:
    try:
        raw = Path(path).read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BumpDownloadCandidateError(f"unable to load download-bump candidate manifest: {exc}") from exc
    if raw != _canonical_json_bytes(document):
        raise BumpDownloadCandidateError("download-bump candidate manifest is not canonical JSON")
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise BumpDownloadCandidateError("download-bump candidate manifest schema is invalid")
    digest = document.get("candidate_sha256")
    unsigned = dict(document)
    unsigned.pop("candidate_sha256", None)
    if digest != _digest("candidate-manifest", unsigned):
        raise BumpDownloadCandidateError("download-bump candidate manifest digest mismatch")
    if not DIGEST_RE.fullmatch(str(document.get("binary_lock_sha256", ""))):
        raise BumpDownloadCandidateError("download-bump candidate binary lock digest is invalid")
    return document


def prepare_bump_commit(
    *,
    repo_root: str | Path,
    candidate_root: str | Path,
    manifest: dict | str | Path,
    repository: str,
    base_sha: str,
    gamever: str,
    source_gamever: str,
    actions_artifact_name: str,
    actions_artifact_digest: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    workflow_run_url: str,
) -> dict:
    manifest = load_bump_candidate(manifest) if isinstance(manifest, (str, Path)) else manifest
    base_sha = base_sha.lower()
    _validate_identity(repository, base_sha, gamever, source_gamever)
    if (
        manifest.get("repository") != repository
        or manifest.get("base_sha") != base_sha
        or manifest.get("game_version") != gamever
        or manifest.get("source_game_version") != source_gamever
        or manifest.get("workflow_run_id") != str(workflow_run_id)
        or manifest.get("workflow_run_attempt") != str(workflow_run_attempt)
        or manifest.get("actions_artifact_name") != actions_artifact_name
        or not SHA_RE.fullmatch(str(manifest.get("producer_commit_sha", "")))
    ):
        raise BumpDownloadCandidateError("download-bump candidate publication identity mismatch")
    if not DIGEST_RE.fullmatch(actions_artifact_digest):
        raise BumpDownloadCandidateError("download-bump Actions Artifact digest is invalid")

    repo_root = Path(repo_root).resolve()
    candidate_root = Path(os.path.abspath(candidate_root))
    if candidate_root == repo_root or repo_root in candidate_root.parents:
        raise BumpDownloadCandidateError("download-bump candidate input must remain outside the publication checkout")
    if _git(repo_root, "rev-parse", "HEAD").lower() != base_sha:
        raise BumpDownloadCandidateError("download-bump publication checkout does not match the bound base SHA")
    if _git(repo_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise BumpDownloadCandidateError("download-bump publication checkout must be clean")

    files = _candidate_files(candidate_root, gamever)
    inventory = _inventory(files)
    if inventory != manifest.get("files") or _digest("candidate-inventory", inventory) != manifest.get(
        "inventory_sha256"
    ):
        raise BumpDownloadCandidateError("download-bump candidate inventory differs from its manifest")
    base_download = _git_bytes(repo_root, "show", f"{base_sha}:download.yaml")
    source_config = _git_bytes(repo_root, "show", f"{base_sha}:configs/{source_gamever}.yaml")
    _validate_candidate_bytes(
        base_download=base_download,
        candidate_download=files["download.yaml"],
        source_config=source_config,
        candidate_config=files[f"configs/{gamever}.yaml"],
        gamever=gamever,
        source_gamever=source_gamever,
    )
    binary_lock = _validate_candidate_binary_lock(
        candidate_download=files["download.yaml"],
        candidate_config=files[f"configs/{gamever}.yaml"],
        candidate_lock=files[f"binary_locks/{gamever}.json"],
        gamever=gamever,
    )
    if binary_lock.sha256 != manifest.get("binary_lock_sha256"):
        raise BumpDownloadCandidateError("download-bump binary lock digest differs from its manifest")
    if _git(repo_root, "ls-tree", base_sha, "--", f"configs/{gamever}.yaml"):
        raise BumpDownloadCandidateError(f"download-bump target config already exists at the bound base: {gamever}")
    if _git(repo_root, "ls-tree", base_sha, "--", f"binary_locks/{gamever}.json"):
        raise BumpDownloadCandidateError(
            f"download-bump target binary lock already exists at the bound base: {gamever}"
        )

    for path, raw in files.items():
        _atomic_write(repo_root / path, raw)
    _git(
        repo_root,
        "add",
        "--",
        "download.yaml",
        f"configs/{gamever}.yaml",
        f"binary_locks/{gamever}.json",
    )
    staged_status = set(filter(None, _git(repo_root, "diff", "--cached", "--name-status", "--").splitlines()))
    expected_status = {
        "M\tdownload.yaml",
        f"A\tconfigs/{gamever}.yaml",
        f"A\tbinary_locks/{gamever}.json",
    }
    if staged_status != expected_status:
        raise BumpDownloadCandidateError(f"download-bump hosted staged allowlist mismatch: {sorted(staged_status)!r}")
    body = "\n".join(
        (
            f"Base-SHA: {base_sha}",
            f"Game-Version: {gamever}",
            f"Config-Source-Game-Version: {source_gamever}",
            f"Candidate-SHA256: {manifest['candidate_sha256']}",
            f"Binary-Lock-SHA256: {binary_lock.sha256}",
            f"Actions-Artifact-Digest: {actions_artifact_digest}",
            f"Workflow-Run: {workflow_run_url}",
            "Co-Authored-By: Codex <codex@openai.com>",
        )
    )
    _git(repo_root, "commit", "-m", f"chore(download): update manifest for {gamever}", "-m", body)
    commit_sha = _git(repo_root, "rev-parse", "HEAD").lower()
    parent_sha = _git(repo_root, "rev-parse", "HEAD^1").lower()
    if parent_sha != base_sha or not SHA_RE.fullmatch(commit_sha):
        raise BumpDownloadCandidateError("download-bump hosted commit is not a direct child of the bound base")
    return {
        "schema_version": 2,
        "repository": repository,
        "game_version": gamever,
        "base_sha": base_sha,
        "parent_sha": parent_sha,
        "commit_sha": commit_sha,
        "changed_paths": sorted(path.split("\t", 1)[1] for path in staged_status),
        "candidate_sha256": manifest["candidate_sha256"],
        "actions_artifact_digest": actions_artifact_digest,
        "binary_lock_sha256": binary_lock.sha256,
    }


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--repo-root", default=".")
    build.add_argument("--base-sha", required=True)
    build.add_argument("--gamever", required=True)
    build.add_argument("--source-gamever", required=True)
    build.add_argument("--repository", required=True)
    build.add_argument("--workflow-run-id", required=True)
    build.add_argument("--workflow-run-attempt", required=True)
    build.add_argument("--output-root", required=True)
    enroll = subparsers.add_parser("enroll-lock")
    enroll.add_argument("--repo-root", default=".")
    enroll.add_argument("--base-sha", required=True)
    enroll.add_argument("--gamever", required=True)
    enroll.add_argument("--source-gamever", required=True)
    enroll.add_argument("--repository", required=True)
    enroll.add_argument("--binary-root", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--repo-root", default=".")
    prepare.add_argument("--candidate-root", required=True)
    prepare.add_argument("--manifest", required=True)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--base-sha", required=True)
    prepare.add_argument("--gamever", required=True)
    prepare.add_argument("--source-gamever", required=True)
    prepare.add_argument("--actions-artifact-name", required=True)
    prepare.add_argument("--actions-artifact-digest", required=True)
    prepare.add_argument("--workflow-run-id", required=True)
    prepare.add_argument("--workflow-run-attempt", required=True)
    prepare.add_argument("--workflow-run-url", required=True)
    prepare.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "enroll-lock":
            result = enroll_bump_binary_lock(
                repo_root=args.repo_root,
                base_sha=args.base_sha,
                gamever=args.gamever,
                source_gamever=args.source_gamever,
                repository=args.repository,
                binary_root=args.binary_root,
            )
        elif args.command == "build":
            result = build_bump_candidate(
                repo_root=args.repo_root,
                base_sha=args.base_sha,
                gamever=args.gamever,
                source_gamever=args.source_gamever,
                repository=args.repository,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
                output_root=args.output_root,
            )
        else:
            result = prepare_bump_commit(
                repo_root=args.repo_root,
                candidate_root=args.candidate_root,
                manifest=args.manifest,
                repository=args.repository,
                base_sha=args.base_sha,
                gamever=args.gamever,
                source_gamever=args.source_gamever,
                actions_artifact_name=args.actions_artifact_name,
                actions_artifact_digest=args.actions_artifact_digest,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
                workflow_run_url=args.workflow_run_url,
            )
            _atomic_write(Path(args.output), _canonical_json_bytes(result))
    except (BumpDownloadCandidateError, OSError, UnicodeError, yaml.YAMLError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

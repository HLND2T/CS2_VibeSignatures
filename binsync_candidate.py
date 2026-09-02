#!/usr/bin/env python3
"""Build and verify credential-free BinSync Git-bundle publication candidates."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from binary_hashing import hash_file
from bin_artifact_contract import ArtifactContractError, build_game_artifact_inventory
from gamesymbol_snapshot_lib.config import SnapshotConfigError, load_contract
from init_gamebin import (
    BINSYNC_ROOT_BRANCH,
    GITHUB_OWNER,
    InitGamebinError,
    local_binsync_refs,
    normalize_github_remote,
    validate_local_binsync_repo,
)
from release_artifact_rebuild import (
    ReleaseArtifactRebuildError,
    load_release_rebuild_preparation,
)
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    load_json_object,
    normalized_relative_path,
    reject_reparse_points,
    sha256_bytes,
    sha256_file,
    write_canonical_json,
)

CANDIDATE_SCHEMA_VERSION = 1
MANIFEST_NAME = "manifest.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"
ROOT_REF = f"refs/heads/{BINSYNC_ROOT_BRANCH}"
REF_PREFIX = "refs/heads/binsync/"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MD5_RE = re.compile(r"^[0-9a-f]{32}$")
REPOSITORY_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,240}$")
ROOT_TREE_PATHS = frozenset({".gitignore", "binary_hash"})
USER_TREE_PATHS = frozenset({".gitignore", "binary_hash", "symbols.toml"})


class BinSyncCandidateError(Exception):
    """Raised when a BinSync candidate cannot be built or verified safely."""


def _run_git(cwd: Path, *arguments: str, binary: bool = False) -> bytes | str:
    try:
        result = subprocess.run(
            ["git", "-C", str(cwd), *arguments],
            capture_output=True,
            text=not binary,
            check=False,
        )
    except (OSError, UnicodeError) as exc:
        raise BinSyncCandidateError(f"unable to run git {' '.join(arguments)}: {exc}") from exc
    if result.returncode:
        stderr = result.stderr.decode(errors="replace") if binary else result.stderr
        stdout = result.stdout.decode(errors="replace") if binary else result.stdout
        detail = (stderr or stdout or "").strip()
        raise BinSyncCandidateError(detail or f"git {' '.join(arguments)} failed with exit {result.returncode}")
    return result.stdout


def _git_text(cwd: Path, *arguments: str) -> str:
    value = _run_git(cwd, *arguments)
    assert isinstance(value, str)
    return value.strip()


def _git_bytes(cwd: Path, *arguments: str) -> bytes:
    value = _run_git(cwd, *arguments, binary=True)
    assert isinstance(value, bytes)
    return value


def _digest(domain: str, value: object) -> str:
    payload = domain.encode("ascii") + b"\n" + canonical_json_bytes(value)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _plain_sha256(data: bytes) -> str:
    return f"sha256:{sha256_bytes(data)}"


def _release_rebuild_digest(label: str, value: object) -> str:
    payload = f"source-artifact-release-{label}:v1\n".encode("ascii") + canonical_json_bytes(value)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def publication_target_state(document: dict) -> dict:
    repositories = [
        {
            "repository_id": repository["repository_id"],
            "owner": repository["owner"],
            "name": repository["name"],
            "refs": [{"ref": item["ref"], "commit": item["candidate_commit"]} for item in repository["refs"]],
        }
        for repository in document["repositories"]
    ]
    return {
        "repositories": repositories,
        "target_state_digest": _digest("binsync-intended-remote-state:v1", repositories),
    }


def _require_exact_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        detail = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if extra:
            detail.append("extra=" + ",".join(extra))
        raise BinSyncCandidateError(f"{label} fields are invalid ({'; '.join(detail)})")


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise BinSyncCandidateError(f"{label} must be a non-empty string")
    return value


def _canonical_repository_id(owner: str, name: str) -> str:
    if not REPOSITORY_COMPONENT_RE.fullmatch(owner) or not REPOSITORY_COMPONENT_RE.fullmatch(name):
        raise BinSyncCandidateError(f"invalid canonical BinSync repository: {owner}/{name}")
    return f"{owner}__{name}"


def _canonical_remote_url(owner: str, name: str) -> str:
    return f"https://github.com/{owner}/{name}"


def _validate_ref(ref: str) -> str:
    if not isinstance(ref, str) or not ref.startswith(REF_PREFIX) or ref == REF_PREFIX:
        raise BinSyncCandidateError(f"BinSync ref is outside the allowlist: {ref!r}")
    result = subprocess.run(
        ["git", "check-ref-format", ref],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise BinSyncCandidateError(f"invalid BinSync ref: {ref!r}")
    return ref


def _remote_heads(remote_url: str) -> dict[str, str]:
    if remote_url != _canonical_remote_url(GITHUB_OWNER, PurePosixPath(remote_url).name):
        raise BinSyncCandidateError(f"refusing to query non-canonical BinSync remote: {remote_url}")
    output = _git_text(Path.cwd(), "ls-remote", "--heads", "--refs", remote_url, f"{REF_PREFIX}*")
    heads: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 2:
            raise BinSyncCandidateError(f"invalid ls-remote response from {remote_url}")
        commit, ref = fields
        commit = commit.lower()
        _validate_ref(ref)
        if not SHA_RE.fullmatch(commit) or ref in heads:
            raise BinSyncCandidateError(f"invalid or duplicate remote ref from {remote_url}: {line!r}")
        heads[ref] = commit
    return heads


def _object_exists(repo: Path, object_id: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{object_id}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def _is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        detail = (result.stderr or result.stdout).strip()
        raise BinSyncCandidateError(detail or "unable to prove BinSync fast-forward relationship")
    return result.returncode == 0


def _relationship(repo: Path, expected: str | None, candidate: str, ref: str) -> str:
    if expected is None:
        return "create"
    if expected == candidate:
        return "unchanged"
    if not _object_exists(repo, expected) or not _is_ancestor(repo, expected, candidate):
        raise BinSyncCandidateError(f"candidate ref {ref} is not a fast-forward from remote head {expected}")
    return "fast-forward"


def _bundle_heads(bundle: Path) -> dict[str, str]:
    output = _git_text(Path.cwd(), "bundle", "list-heads", str(bundle.resolve()))
    heads: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split(" ", 1)
        if len(fields) != 2:
            raise BinSyncCandidateError(f"invalid Git bundle head: {line!r}")
        commit, ref = fields
        commit = commit.lower()
        _validate_ref(ref)
        if not SHA_RE.fullmatch(commit) or ref in heads:
            raise BinSyncCandidateError(f"invalid or duplicate Git bundle head: {line!r}")
        heads[ref] = commit
    return heads


def _commit_tree_inventory(repo: Path, commit: str, ref: str) -> tuple[str, list[dict], str]:
    tree_sha = _git_text(repo, "rev-parse", f"{commit}^{{tree}}").lower()
    if not SHA_RE.fullmatch(tree_sha):
        raise BinSyncCandidateError(f"invalid BinSync tree SHA for {ref}")
    records = []
    for raw_record in _git_bytes(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if not raw_record:
            continue
        try:
            metadata, raw_path = raw_record.split(b"\t", 1)
            mode, object_type, object_sha = metadata.decode("ascii").split(" ")
            path = normalized_relative_path(raw_path.decode("utf-8"))
        except (UnicodeError, ValueError, ReleaseWorkflowError) as exc:
            raise BinSyncCandidateError(f"malformed BinSync tree entry for {ref}") from exc
        if mode != "100644" or object_type != "blob" or not SHA_RE.fullmatch(object_sha):
            raise BinSyncCandidateError(f"BinSync tree contains a non-regular blob: {ref}:{path}")
        payload = _git_bytes(repo, "cat-file", "blob", object_sha)
        records.append({"path": path, "size": len(payload), "sha256": _plain_sha256(payload)})
    allowed = ROOT_TREE_PATHS if ref == ROOT_REF else USER_TREE_PATHS
    actual = {item["path"] for item in records}
    if actual != allowed:
        raise BinSyncCandidateError(
            f"BinSync commit tree violates the publication allowlist for {ref}: "
            f"missing={sorted(allowed - actual)!r}; unexpected={sorted(actual - allowed)!r}"
        )
    return tree_sha, records, _digest("binsync-commit-tree-inventory:v1", records)


def _verify_bundle(bundle: Path, repository: dict) -> None:
    expected_heads = {item["ref"]: item["candidate_commit"] for item in repository["refs"]}
    if _bundle_heads(bundle) != expected_heads:
        raise BinSyncCandidateError(f"Git bundle refs do not match manifest: {bundle}")
    with tempfile.TemporaryDirectory(prefix="verify-binsync-bundle-") as temporary:
        verification_repo = Path(temporary) / "repository.git"
        verification_repo.mkdir()
        _git_text(verification_repo, "init", "--bare")
        _git_text(verification_repo, "bundle", "verify", str(bundle.resolve()))
        for index, (ref, commit) in enumerate(sorted(expected_heads.items())):
            verify_ref = f"refs/verify/{index}"
            _git_text(verification_repo, "fetch", "--no-tags", str(bundle.resolve()), f"{ref}:{verify_ref}")
            if _git_text(verification_repo, "rev-parse", verify_ref).lower() != commit:
                raise BinSyncCandidateError(f"Git bundle candidate commit mismatch for {ref}")

        refs = repository["refs"]
        root_item = next((item for item in refs if item["ref"] == ROOT_REF), None)
        if root_item is None:
            raise BinSyncCandidateError(f"Git bundle is missing required root ref {ROOT_REF}")
        root_commit = root_item["candidate_commit"]
        if root_item["expected_remote_head"] is not None and root_item["relationship"] != "unchanged":
            raise BinSyncCandidateError("existing BinSync root ref must remain immutable")
        binary_hash = _git_text(verification_repo, "show", f"{root_commit}:binary_hash").lower()
        if binary_hash != repository["binary"]["md5"]:
            raise BinSyncCandidateError(f"Git bundle binary_hash mismatch for {repository['repository_id']}")
        for item in refs:
            candidate_commit = item["candidate_commit"]
            expected = item["expected_remote_head"]
            tree_sha, tree_files, tree_inventory_sha256 = _commit_tree_inventory(
                verification_repo, candidate_commit, item["ref"]
            )
            if (
                tree_sha != item["tree_sha"]
                or tree_files != item["tree_files"]
                or tree_inventory_sha256 != item["tree_inventory_sha256"]
            ):
                raise BinSyncCandidateError(f"BinSync commit tree evidence mismatch for {item['ref']}")
            if not _is_ancestor(verification_repo, root_commit, candidate_commit):
                raise BinSyncCandidateError(f"BinSync ref does not descend from the immutable root: {item['ref']}")
            actual_relationship = _relationship(verification_repo, expected, candidate_commit, item["ref"])
            if actual_relationship != item["relationship"]:
                raise BinSyncCandidateError(f"fast-forward proof mismatch for {item['ref']}")


def _sdk_gitlink(repo_root: Path, source_sha: str) -> str:
    fields = _git_text(repo_root, "ls-tree", source_sha, "--", "hl2sdk_cs2").split()
    if len(fields) < 3 or fields[0] != "160000" or fields[1] != "commit" or not SHA_RE.fullmatch(fields[2]):
        raise BinSyncCandidateError("source commit does not bind the hl2sdk_cs2 gitlink")
    return fields[2]


def _source_blob(repo_root: Path, source_sha: str, path: str) -> bytes:
    normalized_relative_path(path)
    return _git_bytes(repo_root, "cat-file", "blob", f"{source_sha}:{path}")


def _binary_entries(binary_inventory: dict) -> list[dict]:
    entries = []
    if not isinstance(binary_inventory, dict) or not binary_inventory:
        raise BinSyncCandidateError("release preparation binary inventory is invalid")
    for module in sorted(binary_inventory):
        platforms = binary_inventory[module]
        if not isinstance(module, str) or not module or not isinstance(platforms, dict):
            raise BinSyncCandidateError("release preparation binary inventory is invalid")
        for platform in sorted(platforms):
            metadata = platforms[platform]
            if platform not in {"windows", "linux"} or not isinstance(metadata, dict):
                raise BinSyncCandidateError("release preparation binary inventory is invalid")
            expected_fields = {"path", "sha256", "md5", "crc32", "crc64", "size"}
            _require_exact_keys(metadata, expected_fields, "binary inventory entry")
            source_path = normalized_relative_path(_require_string(metadata["path"], "binary source path"))
            if not SHA256_RE.fullmatch(str(metadata["sha256"])) or not MD5_RE.fullmatch(str(metadata["md5"])):
                raise BinSyncCandidateError("release preparation binary hashes are invalid")
            if not isinstance(metadata["size"], int) or isinstance(metadata["size"], bool) or metadata["size"] < 0:
                raise BinSyncCandidateError("release preparation binary size is invalid")
            entries.append({"module": module, "platform": platform, "source_path": source_path, **metadata})
    return entries


def _nested_binary_inventory(repositories: list[dict]) -> dict:
    inventory: dict[str, dict[str, dict]] = {}
    for repository in repositories:
        binary = repository["binary"]
        module = binary["module"]
        platform = binary["platform"]
        metadata = {key: binary[key] for key in ("path", "sha256", "md5", "crc32", "crc64", "size")}
        if platform in inventory.setdefault(module, {}):
            raise BinSyncCandidateError(f"duplicate binary inventory target: {module}/{platform}")
        inventory[module][platform] = metadata
    return inventory


def _repository_for_binary(
    *,
    repo_root: Path,
    game_version: str,
    binary: dict,
    repositories_root: Path,
) -> dict:
    binary_name = PurePosixPath(binary["source_path"]).name
    local_binary = repo_root / "bin" / game_version / binary["module"] / binary_name
    if not local_binary.is_file():
        raise BinSyncCandidateError(f"configured release binary is missing: {local_binary}")
    actual_hashes = hash_file(local_binary)
    expected_hashes = {key: binary[key] for key in ("sha256", "md5", "crc32", "crc64", "size")}
    if actual_hashes != expected_hashes:
        raise BinSyncCandidateError(f"configured release binary identity drifted: {local_binary}")

    repository_name = f"CS2_VibeSignatures_binsync_{game_version}_{binary_name}"
    repository_id = _canonical_repository_id(GITHUB_OWNER, repository_name)
    remote_url = _canonical_remote_url(GITHUB_OWNER, repository_name)
    local_repo = local_binary.parent / f"{binary_name}.bsproj"
    try:
        exists, locked = validate_local_binsync_repo(local_repo, binary["md5"], repository_name)
    except InitGamebinError as exc:
        raise BinSyncCandidateError(str(exc)) from exc
    if not exists or locked:
        state = "missing" if not exists else "locked"
        raise BinSyncCandidateError(f"local BinSync repository is {state}: {local_repo}")
    origin = _git_text(local_repo, "remote", "get-url", "origin")
    if origin != remote_url or normalize_github_remote(origin) != (GITHUB_OWNER.casefold(), repository_name.casefold()):
        raise BinSyncCandidateError(f"local BinSync origin is not canonical: {local_repo}")

    try:
        local_refs = local_binsync_refs(local_repo)
    except InitGamebinError as exc:
        raise BinSyncCandidateError(str(exc)) from exc
    current_ref = _git_text(local_repo, "symbolic-ref", "--quiet", "HEAD")
    if current_ref == ROOT_REF or current_ref not in local_refs or not current_ref.startswith(REF_PREFIX):
        raise BinSyncCandidateError(f"local BinSync repository is not on its publication user ref: {local_repo}")
    refs = [ROOT_REF, current_ref]
    remote_heads = _remote_heads(remote_url)
    ref_records = []
    for ref in refs:
        _validate_ref(ref)
        candidate_commit = _git_text(local_repo, "rev-parse", ref).lower()
        if not SHA_RE.fullmatch(candidate_commit):
            raise BinSyncCandidateError(f"invalid local candidate commit for {ref}")
        expected = remote_heads.get(ref)
        tree_sha, tree_files, tree_inventory_sha256 = _commit_tree_inventory(local_repo, candidate_commit, ref)
        ref_records.append(
            {
                "ref": ref,
                "expected_remote_head": expected,
                "candidate_commit": candidate_commit,
                "fast_forward": True,
                "relationship": _relationship(local_repo, expected, candidate_commit, ref),
                "tree_sha": tree_sha,
                "tree_files": tree_files,
                "tree_inventory_sha256": tree_inventory_sha256,
            }
        )

    bundle_relative = f"repositories/{repository_id}.bundle"
    bundle_path = repositories_root / f"{repository_id}.bundle"
    _git_text(local_repo, "bundle", "create", str(bundle_path.resolve()), *refs)
    bundle = {
        "path": bundle_relative,
        "size": bundle_path.stat().st_size,
        "sha256": sha256_file(bundle_path),
    }
    repository = {
        "repository_id": repository_id,
        "owner": GITHUB_OWNER,
        "name": repository_name,
        "remote_url": remote_url,
        "binary": {
            "module": binary["module"],
            "platform": binary["platform"],
            "path": binary["source_path"],
            "sha256": binary["sha256"],
            "md5": binary["md5"],
            "crc32": binary["crc32"],
            "crc64": binary["crc64"],
            "size": binary["size"],
        },
        "refs": ref_records,
        "bundle": bundle,
    }
    _verify_bundle(bundle_path, repository)
    return repository


def _write_checksums(path: Path, repositories: list[dict]) -> bytes:
    lines = [f"{item['bundle']['sha256']}  {item['bundle']['path']}" for item in repositories]
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return payload


def build_candidate(
    *,
    repo_root: str | Path,
    preparation: dict | str | Path,
    candidate_root: str | Path,
    release_version: str,
    build_id: str,
    ida_runtime_identity: str,
    actions_artifact_name: str,
) -> dict:
    """Build one deterministic, credential-free publication candidate."""
    repo_root = Path(repo_root).resolve()
    if not isinstance(preparation, dict):
        try:
            preparation = load_release_rebuild_preparation(preparation)
        except ReleaseArtifactRebuildError as exc:
            raise BinSyncCandidateError(str(exc)) from exc
    candidate_root = Path(os.path.abspath(candidate_root))
    if candidate_root.exists():
        raise BinSyncCandidateError(f"candidate root must be fresh: {candidate_root}")
    candidate_root.mkdir(parents=True)
    repositories_root = candidate_root / "repositories"
    repositories_root.mkdir()

    source_sha = str(preparation.get("source_sha", "")).lower()
    game_version = str(preparation.get("game_version", ""))
    release_version = _require_string(release_version, "release version")
    build_id = _require_string(build_id, "build ID")
    ida_runtime_identity = _require_string(ida_runtime_identity, "IDA runtime identity")
    actions_artifact_name = _require_string(actions_artifact_name, "Actions Artifact name")
    if not SHA_RE.fullmatch(source_sha) or _git_text(repo_root, "rev-parse", "HEAD").lower() != source_sha:
        raise BinSyncCandidateError("candidate checkout does not match the release source SHA")
    if not game_version:
        raise BinSyncCandidateError("release preparation GAMEVER is invalid")
    if not ARTIFACT_NAME_RE.fullmatch(actions_artifact_name):
        raise BinSyncCandidateError("Actions Artifact name contains unsafe characters")

    config_path = repo_root / "configs" / f"{game_version}.yaml"
    try:
        contract = load_contract(config_path, game_version, repo_root / "bin", artifactdir=repo_root / "bin_artifacts")
        artifact_inventory = build_game_artifact_inventory(
            repo_root=repo_root,
            config_path=config_path,
            game_version=game_version,
            artifact_root=repo_root / "bin_artifacts",
            require_tracked=True,
        )
    except (SnapshotConfigError, ArtifactContractError) as exc:
        raise BinSyncCandidateError(f"unable to bind source-owned artifact identity: {exc}") from exc
    if contract.config_sha256 != preparation.get("config_sha256"):
        raise BinSyncCandidateError("release preparation config identity drifted")
    if artifact_inventory.inventory_sha256 != preparation.get("expected_artifact_inventory_sha256"):
        raise BinSyncCandidateError("release preparation artifact inventory identity drifted")
    if _sdk_gitlink(repo_root, source_sha) != preparation.get("sdk_gitlink_sha"):
        raise BinSyncCandidateError("release preparation SDK identity drifted")

    binary_entries = _binary_entries(preparation.get("binary_inventory"))
    repositories = [
        _repository_for_binary(
            repo_root=repo_root,
            game_version=game_version,
            binary=binary,
            repositories_root=repositories_root,
        )
        for binary in binary_entries
    ]
    repositories.sort(key=lambda item: item["repository_id"])
    repository_ids = [item["repository_id"].casefold() for item in repositories]
    if len(repository_ids) != len(set(repository_ids)):
        raise BinSyncCandidateError("canonical BinSync repository IDs collide")
    nested_binary_inventory = _nested_binary_inventory(repositories)
    if _release_rebuild_digest("binary-inventory", nested_binary_inventory) != preparation.get(
        "binary_inventory_sha256"
    ):
        raise BinSyncCandidateError("release preparation binary inventory digest mismatch")

    checksums_payload = _write_checksums(candidate_root / CHECKSUMS_NAME, repositories)
    document = {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "source_sha": source_sha,
        "game_version": game_version,
        "release_version": release_version,
        "build_id": build_id,
        "actions_artifact_name": actions_artifact_name,
        "config_sha256": contract.config_sha256,
        "download_sha256": _plain_sha256(_source_blob(repo_root, source_sha, "download.yaml")),
        "sdk_gitlink_sha": preparation["sdk_gitlink_sha"],
        "artifact_inventory_sha256": artifact_inventory.inventory_sha256,
        "binary_inventory_sha256": preparation["binary_inventory_sha256"],
        "ida_runtime_identity": ida_runtime_identity,
        "repositories": repositories,
        "checksum_file": {
            "path": CHECKSUMS_NAME,
            "size": len(checksums_payload),
            "sha256": sha256_bytes(checksums_payload),
        },
    }
    document["publication_digest"] = _digest("binsync-publication-candidate:v1", document)
    write_canonical_json(candidate_root / MANIFEST_NAME, document)
    verify_candidate(
        candidate_root=candidate_root,
        repo_root=repo_root,
        expected_source_sha=source_sha,
        expected_game_version=game_version,
        expected_release_version=release_version,
        expected_build_id=build_id,
        expected_ida_runtime_identity=ida_runtime_identity,
        expected_actions_artifact_name=actions_artifact_name,
    )
    return document


def _validate_binary(binary: dict) -> None:
    expected = {"module", "platform", "path", "sha256", "md5", "crc32", "crc64", "size"}
    _require_exact_keys(binary, expected, "repository binary")
    _require_string(binary["module"], "binary module")
    if binary["platform"] not in {"windows", "linux"}:
        raise BinSyncCandidateError("binary platform is invalid")
    normalized_relative_path(_require_string(binary["path"], "binary path"))
    if not SHA256_RE.fullmatch(str(binary["sha256"])) or not MD5_RE.fullmatch(str(binary["md5"])):
        raise BinSyncCandidateError("repository binary hashes are invalid")
    if not isinstance(binary["size"], int) or isinstance(binary["size"], bool) or binary["size"] < 0:
        raise BinSyncCandidateError("repository binary size is invalid")


def _validate_repository(repository: dict) -> None:
    expected = {"repository_id", "owner", "name", "remote_url", "binary", "refs", "bundle"}
    _require_exact_keys(repository, expected, "repository")
    owner = _require_string(repository["owner"], "repository owner")
    name = _require_string(repository["name"], "repository name")
    repository_id = _canonical_repository_id(owner, name)
    if owner != GITHUB_OWNER or repository["repository_id"] != repository_id:
        raise BinSyncCandidateError(f"BinSync repository is outside the allowlist: {owner}/{name}")
    if repository["remote_url"] != _canonical_remote_url(owner, name):
        raise BinSyncCandidateError(f"BinSync repository remote is not canonical: {repository_id}")
    _validate_binary(repository["binary"])

    refs = repository["refs"]
    if not isinstance(refs, list) or len(refs) != 2:
        raise BinSyncCandidateError(f"BinSync repository must bind root and user refs: {repository_id}")
    if refs != sorted(refs, key=lambda item: (item.get("ref") != ROOT_REF, item.get("ref", ""))):
        raise BinSyncCandidateError(f"BinSync refs are not canonical: {repository_id}")
    seen_refs = set()
    for item in refs:
        if not isinstance(item, dict):
            raise BinSyncCandidateError(f"BinSync ref entry is invalid: {repository_id}")
        _require_exact_keys(
            item,
            {
                "ref",
                "expected_remote_head",
                "candidate_commit",
                "fast_forward",
                "relationship",
                "tree_sha",
                "tree_files",
                "tree_inventory_sha256",
            },
            "repository ref",
        )
        ref = _validate_ref(item["ref"])
        if ref in seen_refs:
            raise BinSyncCandidateError(f"duplicate BinSync ref: {ref}")
        seen_refs.add(ref)
        expected_head = item["expected_remote_head"]
        if (
            not SHA_RE.fullmatch(str(item["tree_sha"]))
            or not isinstance(item["tree_files"], list)
            or not DIGEST_RE.fullmatch(str(item["tree_inventory_sha256"]))
            or item["tree_inventory_sha256"] != _digest("binsync-commit-tree-inventory:v1", item["tree_files"])
        ):
            raise BinSyncCandidateError(f"BinSync ref tree evidence is invalid: {ref}")
        if expected_head is not None and (not isinstance(expected_head, str) or not SHA_RE.fullmatch(expected_head)):
            raise BinSyncCandidateError(f"expected remote head is invalid for {ref}")
        if not isinstance(item["candidate_commit"], str) or not SHA_RE.fullmatch(item["candidate_commit"]):
            raise BinSyncCandidateError(f"candidate commit is invalid for {ref}")
        if item["fast_forward"] is not True or item["relationship"] not in {"create", "unchanged", "fast-forward"}:
            raise BinSyncCandidateError(f"fast-forward declaration is invalid for {ref}")
    if ROOT_REF not in seen_refs:
        raise BinSyncCandidateError(f"BinSync repository is missing {ROOT_REF}")
    if sum(ref != ROOT_REF for ref in seen_refs) != 1:
        raise BinSyncCandidateError(f"BinSync repository must bind exactly one publication user ref: {repository_id}")

    bundle = repository["bundle"]
    if not isinstance(bundle, dict):
        raise BinSyncCandidateError(f"bundle entry is invalid: {repository_id}")
    _require_exact_keys(bundle, {"path", "size", "sha256"}, "bundle")
    expected_path = f"repositories/{repository_id}.bundle"
    if bundle["path"] != expected_path or normalized_relative_path(bundle["path"]) != expected_path:
        raise BinSyncCandidateError(f"bundle path is not canonical: {bundle['path']!r}")
    if not isinstance(bundle["size"], int) or isinstance(bundle["size"], bool) or bundle["size"] <= 0:
        raise BinSyncCandidateError(f"bundle size is invalid: {expected_path}")
    if not isinstance(bundle["sha256"], str) or not SHA256_RE.fullmatch(bundle["sha256"]):
        raise BinSyncCandidateError(f"bundle SHA-256 is invalid: {expected_path}")


def _validate_manifest(document: dict) -> None:
    expected_fields = {
        "schema_version",
        "source_sha",
        "game_version",
        "release_version",
        "build_id",
        "actions_artifact_name",
        "config_sha256",
        "download_sha256",
        "sdk_gitlink_sha",
        "artifact_inventory_sha256",
        "binary_inventory_sha256",
        "ida_runtime_identity",
        "repositories",
        "checksum_file",
        "publication_digest",
    }
    _require_exact_keys(document, expected_fields, "manifest")
    if document["schema_version"] != CANDIDATE_SCHEMA_VERSION:
        raise BinSyncCandidateError("BinSync candidate schema version is invalid")
    if not isinstance(document["source_sha"], str) or not SHA_RE.fullmatch(document["source_sha"]):
        raise BinSyncCandidateError("BinSync candidate source SHA is invalid")
    for field in ("game_version", "release_version", "build_id", "ida_runtime_identity"):
        _require_string(document[field], field.replace("_", " "))
    if not isinstance(document["actions_artifact_name"], str) or not ARTIFACT_NAME_RE.fullmatch(
        document["actions_artifact_name"]
    ):
        raise BinSyncCandidateError("BinSync candidate Actions Artifact name is invalid")
    for field in ("config_sha256", "download_sha256", "artifact_inventory_sha256", "binary_inventory_sha256"):
        if not isinstance(document[field], str) or not DIGEST_RE.fullmatch(document[field]):
            raise BinSyncCandidateError(f"BinSync candidate {field} is invalid")
    if not isinstance(document["sdk_gitlink_sha"], str) or not SHA_RE.fullmatch(document["sdk_gitlink_sha"]):
        raise BinSyncCandidateError("BinSync candidate SDK gitlink is invalid")

    repositories = document["repositories"]
    if not isinstance(repositories, list) or not repositories:
        raise BinSyncCandidateError("BinSync candidate repositories must be a non-empty list")
    for repository in repositories:
        if not isinstance(repository, dict):
            raise BinSyncCandidateError("BinSync candidate repository entry is invalid")
        _validate_repository(repository)
    if repositories != sorted(repositories, key=lambda item: item["repository_id"]):
        raise BinSyncCandidateError("BinSync candidate repositories are not canonical")
    ids = [item["repository_id"].casefold() for item in repositories]
    if len(ids) != len(set(ids)):
        raise BinSyncCandidateError("BinSync candidate repository IDs collide")

    checksum = document["checksum_file"]
    if not isinstance(checksum, dict):
        raise BinSyncCandidateError("BinSync candidate checksum entry is invalid")
    _require_exact_keys(checksum, {"path", "size", "sha256"}, "checksum file")
    if checksum["path"] != CHECKSUMS_NAME:
        raise BinSyncCandidateError("BinSync candidate checksum path is invalid")
    if not isinstance(checksum["size"], int) or isinstance(checksum["size"], bool) or checksum["size"] <= 0:
        raise BinSyncCandidateError("BinSync candidate checksum size is invalid")
    if not isinstance(checksum["sha256"], str) or not SHA256_RE.fullmatch(checksum["sha256"]):
        raise BinSyncCandidateError("BinSync candidate checksum SHA-256 is invalid")
    unsigned = dict(document)
    publication_digest = unsigned.pop("publication_digest", None)
    if publication_digest != _digest("binsync-publication-candidate:v1", unsigned):
        raise BinSyncCandidateError("BinSync candidate publication digest mismatch")


def _verify_source_identity(repo_root: Path, document: dict) -> None:
    source_sha = document["source_sha"]
    if _git_text(repo_root, "rev-parse", "HEAD").lower() != source_sha:
        raise BinSyncCandidateError("hosted verifier checkout does not match candidate source SHA")
    game_version = document["game_version"]
    config_path = repo_root / "configs" / f"{game_version}.yaml"
    try:
        contract = load_contract(config_path, game_version, repo_root / "bin", artifactdir=repo_root / "bin_artifacts")
        artifact_inventory = build_game_artifact_inventory(
            repo_root=repo_root,
            config_path=config_path,
            game_version=game_version,
            artifact_root=repo_root / "bin_artifacts",
            require_tracked=True,
        )
    except (SnapshotConfigError, ArtifactContractError) as exc:
        raise BinSyncCandidateError(f"hosted source artifact verification failed: {exc}") from exc
    if contract.config_sha256 != document["config_sha256"]:
        raise BinSyncCandidateError("hosted verifier config identity mismatch")
    if artifact_inventory.inventory_sha256 != document["artifact_inventory_sha256"]:
        raise BinSyncCandidateError("hosted verifier artifact inventory mismatch")
    if _plain_sha256(_source_blob(repo_root, source_sha, "download.yaml")) != document["download_sha256"]:
        raise BinSyncCandidateError("hosted verifier download identity mismatch")
    if _sdk_gitlink(repo_root, source_sha) != document["sdk_gitlink_sha"]:
        raise BinSyncCandidateError("hosted verifier SDK identity mismatch")

    target_paths = {
        (target.module_name, target.platform): target.source_path for target in contract.binary_targets.values()
    }
    repositories = document["repositories"]
    candidate_paths = {
        (item["binary"]["module"], item["binary"]["platform"]): item["binary"]["path"] for item in repositories
    }
    if candidate_paths != target_paths:
        raise BinSyncCandidateError("hosted verifier binary target inventory mismatch")
    if (
        _release_rebuild_digest("binary-inventory", _nested_binary_inventory(repositories))
        != document["binary_inventory_sha256"]
    ):
        raise BinSyncCandidateError("hosted verifier binary inventory digest mismatch")
    for repository in repositories:
        expected_name = f"CS2_VibeSignatures_binsync_{game_version}_{PurePosixPath(repository['binary']['path']).name}"
        if repository["name"] != expected_name:
            raise BinSyncCandidateError(f"hosted verifier repository allowlist mismatch: {repository['name']}")


def verify_candidate(
    *,
    candidate_root: str | Path,
    repo_root: str | Path | None = None,
    expected_source_sha: str | None = None,
    expected_game_version: str | None = None,
    expected_release_version: str | None = None,
    expected_build_id: str | None = None,
    expected_ida_runtime_identity: str | None = None,
    expected_actions_artifact_name: str | None = None,
    check_remotes: bool = False,
) -> dict:
    """Verify exact candidate bytes, Git bundles, identities, and publication plan."""
    candidate_root = Path(candidate_root).resolve()
    try:
        reject_reparse_points(candidate_root)
        manifest_path = candidate_root / MANIFEST_NAME
        document = load_json_object(manifest_path)
    except ReleaseWorkflowError as exc:
        raise BinSyncCandidateError(str(exc)) from exc
    if manifest_path.read_bytes() != canonical_json_bytes(document):
        raise BinSyncCandidateError("BinSync candidate manifest is not canonical JSON")
    _validate_manifest(document)

    expected_values = {
        "source SHA": (expected_source_sha.lower() if expected_source_sha else None, document["source_sha"]),
        "GAMEVER": (
            str(expected_game_version) if expected_game_version is not None else None,
            document["game_version"],
        ),
        "release version": (expected_release_version, document["release_version"]),
        "build ID": (expected_build_id, document["build_id"]),
        "IDA runtime identity": (expected_ida_runtime_identity, document["ida_runtime_identity"]),
        "Actions Artifact name": (expected_actions_artifact_name, document["actions_artifact_name"]),
    }
    for label, (expected, actual) in expected_values.items():
        if expected is not None and expected != actual:
            raise BinSyncCandidateError(f"BinSync candidate {label} mismatch: expected {expected}, got {actual}")

    allowed_paths = {MANIFEST_NAME, CHECKSUMS_NAME}
    expected_checksum_lines = []
    for repository in document["repositories"]:
        bundle_record = repository["bundle"]
        bundle_path = candidate_root / PurePosixPath(bundle_record["path"])
        allowed_paths.add(bundle_record["path"])
        if not bundle_path.is_file() or bundle_path.stat().st_size != bundle_record["size"]:
            raise BinSyncCandidateError(f"BinSync bundle size mismatch: {bundle_record['path']}")
        if sha256_file(bundle_path) != bundle_record["sha256"]:
            raise BinSyncCandidateError(f"BinSync bundle checksum mismatch: {bundle_record['path']}")
        expected_checksum_lines.append(f"{bundle_record['sha256']}  {bundle_record['path']}")
        _verify_bundle(bundle_path, repository)
        if check_remotes:
            remote_heads = _remote_heads(repository["remote_url"])
            for item in repository["refs"]:
                if remote_heads.get(item["ref"]) != item["expected_remote_head"]:
                    raise BinSyncCandidateError(f"remote head drift for {repository['repository_id']} {item['ref']}")

    actual_paths = {path.relative_to(candidate_root).as_posix() for path in candidate_root.rglob("*") if path.is_file()}
    if actual_paths != allowed_paths:
        unexpected = sorted(actual_paths - allowed_paths)
        missing = sorted(allowed_paths - actual_paths)
        detail = []
        if unexpected:
            detail.append("unexpected=" + ",".join(unexpected))
        if missing:
            detail.append("missing=" + ",".join(missing))
        raise BinSyncCandidateError("unexpected candidate files (" + "; ".join(detail) + ")")

    checksums_payload = ("\n".join(expected_checksum_lines) + "\n").encode("utf-8")
    checksum_path = candidate_root / CHECKSUMS_NAME
    checksum_record = document["checksum_file"]
    if (
        checksum_path.read_bytes() != checksums_payload
        or checksum_record["size"] != len(checksums_payload)
        or checksum_record["sha256"] != sha256_bytes(checksums_payload)
    ):
        raise BinSyncCandidateError("BinSync SHA256SUMS contract mismatch")
    if repo_root is not None:
        _verify_source_identity(Path(repo_root).resolve(), document)
    target_state = publication_target_state(document)
    return {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "source_sha": document["source_sha"],
        "game_version": document["game_version"],
        "build_id": document["build_id"],
        "repository_count": len(document["repositories"]),
        "publication_digest": document["publication_digest"],
        **target_state,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--repo-root", default=".")
    build.add_argument("--preparation", required=True)
    build.add_argument("--candidate-root", required=True)
    build.add_argument("--release-version", required=True)
    build.add_argument("--build-id", required=True)
    build.add_argument("--ida-runtime-identity", required=True)
    build.add_argument("--actions-artifact-name", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--repo-root")
    verify.add_argument("--candidate-root", required=True)
    verify.add_argument("--source-sha")
    verify.add_argument("--gamever")
    verify.add_argument("--release-version")
    verify.add_argument("--build-id")
    verify.add_argument("--ida-runtime-identity")
    verify.add_argument("--actions-artifact-name")
    verify.add_argument("--check-remotes", action="store_true")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build":
            result = build_candidate(
                repo_root=args.repo_root,
                preparation=args.preparation,
                candidate_root=args.candidate_root,
                release_version=args.release_version,
                build_id=args.build_id,
                ida_runtime_identity=args.ida_runtime_identity,
                actions_artifact_name=args.actions_artifact_name,
            )
        else:
            result = verify_candidate(
                candidate_root=args.candidate_root,
                repo_root=args.repo_root,
                expected_source_sha=args.source_sha,
                expected_game_version=args.gamever,
                expected_release_version=args.release_version,
                expected_build_id=args.build_id,
                expected_ida_runtime_identity=args.ida_runtime_identity,
                expected_actions_artifact_name=args.actions_artifact_name,
                check_remotes=args.check_remotes,
            )
    except BinSyncCandidateError as exc:
        print(f"BinSync candidate error: {exc}", file=sys.stderr)
        return 1
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

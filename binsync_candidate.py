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
import tomllib
from pathlib import Path, PurePosixPath

from binary_lock import BinaryLockError, load_binary_lock_from_revision
from binary_hashing import hash_file
from bin_artifact_contract import (
    ArtifactContractError,
    build_game_artifact_inventory,
    load_game_artifact_git_blobs,
)
from binsync_projection import (
    BinSyncProjectionError,
    FUNCTION_CATEGORIES,
    GLOBAL_CATEGORIES,
    build_source_projection,
    first_segment_lift_bias,
    validate_source_projection,
)
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

CANDIDATE_SCHEMA_VERSION = 5
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
USER_REQUIRED_TREE_PATHS = frozenset(
    {
        ".gitignore",
        "binary_hash",
        "comments.toml",
        "enums.toml",
        "global_vars.toml",
        "metadata.toml",
        "patches.toml",
        "segments.toml",
        "typedefs.toml",
    }
)
FUNCTION_TOML_RE = re.compile(r"^functions/([0-9a-f]{8,16})\.toml$")
STRUCT_TOML_RE = re.compile(r"^structs/[^/]+\.toml$")
LOWERING_SCHEMA_VERSION = 1
LOWERING_ENTRY_FIELDS = {
    "artifact_path",
    "artifact_sha256",
    "category",
    "lifted_address",
    "source_rva",
    "symbol",
    "tree_path",
}


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


def _load_binsync_toml(payload: bytes, path: str) -> dict:
    try:
        document = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise BinSyncCandidateError(f"BinSync tree contains invalid TOML: {path}") from exc
    if not isinstance(document, dict):
        raise BinSyncCandidateError(f"BinSync TOML top level is not a mapping: {path}")
    return document


def _toml_address(value: object, *, path: str, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise BinSyncCandidateError(f"BinSync TOML {path} has invalid {field}")
    return value


def _validate_address_table(document: dict, *, path: str, kind: str) -> None:
    for key, value in document.items():
        try:
            address = int(key, 0)
        except (TypeError, ValueError) as exc:
            raise BinSyncCandidateError(f"BinSync {kind} table has an invalid address key: {path}:{key}") from exc
        if address < 0 or not isinstance(value, dict):
            raise BinSyncCandidateError(f"BinSync {kind} table has an invalid entry: {path}:{key}")
        if _toml_address(value.get("addr"), path=path, field="addr") != address:
            raise BinSyncCandidateError(f"BinSync {kind} address does not match its table key: {path}:{key}")
        if kind == "comment":
            allowed = {"last_change", "addr", "func_addr", "comment", "decompiled"}
            if set(value) - allowed:
                raise BinSyncCandidateError(f"BinSync comment entry has unexpected fields: {path}:{key}")
            _toml_address(value.get("func_addr"), path=path, field="func_addr")
            if not isinstance(value.get("comment"), str) or not isinstance(value.get("decompiled"), bool):
                raise BinSyncCandidateError(f"BinSync comment entry has invalid content: {path}:{key}")
        elif kind == "global":
            allowed = {"last_change", "addr", "name", "type", "size"}
            if set(value) - allowed or not isinstance(value.get("name"), str):
                raise BinSyncCandidateError(f"BinSync global entry has unexpected fields: {path}:{key}")
            _toml_address(value.get("size"), path=path, field="size")


def _validate_binsync_tree_blob(ref: str, path: str, payload: bytes) -> None:
    if path == ".gitignore":
        if payload != b".git/*\n":
            raise BinSyncCandidateError(f"BinSync tree has a noncanonical .gitignore on {ref}")
        return
    if path == "binary_hash":
        if not MD5_RE.fullmatch(payload.decode("ascii", errors="ignore")):
            raise BinSyncCandidateError(f"BinSync tree has an invalid binary_hash on {ref}")
        return
    if ref == ROOT_REF:
        raise BinSyncCandidateError(f"BinSync root tree contains an unexpected file: {path}")

    function_match = FUNCTION_TOML_RE.fullmatch(path)
    if path not in USER_REQUIRED_TREE_PATHS and not function_match and not STRUCT_TOML_RE.fullmatch(path):
        raise BinSyncCandidateError(f"BinSync commit tree violates the publication allowlist for {ref}: {path}")

    document = _load_binsync_toml(payload, path)
    if path == "metadata.toml":
        if set(document) != {"user", "version"} or not all(isinstance(document[key], str) for key in document):
            raise BinSyncCandidateError("BinSync metadata TOML is invalid")
        if document["user"] != ref.removeprefix(REF_PREFIX) or not document["version"]:
            raise BinSyncCandidateError("BinSync metadata does not match its publication ref")
        return
    if function_match:
        allowed = {"last_change", "addr", "size", "name", "type", "header", "stack_vars"}
        address = int(function_match.group(1), 16)
        if set(document) - allowed or _toml_address(document.get("addr"), path=path, field="addr") != address:
            raise BinSyncCandidateError(f"BinSync function TOML does not match its path: {path}")
        _toml_address(document.get("size"), path=path, field="size")
        if not isinstance(document.get("name"), str):
            raise BinSyncCandidateError(f"BinSync function TOML has no canonical name: {path}")
        for field in ("header", "stack_vars"):
            if field in document and document[field] is not None and not isinstance(document[field], dict):
                raise BinSyncCandidateError(f"BinSync function TOML has invalid {field}: {path}")
        return
    if STRUCT_TOML_RE.fullmatch(path):
        if not document:
            raise BinSyncCandidateError(f"BinSync struct TOML is empty: {path}")
        return
    if path == "comments.toml":
        _validate_address_table(document, path=path, kind="comment")
    elif path == "global_vars.toml":
        _validate_address_table(document, path=path, kind="global")
    elif path not in USER_REQUIRED_TREE_PATHS:
        raise BinSyncCandidateError(f"BinSync tree contains an unexpected TOML file: {path}")


def _commit_tree_blobs(repo: Path, commit: str) -> dict[str, bytes]:
    object_records: list[tuple[str, str]] = []
    for raw_record in _git_bytes(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if not raw_record:
            continue
        try:
            metadata, raw_path = raw_record.split(b"\t", 1)
            mode, object_type, object_sha = metadata.decode("ascii").split(" ")
            path = normalized_relative_path(raw_path.decode("utf-8"))
        except (UnicodeError, ValueError, ReleaseWorkflowError) as exc:
            raise BinSyncCandidateError(f"malformed BinSync tree entry for {commit}") from exc
        if mode != "100644" or object_type != "blob" or not SHA_RE.fullmatch(object_sha):
            raise BinSyncCandidateError(f"BinSync tree contains a non-regular blob: {path}")
        object_records.append((path, object_sha.lower()))

    requests = b"".join(f"{object_sha}\n".encode("ascii") for _path, object_sha in object_records)
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "--batch"],
            input=requests,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise BinSyncCandidateError(f"unable to read BinSync tree blobs: {exc}") from exc
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise BinSyncCandidateError(detail or "unable to read BinSync tree blobs")
    cursor = 0
    blobs: dict[str, bytes] = {}
    for path, expected_object_sha in object_records:
        header_end = result.stdout.find(b"\n", cursor)
        if header_end < 0:
            raise BinSyncCandidateError(f"BinSync tree blob response is truncated: {path}")
        try:
            header = result.stdout[cursor:header_end].decode("ascii").split()
        except UnicodeError as exc:
            raise BinSyncCandidateError(f"BinSync tree blob response is invalid: {path}") from exc
        if len(header) != 3 or header[0].lower() != expected_object_sha or header[1] != "blob":
            raise BinSyncCandidateError(f"BinSync tree blob response does not match: {path}")
        try:
            size = int(header[2])
        except ValueError as exc:
            raise BinSyncCandidateError(f"BinSync tree blob size is invalid: {path}") from exc
        start = header_end + 1
        end = start + size
        if end >= len(result.stdout) or result.stdout[end : end + 1] != b"\n":
            raise BinSyncCandidateError(f"BinSync tree blob response is truncated: {path}")
        if path in blobs:
            raise BinSyncCandidateError(f"BinSync tree contains a duplicate path: {path}")
        blobs[path] = result.stdout[start:end]
        cursor = end + 1
    if cursor != len(result.stdout):
        raise BinSyncCandidateError("BinSync tree blob response contains trailing data")
    return blobs


def _commit_tree_inventory(repo: Path, commit: str, ref: str) -> tuple[str, list[dict], str]:
    tree_sha = _git_text(repo, "rev-parse", f"{commit}^{{tree}}").lower()
    if not SHA_RE.fullmatch(tree_sha):
        raise BinSyncCandidateError(f"invalid BinSync tree SHA for {ref}")
    records = []
    for path, payload in _commit_tree_blobs(repo, commit).items():
        _validate_binsync_tree_blob(ref, path, payload)
        records.append({"path": path, "size": len(payload), "sha256": _plain_sha256(payload)})
    actual = {item["path"] for item in records}
    if ref == ROOT_REF and actual != ROOT_TREE_PATHS:
        raise BinSyncCandidateError(
            f"BinSync commit tree violates the publication allowlist for {ref}: "
            f"missing={sorted(ROOT_TREE_PATHS - actual)!r}; unexpected={sorted(actual - ROOT_TREE_PATHS)!r}"
        )
    if ref != ROOT_REF:
        missing = USER_REQUIRED_TREE_PATHS - actual
        unexpected = {
            path
            for path in actual - USER_REQUIRED_TREE_PATHS
            if not FUNCTION_TOML_RE.fullmatch(path) and not STRUCT_TOML_RE.fullmatch(path)
        }
        if missing or unexpected:
            raise BinSyncCandidateError(
                f"BinSync commit tree violates the publication allowlist for {ref}: "
                f"missing={sorted(missing)!r}; unexpected={sorted(unexpected)!r}"
            )
    return tree_sha, records, _digest("binsync-commit-tree-inventory:v1", records)


def _commit_closure_evidence(repo: Path, *, base: str, candidate: str, ref: str) -> list[dict]:
    if base == candidate:
        return []
    commits = [value for value in _git_text(repo, "rev-list", "--reverse", candidate, f"^{base}").splitlines() if value]
    previous = base
    evidence = []
    for commit in commits:
        if not SHA_RE.fullmatch(commit):
            raise BinSyncCandidateError(f"BinSync commit closure contains an invalid commit on {ref}")
        parent_line = _git_text(repo, "rev-list", "--parents", "-n", "1", commit).split()
        if parent_line != [commit, previous]:
            raise BinSyncCandidateError(f"BinSync commit closure is not a linear exact transition on {ref}")
        tree_sha, tree_files, tree_inventory_sha256 = _commit_tree_inventory(repo, commit, ref)
        evidence.append(
            {
                "commit": commit,
                "tree_sha": tree_sha,
                "tree_files": tree_files,
                "tree_inventory_sha256": tree_inventory_sha256,
            }
        )
        previous = commit
    if previous != candidate:
        raise BinSyncCandidateError(f"BinSync commit closure does not reach the candidate tip on {ref}")
    return evidence


def _lowering_entry_sort_key(entry: dict) -> tuple:
    return (
        entry["artifact_path"],
        entry["category"],
        entry["symbol"],
        entry["source_rva"],
        entry["lifted_address"],
        entry["tree_path"],
    )


def _lowering_tree_indexes(blobs: dict[str, bytes]) -> tuple[dict[int, str], set[int]]:
    function_paths: dict[int, str] = {}
    for path in blobs:
        match = FUNCTION_TOML_RE.fullmatch(path)
        if not match:
            continue
        address = int(match.group(1), 16)
        if address in function_paths:
            raise BinSyncCandidateError(f"BinSync tree has duplicate function address paths: {address:#x}")
        function_paths[address] = path
    global_document = _load_binsync_toml(blobs.get("global_vars.toml", b""), "global_vars.toml")
    global_addresses = set()
    for key in global_document:
        try:
            global_addresses.add(int(key, 0))
        except (TypeError, ValueError) as exc:
            raise BinSyncCandidateError(f"BinSync global table has an invalid address key: {key}") from exc
    return function_paths, global_addresses


def _build_lowering_evidence(
    *,
    repo: Path,
    commit: str,
    binary_path: Path,
    projection_entries: list[dict],
) -> dict:
    try:
        lift_bias = first_segment_lift_bias(binary_path)
    except (BinSyncProjectionError, OSError) as exc:
        raise BinSyncCandidateError(f"unable to derive BinSync lift bias: {exc}") from exc
    blobs = _commit_tree_blobs(repo, commit)
    function_paths, global_addresses = _lowering_tree_indexes(blobs)
    entries = []
    for source in projection_entries:
        lifted_address = source["source_rva"] - lift_bias
        if lifted_address < 0:
            raise BinSyncCandidateError(f"projected source RVA is below the first segment: {source['artifact_path']}")
        if source["category"] in FUNCTION_CATEGORIES:
            tree_path = function_paths.get(lifted_address)
            if tree_path is None:
                raise BinSyncCandidateError(
                    f"projected function address is missing from BinSync tree: {source['artifact_path']}"
                )
        else:
            if lifted_address not in global_addresses:
                raise BinSyncCandidateError(
                    f"projected global address is missing from BinSync tree: {source['artifact_path']}"
                )
            tree_path = "global_vars.toml"
        entries.append(
            {
                "artifact_path": source["artifact_path"],
                "artifact_sha256": source["artifact_sha256"],
                "category": source["category"],
                "lifted_address": lifted_address,
                "source_rva": source["source_rva"],
                "symbol": source["symbol"],
                "tree_path": tree_path,
            }
        )
    entries.sort(key=_lowering_entry_sort_key)
    unsigned = {
        "schema_version": LOWERING_SCHEMA_VERSION,
        "lift_bias": lift_bias,
        "entries": entries,
    }
    return {**unsigned, "digest": _digest("binsync-lowering-evidence:v1", unsigned)}


def _validate_lowering_evidence(evidence: object) -> dict:
    if not isinstance(evidence, dict):
        raise BinSyncCandidateError("BinSync lowering evidence is invalid")
    _require_exact_keys(evidence, {"schema_version", "lift_bias", "entries", "digest"}, "lowering evidence")
    if evidence["schema_version"] != LOWERING_SCHEMA_VERSION:
        raise BinSyncCandidateError("BinSync lowering evidence schema is invalid")
    lift_bias = evidence["lift_bias"]
    if not isinstance(lift_bias, int) or isinstance(lift_bias, bool) or lift_bias < 0:
        raise BinSyncCandidateError("BinSync lowering evidence lift bias is invalid")
    entries = evidence["entries"]
    if not isinstance(entries, list):
        raise BinSyncCandidateError("BinSync lowering evidence entries must be a list")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise BinSyncCandidateError("BinSync lowering evidence entry is invalid")
        _require_exact_keys(entry, LOWERING_ENTRY_FIELDS, "lowering evidence entry")
        for field in ("artifact_path", "artifact_sha256", "category", "symbol", "tree_path"):
            _require_string(entry[field], f"lowering evidence {field}")
        try:
            normalized_relative_path(entry["artifact_path"])
        except ReleaseWorkflowError as exc:
            raise BinSyncCandidateError(f"BinSync lowering evidence artifact path is invalid: {exc}") from exc
        if not DIGEST_RE.fullmatch(entry["artifact_sha256"]):
            raise BinSyncCandidateError("BinSync lowering evidence artifact digest is invalid")
        if entry["category"] not in FUNCTION_CATEGORIES | GLOBAL_CATEGORIES:
            raise BinSyncCandidateError("BinSync lowering evidence category is invalid")
        for field in ("source_rva", "lifted_address"):
            if not isinstance(entry[field], int) or isinstance(entry[field], bool) or entry[field] < 0:
                raise BinSyncCandidateError(f"BinSync lowering evidence {field} is invalid")
        if entry["source_rva"] - entry["lifted_address"] != lift_bias:
            raise BinSyncCandidateError("BinSync lowering evidence address relation is invalid")
        if entry["category"] in FUNCTION_CATEGORIES:
            match = FUNCTION_TOML_RE.fullmatch(entry["tree_path"])
            if not match or int(match.group(1), 16) != entry["lifted_address"]:
                raise BinSyncCandidateError("BinSync lowering evidence function path is invalid")
        elif entry["tree_path"] != "global_vars.toml":
            raise BinSyncCandidateError("BinSync lowering evidence global path is invalid")
        key = _lowering_entry_sort_key(entry)
        if key in seen:
            raise BinSyncCandidateError("BinSync lowering evidence contains a duplicate entry")
        seen.add(key)
    if entries != sorted(entries, key=_lowering_entry_sort_key):
        raise BinSyncCandidateError("BinSync lowering evidence entries are not canonical")
    unsigned = {"schema_version": evidence["schema_version"], "lift_bias": lift_bias, "entries": entries}
    if evidence["digest"] != _digest("binsync-lowering-evidence:v1", unsigned):
        raise BinSyncCandidateError("BinSync lowering evidence digest mismatch")
    return evidence


def _verify_lowering_tree(repo: Path, commit: str, evidence: dict) -> None:
    blobs = _commit_tree_blobs(repo, commit)
    function_paths, global_addresses = _lowering_tree_indexes(blobs)
    for entry in evidence["entries"]:
        if entry["category"] in FUNCTION_CATEGORIES:
            if function_paths.get(entry["lifted_address"]) != entry["tree_path"]:
                raise BinSyncCandidateError("BinSync lowering evidence function tree mismatch")
        elif entry["lifted_address"] not in global_addresses:
            raise BinSyncCandidateError("BinSync lowering evidence global tree mismatch")


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
        if len(_git_text(verification_repo, "rev-list", "--parents", "-n", "1", root_commit).split()) != 1:
            raise BinSyncCandidateError("BinSync root ref must point to a parentless immutable commit")
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
            closure_base = (
                candidate_commit if item["ref"] == ROOT_REF and expected is None else (expected or root_commit)
            )
            if (
                _commit_closure_evidence(
                    verification_repo,
                    base=closure_base,
                    candidate=candidate_commit,
                    ref=item["ref"],
                )
                != item["new_commits"]
            ):
                raise BinSyncCandidateError(f"BinSync commit closure evidence mismatch for {item['ref']}")
        user_item = next(item for item in refs if item["ref"] != ROOT_REF)
        _verify_lowering_tree(
            verification_repo,
            user_item["candidate_commit"],
            repository["lowering_evidence"],
        )


def _sdk_gitlink(repo_root: Path, source_sha: str) -> str:
    fields = _git_text(repo_root, "ls-tree", source_sha, "--", "hl2sdk_cs2").split()
    if len(fields) < 3 or fields[0] != "160000" or fields[1] != "commit" or not SHA_RE.fullmatch(fields[2]):
        raise BinSyncCandidateError("source commit does not bind the hl2sdk_cs2 gitlink")
    return fields[2]


def _source_blob(repo_root: Path, source_sha: str, path: str) -> bytes:
    normalized_relative_path(path)
    return _git_bytes(repo_root, "cat-file", "blob", f"{source_sha}:{path}")


def _build_source_projection(
    *,
    repo_root: Path,
    source_sha: str,
    game_version: str,
    repositories: list[dict],
    artifact_inventory,
) -> dict:
    artifact_paths = {item.path for item in artifact_inventory.files}
    try:
        artifact_blobs = load_game_artifact_git_blobs(
            repo_root=repo_root,
            game_version=game_version,
            git_revision=source_sha,
        )
    except ArtifactContractError as exc:
        raise BinSyncCandidateError(f"unable to load BinSync source projection blobs: {exc}") from exc
    if set(artifact_blobs) != artifact_paths:
        raise BinSyncCandidateError("BinSync source projection blob inventory mismatch")

    def read_artifact(path: str) -> bytes | None:
        return artifact_blobs.get(path)

    targets = [
        {
            "module": repository["binary"]["module"],
            "platform": repository["binary"]["platform"],
            "repository_id": repository["repository_id"],
        }
        for repository in repositories
    ]
    try:
        return build_source_projection(
            game_version=game_version,
            config_payload=_source_blob(repo_root, source_sha, f"configs/{game_version}.yaml"),
            targets=targets,
            read_artifact=read_artifact,
        )
    except (BinSyncProjectionError, ReleaseWorkflowError) as exc:
        raise BinSyncCandidateError(f"unable to build BinSync source projection: {exc}") from exc


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
    root_commit = _git_text(local_repo, "rev-parse", ROOT_REF).lower()
    if len(_git_text(local_repo, "rev-list", "--parents", "-n", "1", root_commit).split()) != 1:
        raise BinSyncCandidateError("BinSync root ref must point to a parentless immutable commit")
    ref_records = []
    for ref in refs:
        _validate_ref(ref)
        candidate_commit = _git_text(local_repo, "rev-parse", ref).lower()
        if not SHA_RE.fullmatch(candidate_commit):
            raise BinSyncCandidateError(f"invalid local candidate commit for {ref}")
        expected = remote_heads.get(ref)
        tree_sha, tree_files, tree_inventory_sha256 = _commit_tree_inventory(local_repo, candidate_commit, ref)
        closure_base = candidate_commit if ref == ROOT_REF and expected is None else (expected or root_commit)
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
                "new_commits": _commit_closure_evidence(
                    local_repo,
                    base=closure_base,
                    candidate=candidate_commit,
                    ref=ref,
                ),
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
    return repository


def _bind_repository_lowering(
    *,
    repo_root: Path,
    game_version: str,
    repository: dict,
    source_projection: dict,
    candidate_root: Path,
) -> None:
    binary_name = PurePosixPath(repository["binary"]["path"]).name
    binary_path = repo_root / "bin" / game_version / repository["binary"]["module"] / binary_name
    local_repo = binary_path.parent / f"{binary_name}.bsproj"
    user_item = next(item for item in repository["refs"] if item["ref"] != ROOT_REF)
    projection_entries = [
        entry for entry in source_projection["entries"] if entry["repository_id"] == repository["repository_id"]
    ]
    repository["lowering_evidence"] = _build_lowering_evidence(
        repo=local_repo,
        commit=user_item["candidate_commit"],
        binary_path=binary_path,
        projection_entries=projection_entries,
    )
    _verify_bundle(candidate_root / PurePosixPath(repository["bundle"]["path"]), repository)


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
            git_revision=source_sha,
        )
    except (SnapshotConfigError, ArtifactContractError) as exc:
        raise BinSyncCandidateError(f"unable to bind source-owned artifact identity: {exc}") from exc
    if contract.config_sha256 != preparation.get("config_sha256"):
        raise BinSyncCandidateError("release preparation config identity drifted")
    if artifact_inventory.inventory_sha256 != preparation.get("expected_artifact_inventory_sha256"):
        raise BinSyncCandidateError("release preparation artifact inventory identity drifted")
    if _sdk_gitlink(repo_root, source_sha) != preparation.get("sdk_gitlink_sha"):
        raise BinSyncCandidateError("release preparation SDK identity drifted")
    try:
        binary_lock = load_binary_lock_from_revision(
            repo_root=repo_root,
            revision=source_sha,
            game_version=game_version,
            download_payload=_source_blob(repo_root, source_sha, "download.yaml"),
            binary_targets=contract.binary_targets,
        )
    except BinaryLockError as exc:
        raise BinSyncCandidateError(f"unable to bind source binary lock: {exc}") from exc
    locked_binaries = binary_lock.document["binaries"]
    if binary_lock.sha256 != preparation.get("binary_lock_sha256") or locked_binaries != preparation.get(
        "binary_inventory"
    ):
        raise BinSyncCandidateError("release preparation does not match the source binary lock")

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
    source_projection = _build_source_projection(
        repo_root=repo_root,
        source_sha=source_sha,
        game_version=game_version,
        repositories=repositories,
        artifact_inventory=artifact_inventory,
    )
    for repository in repositories:
        _bind_repository_lowering(
            repo_root=repo_root,
            game_version=game_version,
            repository=repository,
            source_projection=source_projection,
            candidate_root=candidate_root,
        )

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
        "binary_lock_sha256": binary_lock.sha256,
        "binary_inventory_sha256": preparation["binary_inventory_sha256"],
        "ida_runtime_identity": ida_runtime_identity,
        "source_projection": source_projection,
        "repositories": repositories,
        "checksum_file": {
            "path": CHECKSUMS_NAME,
            "size": len(checksums_payload),
            "sha256": sha256_bytes(checksums_payload),
        },
    }
    document["publication_digest"] = _digest("binsync-publication-candidate:v4", document)
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
    expected = {
        "repository_id",
        "owner",
        "name",
        "remote_url",
        "binary",
        "lowering_evidence",
        "refs",
        "bundle",
    }
    _require_exact_keys(repository, expected, "repository")
    owner = _require_string(repository["owner"], "repository owner")
    name = _require_string(repository["name"], "repository name")
    repository_id = _canonical_repository_id(owner, name)
    if owner != GITHUB_OWNER or repository["repository_id"] != repository_id:
        raise BinSyncCandidateError(f"BinSync repository is outside the allowlist: {owner}/{name}")
    if repository["remote_url"] != _canonical_remote_url(owner, name):
        raise BinSyncCandidateError(f"BinSync repository remote is not canonical: {repository_id}")
    _validate_binary(repository["binary"])
    _validate_lowering_evidence(repository["lowering_evidence"])

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
                "new_commits",
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
        if not isinstance(item["new_commits"], list):
            raise BinSyncCandidateError(f"BinSync ref commit closure evidence is invalid: {ref}")
        for commit in item["new_commits"]:
            _require_exact_keys(
                commit,
                {"commit", "tree_sha", "tree_files", "tree_inventory_sha256"},
                "repository ref commit closure",
            )
            if (
                not SHA_RE.fullmatch(str(commit["commit"]))
                or not SHA_RE.fullmatch(str(commit["tree_sha"]))
                or not isinstance(commit["tree_files"], list)
                or not DIGEST_RE.fullmatch(str(commit["tree_inventory_sha256"]))
                or commit["tree_inventory_sha256"] != _digest("binsync-commit-tree-inventory:v1", commit["tree_files"])
            ):
                raise BinSyncCandidateError(f"BinSync ref commit closure evidence is invalid: {ref}")
        if expected_head is not None and (not isinstance(expected_head, str) or not SHA_RE.fullmatch(expected_head)):
            raise BinSyncCandidateError(f"expected remote head is invalid for {ref}")
        if not isinstance(item["candidate_commit"], str) or not SHA_RE.fullmatch(item["candidate_commit"]):
            raise BinSyncCandidateError(f"candidate commit is invalid for {ref}")
        if item["fast_forward"] is not True or item["relationship"] not in {"create", "unchanged", "fast-forward"}:
            raise BinSyncCandidateError(f"fast-forward declaration is invalid for {ref}")
        if item["relationship"] == "unchanged" and item["new_commits"]:
            raise BinSyncCandidateError(f"unchanged BinSync ref declares new commits: {ref}")
        if item["new_commits"] and item["new_commits"][-1]["commit"] != item["candidate_commit"]:
            raise BinSyncCandidateError(f"BinSync ref commit closure does not end at the candidate: {ref}")
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
        "binary_lock_sha256",
        "binary_inventory_sha256",
        "ida_runtime_identity",
        "source_projection",
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
    for field in (
        "config_sha256",
        "download_sha256",
        "artifact_inventory_sha256",
        "binary_lock_sha256",
        "binary_inventory_sha256",
    ):
        if not isinstance(document[field], str) or not DIGEST_RE.fullmatch(document[field]):
            raise BinSyncCandidateError(f"BinSync candidate {field} is invalid")
    if not isinstance(document["sdk_gitlink_sha"], str) or not SHA_RE.fullmatch(document["sdk_gitlink_sha"]):
        raise BinSyncCandidateError("BinSync candidate SDK gitlink is invalid")
    try:
        projection = validate_source_projection(document["source_projection"])
    except BinSyncProjectionError as exc:
        raise BinSyncCandidateError(str(exc)) from exc

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
    projection_targets = {
        item["repository_id"]: (item["binary"]["module"], item["binary"]["platform"]) for item in repositories
    }
    projection_prefix = f"bin_artifacts/{document['game_version']}/"
    for entry in projection["entries"]:
        if projection_targets.get(entry["repository_id"]) != (entry["module"], entry["platform"]):
            raise BinSyncCandidateError("BinSync source projection repository target mismatch")
        if not entry["artifact_path"].startswith(projection_prefix):
            raise BinSyncCandidateError("BinSync source projection GAMEVER mismatch")
    projection_fields = ("artifact_path", "artifact_sha256", "category", "source_rva", "symbol")
    for repository in repositories:
        source_entries = [
            entry for entry in projection["entries"] if entry["repository_id"] == repository["repository_id"]
        ]
        lowering_entries = repository["lowering_evidence"]["entries"]
        if len(source_entries) != len(lowering_entries):
            raise BinSyncCandidateError("BinSync lowering evidence does not cover the source projection")
        for source, lowering in zip(source_entries, lowering_entries, strict=True):
            if any(source[field] != lowering[field] for field in projection_fields):
                raise BinSyncCandidateError("BinSync lowering evidence does not match the source projection")

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
    if publication_digest != _digest("binsync-publication-candidate:v4", unsigned):
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
            git_revision=source_sha,
        )
    except (SnapshotConfigError, ArtifactContractError) as exc:
        raise BinSyncCandidateError(f"hosted source artifact verification failed: {exc}") from exc
    if contract.config_sha256 != document["config_sha256"]:
        raise BinSyncCandidateError("hosted verifier config identity mismatch")
    if artifact_inventory.inventory_sha256 != document["artifact_inventory_sha256"]:
        raise BinSyncCandidateError("hosted verifier artifact inventory mismatch")
    download_payload = _source_blob(repo_root, source_sha, "download.yaml")
    if _plain_sha256(download_payload) != document["download_sha256"]:
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
    try:
        binary_lock = load_binary_lock_from_revision(
            repo_root=repo_root,
            revision=source_sha,
            game_version=game_version,
            download_payload=download_payload,
            binary_targets=contract.binary_targets,
        )
    except BinaryLockError as exc:
        raise BinSyncCandidateError(f"hosted source binary lock verification failed: {exc}") from exc
    locked_binaries = binary_lock.document["binaries"]
    if binary_lock.sha256 != document["binary_lock_sha256"] or locked_binaries != _nested_binary_inventory(
        repositories
    ):
        raise BinSyncCandidateError("hosted verifier source binary lock mismatch")
    for repository in repositories:
        expected_name = f"CS2_VibeSignatures_binsync_{game_version}_{PurePosixPath(repository['binary']['path']).name}"
        if repository["name"] != expected_name:
            raise BinSyncCandidateError(f"hosted verifier repository allowlist mismatch: {repository['name']}")
    expected_projection = _build_source_projection(
        repo_root=repo_root,
        source_sha=source_sha,
        game_version=game_version,
        repositories=repositories,
        artifact_inventory=artifact_inventory,
    )
    if expected_projection != document["source_projection"]:
        raise BinSyncCandidateError("hosted verifier source projection mismatch")


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

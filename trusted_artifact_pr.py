#!/usr/bin/env python3
"""Plan and verify trusted, isolated source-artifact PR rebuilds."""

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

import yaml

from artifact_diagnostics import (
    DiagnosticContext,
    append_failure_diagnostics,
    collect_failure_bundle,
    external_staging,
    read_artifact_bytes,
    safe_component,
)
from binary_lock import BinaryLockError, download_identity, load_binary_lock_from_revision
from bin_artifact_contract import (
    ArtifactContractError,
    _category_for,
    _category_map,
    build_game_artifact_inventory,
)
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotConfigError
from gamesymbol_snapshot_lib.model import ChangedPath
from gamesymbol_snapshot_lib.paths import is_reparse_point, validate_snapshot_key
from gamesymbol_snapshot_lib.pr_validation import build_invalidation_plan, required_source_index_sides
from gamever_baseline import gamever_order_key, select_prior_gamever
from ida_analyze_util import SymbolArtifactError, canonical_symbol_yaml_bytes
from trusted_pr_context import (
    BASE_INHERITED_SELECTED_STRATEGY,
    EXECUTION_STRATEGIES,
    FRESH_FULL_STRATEGY,
    load_trusted_pr_context,
    validate_trusted_pr_context,
)


PLAN_SCHEMA_VERSION = 4
PREPARATION_SCHEMA_VERSION = 3
SELECTED_EXECUTION_SCHEMA_VERSION = 1
SELECTED_EXECUTION_DIGEST_DOMAIN = "source2-selected-execution:v1"
SELECTED_MANIFEST_DIGEST_LABEL = "selected-execution-manifest"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CONFIG_RE = re.compile(r"^configs/([^/]+)\.yaml$")
ARTIFACT_RE = re.compile(r"^bin_artifacts/([^/]+)/(.+)$")
BINARY_LOCK_RE = re.compile(r"^binary_locks/([^/]+)\.json$")
BINARY_LOCK_METADATA_PATHS = frozenset({"binary_locks/README.md"})
SOURCE_PREFIXES = (
    ".claude/agents/",
    ".claude/skills/",
    ".opencode/agents/",
    ".opencode/skills/",
    "ida_preprocessor_scripts/",
)
SHARED_ANALYSIS_PATHS = frozenset(
    {
        "analysis_output_contract.py",
        "bin_artifact_contract.py",
        "binary_lock.py",
        "ida_analyze_bin.py",
        "ida_analyze_util.py",
        "gamever_baseline.py",
        "trusted_artifact_pr.py",
        "gamesymbol_snapshot_lib/config.py",
        "gamesymbol_snapshot_lib/model.py",
        "gamesymbol_snapshot_lib/paths.py",
        "gamesymbol_snapshot_lib/pr_validation.py",
    }
)
SHARED_ANALYSIS_PREFIXES = ("gamesymbol_snapshot_lib/",)


class TrustedArtifactPrError(RuntimeError):
    """Trusted source-artifact planning or isolated verification failed closed."""


def _is_shared_analysis_runtime_path(path: str) -> bool:
    """Return whether a Git path can change analyzer-wide artifact semantics."""
    return (
        path in SHARED_ANALYSIS_PATHS
        or ("/" not in path and path.endswith(".py"))
        or (path.startswith(SHARED_ANALYSIS_PREFIXES) and path.endswith(".py"))
    )


@dataclass(frozen=True)
class GitTreeEntry:
    mode: str
    object_type: str
    object_sha: str
    path: str


class GitTreeRepository:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

    def run(self, *arguments: str) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise TrustedArtifactPrError(f"git {' '.join(arguments)} failed: {message}")
        return result.stdout

    def resolve_commit(self, revision: str) -> str:
        value = self.run("rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip().lower()
        if not SHA_RE.fullmatch(value):
            raise TrustedArtifactPrError(f"Git revision did not resolve to a full commit SHA: {revision!r}")
        return value

    def tree_sha(self, revision: str) -> str:
        value = self.run("rev-parse", "--verify", f"{revision}^{{tree}}").decode().strip().lower()
        if not SHA_RE.fullmatch(value):
            raise TrustedArtifactPrError(f"Git revision did not resolve to a full tree SHA: {revision!r}")
        return value

    def entries(self, revision: str, prefix: str | None = None) -> tuple[GitTreeEntry, ...]:
        arguments = ["ls-tree", "-r", "-z", "--full-tree", revision]
        if prefix:
            arguments.extend(["--", prefix])
        entries = []
        for record in self.run(*arguments).split(b"\0"):
            if not record:
                continue
            try:
                metadata, raw_path = record.split(b"\t", 1)
                mode, object_type, object_sha = metadata.decode("ascii").split(" ")
                path = raw_path.decode("utf-8")
            except (UnicodeDecodeError, ValueError) as exc:
                raise TrustedArtifactPrError("Git returned a malformed or non-UTF-8 tree entry") from exc
            entries.append(GitTreeEntry(mode, object_type, object_sha, path.replace("\\", "/")))
        return tuple(entries)

    def read(self, revision: str, path: str) -> bytes:
        return self.run("show", f"{revision}:{path}")

    def read_blobs(self, entries: tuple[GitTreeEntry, ...] | list[GitTreeEntry]) -> dict[str, bytes]:
        """Read an exact Git blob inventory through one fail-closed batch process."""
        if not entries:
            return {}
        for entry in entries:
            if entry.object_type != "blob" or not SHA_RE.fullmatch(entry.object_sha):
                raise TrustedArtifactPrError(f"cannot batch-read non-blob Git entry: {entry.path}")
        request = b"".join(f"{entry.object_sha}\n".encode("ascii") for entry in entries)
        result = subprocess.run(
            ["git", "-C", str(self.root), "cat-file", "--batch"],
            input=request,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise TrustedArtifactPrError(f"git cat-file --batch failed: {message}")
        output = result.stdout
        offset = 0
        payloads = {}
        for entry in entries:
            header_end = output.find(b"\n", offset)
            if header_end < 0:
                raise TrustedArtifactPrError("git cat-file --batch returned a truncated header")
            try:
                object_sha, object_type, raw_size = output[offset:header_end].decode("ascii").split(" ")
                size = int(raw_size)
            except (UnicodeDecodeError, ValueError) as exc:
                raise TrustedArtifactPrError("git cat-file --batch returned a malformed header") from exc
            if object_sha != entry.object_sha or object_type != "blob" or size < 0:
                raise TrustedArtifactPrError(f"git cat-file --batch identity drifted for {entry.path}")
            payload_start = header_end + 1
            payload_end = payload_start + size
            if payload_end >= len(output) or output[payload_end : payload_end + 1] != b"\n":
                raise TrustedArtifactPrError(f"git cat-file --batch returned a truncated blob for {entry.path}")
            payloads[entry.path] = output[payload_start:payload_end]
            offset = payload_end + 1
        if offset != len(output):
            raise TrustedArtifactPrError("git cat-file --batch returned unexpected trailing data")
        return payloads

    def changes(self, base_revision: str, merge_revision: str) -> tuple[ChangedPath, ...]:
        fields = self.run("diff", "--name-status", "-M", "-z", base_revision, merge_revision, "--").split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        changes = []
        index = 0
        while index < len(fields):
            try:
                status_token = fields[index].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise TrustedArtifactPrError("Git returned a non-UTF-8 changed path") from exc
            index += 1
            status = status_token[:1]
            path_count = 2 if status in {"R", "C"} else 1
            if status not in {"A", "M", "D", "R", "C"} or index + path_count > len(fields):
                raise TrustedArtifactPrError(f"unsupported or malformed Git change record: {status_token!r}")
            try:
                paths = [field.decode("utf-8") for field in fields[index : index + path_count]]
            except UnicodeDecodeError as exc:
                raise TrustedArtifactPrError("Git returned a non-UTF-8 changed path") from exc
            index += path_count
            if status == "A":
                changes.append(ChangedPath(status, None, paths[0]))
            elif status == "D":
                changes.append(ChangedPath(status, paths[0], None))
            elif status == "M":
                changes.append(ChangedPath(status, paths[0], paths[0]))
            else:
                changes.append(ChangedPath(status, paths[0], paths[1]))
        return tuple(changes)


def _canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def _digest(label: str, value: object) -> str:
    raw = f"source-artifact-{label}:v1\n".encode() + _canonical_json_bytes(value)
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


def _configured_versions(repo: GitTreeRepository, revision: str) -> tuple[str, ...]:
    versions = []
    spellings = {}
    for entry in repo.entries(revision, "configs"):
        match = CONFIG_RE.fullmatch(entry.path)
        if not match:
            continue
        gamever = match.group(1)
        previous = spellings.setdefault(gamever.casefold(), gamever)
        if previous != gamever:
            raise TrustedArtifactPrError(f"configured GAMEVER casefold collision: {previous!r} and {gamever!r}")
        versions.append(gamever)
    return tuple(sorted(versions))


def _validate_repository_tree_namespaces(
    repo: GitTreeRepository, revision: str, configured_versions: tuple[str, ...]
) -> None:
    configured = set(configured_versions)
    unconfigured_artifacts = []
    binary_lock_versions = set()
    invalid_binary_locks = []
    legacy_outputs = []
    for entry in repo.entries(revision):
        path = entry.path
        if path.startswith("bin_artifacts/"):
            match = ARTIFACT_RE.fullmatch(path)
            if not match or match.group(1) not in configured:
                unconfigured_artifacts.append(path)
        if path.startswith("binary_locks/"):
            if path in BINARY_LOCK_METADATA_PATHS:
                if entry.mode != "100644" or entry.object_type != "blob":
                    raise TrustedArtifactPrError(f"binary lock metadata must be a regular Git blob: {path}")
                continue
            match = BINARY_LOCK_RE.fullmatch(path)
            if not match or match.group(1) not in configured:
                invalid_binary_locks.append(path)
            elif entry.mode != "100644" or entry.object_type != "blob":
                raise TrustedArtifactPrError(f"binary lock must be a non-executable regular Git blob: {path}")
            else:
                binary_lock_versions.add(match.group(1))
        if (path.startswith("bin/") and path.lower().endswith(".yaml")) or path.startswith(
            ("gamesymbols/", "gamedata/", "release-manifests/")
        ):
            legacy_outputs.append(path)
    if unconfigured_artifacts:
        raise TrustedArtifactPrError(
            "Git artifacts belong to an unconfigured GAMEVER:\n"
            + "\n".join(f"  {path}" for path in sorted(unconfigured_artifacts))
        )
    if invalid_binary_locks:
        raise TrustedArtifactPrError(
            "binary locks belong to an unconfigured GAMEVER or invalid path:\n"
            + "\n".join(f"  {path}" for path in sorted(invalid_binary_locks))
        )
    missing_binary_locks = sorted(configured - binary_lock_versions)
    if missing_binary_locks:
        raise TrustedArtifactPrError(
            "configured GAMEVER is missing a binary lock:\n"
            + "\n".join(f"  binary_locks/{gamever}.json" for gamever in missing_binary_locks)
        )
    if legacy_outputs:
        raise TrustedArtifactPrError(
            "legacy generated outputs remain in the source-owned Git tree:\n"
            + "\n".join(f"  {path}" for path in sorted(legacy_outputs))
        )


def _load_revision_contract(repo: GitTreeRepository, revision: str, gamever: str, temporary_root: Path):
    raw = repo.read(revision, f"configs/{gamever}.yaml")
    config_path = temporary_root / revision / "configs" / f"{gamever}.yaml"
    _atomic_write(config_path, raw)
    try:
        contract = load_contract(
            config_path,
            gamever,
            temporary_root / revision / "bin",
            artifactdir=temporary_root / revision / "bin_artifacts",
        )
    except SnapshotConfigError as exc:
        raise TrustedArtifactPrError(f"invalid config at {revision}:configs/{gamever}.yaml: {exc}") from exc
    try:
        config_document = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise TrustedArtifactPrError(f"invalid config YAML at {revision}:configs/{gamever}.yaml: {exc}") from exc
    return contract, config_path, config_document


def _load_revision_binary_lock(repo: GitTreeRepository, revision: str, gamever: str, contract):
    try:
        return load_binary_lock_from_revision(
            repo_root=repo.root,
            revision=revision,
            game_version=gamever,
            download_payload=repo.read(revision, "download.yaml"),
            binary_targets=contract.binary_targets,
        )
    except BinaryLockError as exc:
        raise TrustedArtifactPrError(f"invalid binary lock at {revision}:binary_locks/{gamever}.json: {exc}") from exc


def _reject_casefold_collisions(paths: list[str], *, label: str) -> None:
    seen = {}
    for path in sorted(paths):
        previous = seen.setdefault(path.casefold(), path)
        if previous != path:
            raise TrustedArtifactPrError(f"{label} casefold collision: {previous!r} and {path!r}")


def _reject_non_maintained_version_edits(changes: tuple[ChangedPath, ...], maintained_versions: set[str]) -> None:
    """Fail closed on config/artifact edits that target any non-maintained GAMEVER.

    Only the maintained (latest) GAMEVER accepts gamesymbol definition or artifact edits;
    historical versions are immutable and require a new GAMEVER bump instead (#847).
    """
    stale_edits: dict[str, set[str]] = {}
    for change in changes:
        for path in (change.old_path, change.new_path):
            if not path:
                continue
            match = CONFIG_RE.fullmatch(path) or ARTIFACT_RE.fullmatch(path)
            if match and match.group(1) not in maintained_versions:
                stale_edits.setdefault(match.group(1), set()).add(path)
    if stale_edits:
        details = "\n".join(
            f"  {gamever}: {path}" for gamever in sorted(stale_edits) for path in sorted(stale_edits[gamever])
        )
        raise TrustedArtifactPrError(
            "changes target configs/bin_artifacts of non-maintained GAMEVER versions; "
            "apply gamesymbol changes to the maintained (latest) GAMEVER or bump a new GAMEVER:\n" + details
        )


def _tree_artifact_inventory(
    repo: GitTreeRepository,
    revision: str,
    gamever: str,
    contract,
    config_path: Path,
    *,
    allow_missing_required: bool,
) -> tuple[dict, dict]:
    prefix = f"bin_artifacts/{gamever}"
    entries = repo.entries(revision, prefix)
    relative_entries = {}
    for entry in entries:
        match = ARTIFACT_RE.fullmatch(entry.path)
        if not match or match.group(1) != gamever:
            raise TrustedArtifactPrError(f"invalid artifact tree path: {entry.path}")
        if entry.mode != "100644" or entry.object_type != "blob":
            raise TrustedArtifactPrError(f"artifact must be a non-executable regular Git blob: {entry.path}")
        try:
            key = validate_snapshot_key(match.group(2))
        except SnapshotConfigError as exc:
            raise TrustedArtifactPrError(str(exc)) from exc
        relative_entries[key] = entry
    _reject_casefold_collisions(list(relative_entries), label=f"{gamever} artifact path")
    actual_paths = set(relative_entries)
    extra = sorted(actual_paths - contract.formal_paths)
    missing = sorted(contract.required_paths - actual_paths)
    if extra:
        raise TrustedArtifactPrError(
            f"extra/stale Git artifacts for {gamever}:\n" + "\n".join(f"  {path}" for path in extra)
        )
    if missing and not allow_missing_required:
        raise TrustedArtifactPrError(
            f"missing required Git artifacts for {gamever}:\n" + "\n".join(f"  {path}" for path in missing)
        )

    categories = _category_map(config_path)
    files = {}
    inventory = []
    raw_by_path = repo.read_blobs(list(relative_entries.values()))
    for key in sorted(relative_entries):
        raw = raw_by_path[f"bin_artifacts/{gamever}/{key}"]
        try:
            payload = yaml.safe_load(raw)
            canonical = canonical_symbol_yaml_bytes(payload, category=_category_for(key, payload, categories))
        except (yaml.YAMLError, SymbolArtifactError, ArtifactContractError) as exc:
            raise TrustedArtifactPrError(f"invalid Source2 artifact {gamever}/{key}: {exc}") from exc
        if raw != canonical:
            raise TrustedArtifactPrError(f"Git artifact is not canonical: bin_artifacts/{gamever}/{key}")
        files[key] = payload
        inventory.append(
            {
                "path": f"bin_artifacts/{gamever}/{key}",
                "size": len(raw),
                "sha256": _sha256(raw),
                "blob_sha": relative_entries[key].object_sha,
            }
        )
    report = {
        "file_count": len(inventory),
        "required_count": len(contract.required_paths),
        "present_optional_count": len(actual_paths - contract.required_paths),
        "missing_required": missing,
        "inventory_sha256": _digest("git-artifact-inventory", inventory),
        "files": inventory,
    }
    return files, report


def _source_inventory(repo: GitTreeRepository, revision: str) -> dict:
    entries = [
        entry
        for entry in repo.entries(revision)
        if entry.object_type == "blob"
        and (_is_shared_analysis_runtime_path(entry.path) or entry.path.startswith(SOURCE_PREFIXES))
    ]
    raw_by_path = repo.read_blobs(entries)
    items = [
        {"path": entry.path, "size": len(raw_by_path[entry.path]), "sha256": _sha256(raw_by_path[entry.path])}
        for entry in entries
    ]
    return {"file_count": len(items), "sha256": _digest("analysis-source-inventory", items)}


def _download_identities(repo: GitTreeRepository, revision: str) -> dict[str, dict]:
    try:
        document = yaml.safe_load(repo.read(revision, "download.yaml"))
    except yaml.YAMLError as exc:
        raise TrustedArtifactPrError(f"invalid download.yaml at {revision}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"downloads"} or not isinstance(document["downloads"], list):
        raise TrustedArtifactPrError(f"download.yaml at {revision} must contain only a downloads list")
    identities = {}
    for item in document["downloads"]:
        if not isinstance(item, dict) or not isinstance(item.get("tag"), str) or not item["tag"]:
            raise TrustedArtifactPrError(f"download.yaml at {revision} has an invalid download entry")
        tag = item["tag"]
        if tag in identities:
            raise TrustedArtifactPrError(f"download.yaml at {revision} has duplicate tag {tag!r}")
        identities[tag] = item
    return identities


def _revision_download_identity(download_payload: bytes, gamever: str) -> dict:
    """Return the normalized DepotDownloader identity for one tag, failing closed."""
    try:
        return download_identity(download_payload, gamever)
    except BinaryLockError as exc:
        raise TrustedArtifactPrError(f"invalid download identity for GAMEVER {gamever}: {exc}") from exc


def _revision_python_sources(repo: GitTreeRepository, revision: str) -> dict[str, str]:
    sources = {}
    for entry in repo.entries(revision, "ida_preprocessor_scripts"):
        if entry.object_type != "blob" or not entry.path.endswith(".py"):
            continue
        try:
            sources[entry.path] = repo.read(revision, entry.path).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TrustedArtifactPrError(f"analysis source is not UTF-8: {revision}:{entry.path}") from exc
    return sources


def _pseudo_snapshot(contract, files: dict) -> dict:
    return {
        "schema_version": 5,
        "analysis_output_contract_version": contract.analysis_output_contract_version,
        "files": files,
    }


def _prerequisite_producer_nodes(contract, node) -> set[str]:
    """Return same-session prerequisite nodes whose side effects a node depends on."""
    result = set()
    for prerequisite in node.prerequisites:
        for other in contract.nodes.values():
            if (
                other.stage_index == node.stage_index
                and other.module_name == node.module_name
                and other.platform == node.platform
                and other.skill_name == prerequisite
            ):
                result.add(other.node_id)
    return result


def _execution_closure(contract, invalidation) -> tuple[set[str], set[str]]:
    """Expand an invalidation into the exact execution closure (fixed point).

    The closure iterates until stable over three expansions:
    - a selected node invalidates every producer group owning any of its outputs;
    - a selected group pulls in all of its alternative nodes and every downstream group;
    - an executed node must actually run its same-session prerequisites, because it
      depends on their in-session side effects even when their artifacts are unchanged.
    """
    selected_groups = {
        contract.producer_group_ids_by_path[path]
        for path in invalidation.paths
        if path in contract.producer_group_ids_by_path
    }
    for node_id in invalidation.node_ids:
        for group_id, group in contract.producer_groups.items():
            if node_id in group.alternative_node_ids:
                selected_groups.add(group_id)
    while True:
        expanded = set(contract.downstream_group_ids(selected_groups))
        selected_nodes = {
            node_id for group_id in expanded for node_id in contract.producer_groups[group_id].alternative_node_ids
        }
        while True:
            changed = False
            prerequisite_nodes = set()
            for node_id in selected_nodes:
                prerequisite_nodes.update(_prerequisite_producer_nodes(contract, contract.nodes[node_id]))
            if not prerequisite_nodes <= selected_nodes:
                selected_nodes |= prerequisite_nodes
                changed = True
            for node_id in selected_nodes:
                for path in contract.nodes[node_id].outputs:
                    group_id = contract.producer_group_ids_by_path.get(path)
                    if group_id is None:
                        continue
                    if group_id not in expanded:
                        expanded.add(group_id)
                        changed = True
                    alternatives = set(contract.producer_groups[group_id].alternative_node_ids)
                    if not alternatives <= selected_nodes:
                        selected_nodes |= alternatives
                        changed = True
            if not changed:
                break
        if expanded == selected_groups:
            return expanded, selected_nodes
        selected_groups = expanded


def _partition_version_execution(
    contract,
    base_files: dict,
    merge_files: dict,
    selected_group_ids: set[str],
    selected_node_ids: set[str],
) -> dict:
    """Partition merge-contract outputs into execution, inheritance, and legal absence.

    Fail closed whenever a byte-level change, a new output, or an optional presence
    change is not covered by a selected producer group: such outputs can neither be
    executed nor honestly inherited from the base tree.
    """
    executed_paths = {path for node_id in selected_node_ids for path in contract.nodes[node_id].outputs}
    inherit_paths = []
    inherited_absent_groups = []
    for group_id in sorted(contract.producer_groups):
        if group_id in selected_group_ids:
            continue
        group = contract.producer_groups[group_id]
        path = group.artifact_path
        if path in executed_paths:
            raise TrustedArtifactPrError(f"execution/inheritance partition collision on a writable output: {path}")
        merge_item = merge_files.get(path)
        if merge_item is not None:
            base_item = base_files.get(path)
            if base_item is None:
                raise TrustedArtifactPrError(f"new formal output was not scheduled for execution: {path}")
            if (
                base_item["blob_sha"] != merge_item["blob_sha"]
                or base_item["size"] != merge_item["size"]
                or base_item["sha256"] != merge_item["sha256"]
            ):
                raise TrustedArtifactPrError(f"changed artifact bytes without a selected producer: {path}")
            inherit_paths.append(
                {
                    "path": path,
                    "blob_sha": base_item["blob_sha"],
                    "size": base_item["size"],
                    "sha256": base_item["sha256"],
                }
            )
        elif path in base_files:
            raise TrustedArtifactPrError(f"optional output presence change was not scheduled for execution: {path}")
        else:
            inherited_absent_groups.append(
                {
                    "group_id": group_id,
                    "artifact_path": path,
                    "required": group.required,
                    "fingerprint": group.fingerprint,
                    "alternative_node_ids": list(group.alternative_node_ids),
                }
            )
    removed_paths = sorted(path for path in base_files if path not in contract.formal_paths)
    covered = {contract.producer_groups[group_id].artifact_path for group_id in selected_group_ids}
    covered.update(item["path"] for item in inherit_paths)
    covered.update(group["artifact_path"] for group in inherited_absent_groups)
    if covered != contract.formal_paths:
        raise TrustedArtifactPrError("execution/inheritance partition does not exactly cover the merge contract")
    return {
        "inherit_paths": inherit_paths,
        "inherited_absent_groups": inherited_absent_groups,
        "removed_paths": removed_paths,
    }


def _select_all_groups(merge_contract) -> tuple[set[str], set[str]]:
    group_ids = set(merge_contract.producer_groups)
    node_ids = {node_id for group in merge_contract.producer_groups.values() for node_id in group.alternative_node_ids}
    return group_ids, node_ids


def _node_document(contract, node_id: str) -> dict:
    node = contract.nodes[node_id]
    return {
        "node_id": node.node_id,
        "stage_index": node.stage_index,
        "module": node.module_name,
        "platform": node.platform,
        "skill": node.skill_name,
        "fingerprint": node.fingerprint,
        "outputs": sorted(node.outputs),
    }


def _change_document(change: ChangedPath) -> dict:
    return {"status": change.status, "old_path": change.old_path, "new_path": change.new_path}


def _gitlink_sha(repo: GitTreeRepository, revision: str, path: str) -> str | None:
    entries = [entry for entry in repo.entries(revision, path) if entry.path == path]
    if not entries:
        return None
    entry = entries[0]
    if entry.mode != "160000" or entry.object_type != "commit" or not SHA_RE.fullmatch(entry.object_sha):
        raise TrustedArtifactPrError(f"expected a Git gitlink at {revision}:{path}")
    return entry.object_sha


def build_trusted_artifact_plan(*, repo_root: str | Path, trusted_context: dict | str | Path) -> dict:
    context = (
        load_trusted_pr_context(trusted_context)
        if isinstance(trusted_context, (str, Path))
        else validate_trusted_pr_context(trusted_context)
    )
    if context["artifact_policy"]["mode"] != "source-owned":
        raise TrustedArtifactPrError("trusted source-artifact planner is not enabled by the base policy")
    repo = GitTreeRepository(repo_root)
    for commit_field, tree_field in (
        ("base_sha", "base_tree_sha"),
        ("head_sha", "head_tree_sha"),
        ("merge_sha", "merge_tree_sha"),
    ):
        commit = repo.resolve_commit(context[commit_field])
        if commit != context[commit_field] or repo.tree_sha(commit) != context[tree_field]:
            raise TrustedArtifactPrError(f"trusted PR context drifted for {commit_field}")

    base_versions = _configured_versions(repo, context["base_sha"])
    merge_versions = _configured_versions(repo, context["merge_sha"])
    maintained_versions = {max(merge_versions, key=gamever_order_key)} if merge_versions else set()
    _validate_repository_tree_namespaces(repo, context["base_sha"], base_versions)
    _validate_repository_tree_namespaces(repo, context["merge_sha"], merge_versions)
    changes = repo.changes(context["base_sha"], context["merge_sha"])
    _reject_non_maintained_version_edits(changes, maintained_versions)
    base_downloads = _download_identities(repo, context["base_sha"])
    merge_downloads = _download_identities(repo, context["merge_sha"])
    base_download_raw = repo.read(context["base_sha"], "download.yaml")
    merge_download_raw = repo.read(context["merge_sha"], "download.yaml")
    needs_base_sources, needs_merge_sources = required_source_index_sides(list(changes))
    base_sources = _revision_python_sources(repo, context["base_sha"]) if needs_base_sources else {}
    merge_sources = _revision_python_sources(repo, context["merge_sha"]) if needs_merge_sources else {}

    version_reports = []
    with tempfile.TemporaryDirectory(prefix="trusted-artifact-plan-") as temporary:
        temporary_root = Path(temporary)
        for gamever in sorted(set(base_versions) | set(merge_versions)):
            base_contract = base_config = None
            base_files = {}
            base_inventory = None
            base_binary_lock = None
            if gamever in base_versions:
                base_contract, base_config, _base_document = _load_revision_contract(
                    repo, context["base_sha"], gamever, temporary_root
                )
                base_binary_lock = _load_revision_binary_lock(repo, context["base_sha"], gamever, base_contract)
                base_files, base_inventory = _tree_artifact_inventory(
                    repo,
                    context["base_sha"],
                    gamever,
                    base_contract,
                    base_config,
                    allow_missing_required=False,
                )

            merge_contract = merge_config = None
            merge_files = {}
            merge_inventory = None
            merge_binary_lock = None
            bootstrap_required = False
            if gamever in merge_versions:
                merge_contract, merge_config, _merge_document = _load_revision_contract(
                    repo, context["merge_sha"], gamever, temporary_root
                )
                merge_binary_lock = _load_revision_binary_lock(repo, context["merge_sha"], gamever, merge_contract)
                is_new = gamever not in base_versions
                merge_files, merge_inventory = _tree_artifact_inventory(
                    repo,
                    context["merge_sha"],
                    gamever,
                    merge_contract,
                    merge_config,
                    allow_missing_required=is_new,
                )
                bootstrap_required = is_new and bool(merge_inventory["missing_required"])

            reasons = []
            selected_group_ids: set[str] = set()
            selected_node_ids: set[str] = set()
            invalidated_paths: set[str] = set()
            partition = {"inherit_paths": [], "inherited_absent_groups": [], "removed_paths": []}
            maintained = gamever in maintained_versions
            if merge_contract is not None and base_contract is not None and maintained:
                invalidation = build_invalidation_plan(
                    base_contract,
                    merge_contract,
                    _pseudo_snapshot(base_contract, base_files),
                    _pseudo_snapshot(merge_contract, merge_files),
                    list(changes),
                    repo.root,
                    base_sources=base_sources,
                    head_sources=merge_sources,
                )
                selected_group_ids, selected_node_ids = _execution_closure(merge_contract, invalidation)
                invalidated_paths.update(
                    merge_contract.producer_groups[group_id].artifact_path for group_id in selected_group_ids
                )
                invalidated_paths.update(path for path in invalidation.paths if path not in merge_contract.formal_paths)
                reasons.extend(invalidation.reasons)
            elif merge_contract is not None and maintained:
                selected_group_ids, selected_node_ids = _select_all_groups(merge_contract)
                invalidated_paths.update(merge_contract.formal_paths)
                reasons.append("new configured GAMEVER")
            elif base_contract is not None and maintained:
                invalidated_paths.update(base_contract.formal_paths)
                reasons.append("configured GAMEVER removed")

            if gamever in base_versions and gamever in merge_versions:
                changed_identity_paths = []
                # Compare the normalized DepotDownloader selection (app_id/branch/manifests/os)
                # exactly like binary_lock does, so non-identity metadata such as
                # major_update stays a legal prior-baseline policy adjustment.
                if _revision_download_identity(base_download_raw, gamever) != _revision_download_identity(
                    merge_download_raw, gamever
                ):
                    changed_identity_paths.append(f"download.yaml (existing tag {gamever!r})")
                if base_binary_lock.sha256 != merge_binary_lock.sha256:
                    changed_identity_paths.append(f"binary_locks/{gamever}.json")
                if changed_identity_paths:
                    raise TrustedArtifactPrError(
                        "manual binary identity change for an already-configured GAMEVER is rejected; "
                        "use the download/binary-lock bump flow instead of editing identity by hand:\n"
                        + "\n".join(f"  {path}" for path in changed_identity_paths)
                    )

            if merge_contract is not None and maintained:
                identity_prefix = f"bin_artifacts/{gamever}/"
                base_identity = (
                    {item["path"].removeprefix(identity_prefix): item for item in base_inventory["files"]}
                    if base_inventory
                    else {}
                )
                merge_identity = {item["path"].removeprefix(identity_prefix): item for item in merge_inventory["files"]}
                partition = _partition_version_execution(
                    merge_contract, base_identity, merge_identity, selected_group_ids, selected_node_ids
                )

            artifact_changes = [
                change
                for change in changes
                if any(
                    path and path.startswith(f"bin_artifacts/{gamever}/") for path in (change.old_path, change.new_path)
                )
            ]
            if artifact_changes and maintained and not invalidated_paths:
                raise TrustedArtifactPrError(f"artifact-only changes produced an empty plan for GAMEVER {gamever}")

            groups = []
            nodes = []
            if merge_contract is not None:
                groups = [
                    {
                        "group_id": group_id,
                        "artifact_path": merge_contract.producer_groups[group_id].artifact_path,
                        "required": merge_contract.producer_groups[group_id].required,
                        "fingerprint": merge_contract.producer_groups[group_id].fingerprint,
                        "alternative_node_ids": list(merge_contract.producer_groups[group_id].alternative_node_ids),
                    }
                    for group_id in sorted(selected_group_ids)
                ]
                nodes = [
                    _node_document(merge_contract, node_id)
                    for node_id in sorted(
                        selected_node_ids,
                        key=lambda value: (
                            merge_contract.nodes[value].stage_index,
                            merge_contract.nodes[value].module_name,
                            merge_contract.nodes[value].platform,
                            merge_contract.nodes[value].skill_name,
                            value,
                        ),
                    )
                ]
            binary_inventory = [
                {
                    "module": target.module_name,
                    "platform": target.platform,
                    "source_path": target.source_path,
                }
                for target in sorted(
                    (merge_contract or base_contract).binary_targets.values(),
                    key=lambda target: (target.module_name, target.platform),
                )
            ]
            version_reports.append(
                {
                    "game_version": gamever,
                    "maintained": maintained,
                    "base_config_sha256": base_contract.config_sha256 if base_contract else None,
                    "merge_config_sha256": merge_contract.config_sha256 if merge_contract else None,
                    "base_binary_lock_sha256": base_binary_lock.sha256 if base_binary_lock else None,
                    "merge_binary_lock_sha256": merge_binary_lock.sha256 if merge_binary_lock else None,
                    "base_artifacts": base_inventory,
                    "merge_artifacts": merge_inventory,
                    "binary_inventory": binary_inventory,
                    "binary_inventory_sha256": _digest("configured-binary-inventory", binary_inventory),
                    "bootstrap_required": bootstrap_required,
                    "prior_gamever": None,
                    "invalidated_paths": sorted(invalidated_paths),
                    "execute_groups": groups,
                    "execute_nodes": nodes,
                    "inherit_paths": partition["inherit_paths"],
                    "inherited_absent_groups": partition["inherited_absent_groups"],
                    "removed_paths": partition["removed_paths"],
                    "reasons": list(dict.fromkeys(reasons)),
                }
            )

    complete_merge_versions = [
        report["game_version"]
        for report in version_reports
        if report["merge_artifacts"] is not None
        and not report["merge_artifacts"]["missing_required"]
        and report["game_version"] in merge_downloads
    ]
    for report in version_reports:
        gamever = report["game_version"]
        if report["merge_artifacts"] is None or bool(merge_downloads.get(gamever, {}).get("major_update")):
            continue
        report["prior_gamever"] = select_prior_gamever(gamever, complete_merge_versions)

    affected_versions = [
        report["game_version"]
        for report in version_reports
        if report["invalidated_paths"] or report["bootstrap_required"]
    ]
    mode = (
        "bootstrap_required"
        if any(report["bootstrap_required"] for report in version_reports)
        else ("full" if affected_versions else "light")
    )
    policy_strategy = context["artifact_policy"]["execution_strategy"]
    document = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "event_kind": context["event_kind"],
        "mode": mode,
        "execution_strategy": policy_strategy,
        "base_sha": context["base_sha"],
        "head_sha": context["head_sha"],
        "merge_sha": context["merge_sha"],
        "merge_tree_sha": context["merge_tree_sha"],
        "trusted_context_sha256": context["context_sha256"],
        "configured_game_versions": list(merge_versions),
        "affected_game_versions": affected_versions,
        "download_sha256": _sha256(merge_download_raw),
        "sdk_gitlink_sha": _gitlink_sha(repo, context["merge_sha"], "hl2sdk_cs2"),
        "base_analysis_sources": _source_inventory(repo, context["base_sha"]),
        "merge_analysis_sources": _source_inventory(repo, context["merge_sha"]),
        "changed_paths": [_change_document(change) for change in changes],
        "impact": {
            "release": any(
                path
                and path.startswith(
                    ("configs/", "download.yaml", "binary_locks/", "bin_artifacts/", "gamedata-generators/")
                )
                for change in changes
                for path in (change.old_path, change.new_path)
            ),
            "gamedata": any(
                path and path.startswith(("configs/", "binary_locks/", "bin_artifacts/", "gamedata-generators/"))
                for change in changes
                for path in (change.old_path, change.new_path)
            ),
            "cpp": any(
                path and path.startswith(("configs/", "binary_locks/", "bin_artifacts/", "cpp_tests/", "hl2sdk_cs2"))
                for change in changes
                for path in (change.old_path, change.new_path)
            ),
            "pages": any(
                path and path.startswith(("pages/", ".github/workflows/pages"))
                for change in changes
                for path in (change.old_path, change.new_path)
            ),
        },
        "game_versions": version_reports,
    }
    document["plan_sha256"] = _digest("trusted-pr-plan", document)
    return document


def _validated_partition_item(item: object, gamever: str) -> dict:
    if (
        not isinstance(item, dict)
        or set(item) != {"path", "blob_sha", "size", "sha256"}
        or not isinstance(item.get("path"), str)
        or not item["path"]
        or not SHA_RE.fullmatch(str(item.get("blob_sha", "")))
        or not isinstance(item.get("size"), int)
        or isinstance(item.get("size"), bool)
        or item["size"] < 0
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(item.get("sha256", "")))
    ):
        raise TrustedArtifactPrError(f"trusted artifact plan inherit entry is invalid for {gamever}")
    return item


def validate_trusted_artifact_plan(document: object) -> dict:
    if not isinstance(document, dict) or document.get("schema_version") != PLAN_SCHEMA_VERSION:
        raise TrustedArtifactPrError("trusted artifact plan schema is invalid")
    digest = document.get("plan_sha256")
    unsigned = dict(document)
    unsigned.pop("plan_sha256", None)
    if digest != _digest("trusted-pr-plan", unsigned):
        raise TrustedArtifactPrError("trusted artifact plan digest mismatch")
    for field in ("base_sha", "head_sha", "merge_sha", "merge_tree_sha"):
        if not SHA_RE.fullmatch(str(document.get(field, ""))):
            raise TrustedArtifactPrError(f"trusted artifact plan has an invalid {field}")
    if document.get("mode") not in {"light", "full", "bootstrap_required"}:
        raise TrustedArtifactPrError("trusted artifact plan mode is invalid")
    if document.get("execution_strategy") not in EXECUTION_STRATEGIES:
        raise TrustedArtifactPrError("trusted artifact plan execution strategy is invalid")
    versions = document.get("game_versions")
    if not isinstance(versions, list) or any(
        not isinstance(version, dict) or not isinstance(version.get("game_version"), str) for version in versions
    ):
        raise TrustedArtifactPrError("trusted artifact plan game_versions are invalid")
    versions_by_gamever = {version.get("game_version"): version for version in versions}
    if len(versions_by_gamever) != len(versions):
        raise TrustedArtifactPrError("trusted artifact plan GAMEVER identities are duplicate or invalid")
    for gamever, version in versions_by_gamever.items():
        for config_field, lock_field in (
            ("base_config_sha256", "base_binary_lock_sha256"),
            ("merge_config_sha256", "merge_binary_lock_sha256"),
        ):
            config_digest = version.get(config_field)
            lock_digest = version.get(lock_field)
            if (config_digest is None) != (lock_digest is None) or (
                lock_digest is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", str(lock_digest))
            ):
                raise TrustedArtifactPrError(f"trusted artifact plan has an invalid {lock_field} for {gamever}")
        if not isinstance(version.get("maintained"), bool):
            raise TrustedArtifactPrError(f"trusted artifact plan maintained flag is invalid for {gamever}")
        for field in ("execute_groups", "execute_nodes"):
            if not isinstance(version.get(field), list):
                raise TrustedArtifactPrError(f"trusted artifact plan {field} is invalid for {gamever}")
        for field in ("inherit_paths",):
            if not isinstance(version.get(field), list):
                raise TrustedArtifactPrError(f"trusted artifact plan {field} is invalid for {gamever}")
            for item in version[field]:
                _validated_partition_item(item, gamever)
        if not isinstance(version.get("inherited_absent_groups"), list) or any(
            not isinstance(group, dict)
            or not isinstance(group.get("group_id"), str)
            or not isinstance(group.get("artifact_path"), str)
            or group.get("required") is not False
            for group in version["inherited_absent_groups"]
        ):
            raise TrustedArtifactPrError(f"trusted artifact plan inherited_absent_groups is invalid for {gamever}")
        if not isinstance(version.get("removed_paths"), list) or any(
            not isinstance(item, str) for item in version["removed_paths"]
        ):
            raise TrustedArtifactPrError(f"trusted artifact plan removed_paths is invalid for {gamever}")
        inherit_paths = [item["path"] for item in version["inherit_paths"]]
        if len(set(inherit_paths)) != len(inherit_paths):
            raise TrustedArtifactPrError(f"trusted artifact plan inherit paths are duplicate for {gamever}")
        absent_paths = [group["artifact_path"] for group in version["inherited_absent_groups"]]
        executed = [group.get("artifact_path") for group in version["execute_groups"]]
        overlap = (set(inherit_paths) | set(absent_paths)) & (set(executed) | set(version["removed_paths"]))
        overlap |= (set(absent_paths) & set(inherit_paths)) | (set(absent_paths) & set(version["removed_paths"]))
        if overlap:
            raise TrustedArtifactPrError(f"trusted artifact plan partitions overlap for {gamever}: {sorted(overlap)}")
        if "prior_gamever" not in version:
            raise TrustedArtifactPrError(f"trusted artifact plan omits prior_gamever for {gamever}")
        prior_gamever = version["prior_gamever"]
        if prior_gamever is None:
            continue
        prior_version = versions_by_gamever.get(prior_gamever)
        current_key = gamever_order_key(str(gamever))
        prior_key = gamever_order_key(str(prior_gamever))
        if (
            not isinstance(prior_gamever, str)
            or current_key is None
            or prior_key is None
            or prior_key >= current_key
            or prior_version is None
            or not isinstance(prior_version.get("merge_artifacts"), dict)
            or prior_version["merge_artifacts"].get("missing_required") != []
        ):
            raise TrustedArtifactPrError(f"trusted artifact plan has an invalid prior_gamever for {gamever}")
    return document


def load_trusted_artifact_plan(path: str | Path) -> dict:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TrustedArtifactPrError(f"unable to load trusted artifact plan: {exc}") from exc
    return validate_trusted_artifact_plan(document)


def _filesystem_artifact_digest(root: Path) -> str:
    if not root.exists():
        return _digest("checkout-artifact-inventory", [])
    items = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            path = current_path / directory
            if is_reparse_point(path):
                raise TrustedArtifactPrError(f"artifact checkout traverses a link/reparse point: {path}")
        for filename in files:
            path = current_path / filename
            if is_reparse_point(path):
                raise TrustedArtifactPrError(f"artifact checkout contains a link/reparse point: {path}")
            raw = path.read_bytes()
            items.append({"path": path.relative_to(root).as_posix(), "size": len(raw), "sha256": _sha256(raw)})
    return _digest("checkout-artifact-inventory", sorted(items, key=lambda item: item["path"]))


def _validate_checkout_external_staging(repo: GitTreeRepository, staging_root: Path) -> None:
    try:
        staging_root.relative_to(repo.root)
    except ValueError:
        pass
    else:
        raise TrustedArtifactPrError("isolated rebuild staging root must be outside the source checkout")


def _materialize_inherited_whitelist(
    repo: GitTreeRepository,
    plan: dict,
    version: dict,
    gamever: str,
    actual_root: Path,
    expected_root: Path,
) -> list[dict]:
    """Write only the planned inherit paths from exact base Git blobs into the actual root.

    The base bytes are cross-checked against the materialized merge-side expected blob
    before and after the write, so a seeded actual root can only ever hold base-owned
    bytes that the prospective merge tree also carries unchanged.
    """
    prefix = f"bin_artifacts/{gamever}/"
    inherited = []
    base_entries = [
        GitTreeEntry("100644", "blob", item["blob_sha"], f"{prefix}{item['path']}") for item in version["inherit_paths"]
    ]
    raw_by_path = repo.read_blobs(base_entries)
    for item in version["inherit_paths"]:
        raw = raw_by_path[f"{prefix}{item['path']}"]
        if len(raw) != item["size"] or _sha256(raw) != item["sha256"]:
            raise TrustedArtifactPrError(f"inherited base artifact drifted: {prefix}{item['path']}")
        expected_path = expected_root / gamever / item["path"]
        if not expected_path.is_file() or expected_path.read_bytes() != raw:
            raise TrustedArtifactPrError(
                f"inherited artifact differs between the base and merge trees: {prefix}{item['path']}"
            )
        actual_path = actual_root / gamever / item["path"]
        _atomic_write(actual_path, raw)
        materialized = actual_path.read_bytes()
        if materialized != raw:
            raise TrustedArtifactPrError(f"inherited artifact materialization drifted: {prefix}{item['path']}")
        inherited.append({**item})
    return inherited


def _build_selected_execution_manifest(plan: dict, version: dict, config_root: Path, initial_inventory: str) -> dict:
    gamever = version["game_version"]
    config_raw = (config_root / f"{gamever}.yaml").read_bytes()
    manifest = {
        "schema_version": SELECTED_EXECUTION_SCHEMA_VERSION,
        "execution_strategy": BASE_INHERITED_SELECTED_STRATEGY,
        "plan_sha256": plan["plan_sha256"],
        "base_sha": plan["base_sha"],
        "merge_sha": plan["merge_sha"],
        "merge_tree_sha": plan["merge_tree_sha"],
        "game_version": gamever,
        "prior_gamever": version["prior_gamever"],
        "config_sha256": _sha256(config_raw),
        "initial_actual_inventory_sha256": initial_inventory,
        "execute_nodes": version["execute_nodes"],
        "execute_groups": version["execute_groups"],
        "inherit_paths": version["inherit_paths"],
        "inherited_absent_groups": version["inherited_absent_groups"],
        "removed_paths": version["removed_paths"],
    }
    manifest["manifest_sha256"] = _digest(SELECTED_MANIFEST_DIGEST_LABEL, manifest)
    return manifest


def _prepare_isolated_rebuild(
    *,
    repo_root: str | Path,
    plan: dict | str | Path,
    staging_root: str | Path,
    game_version: str | None = None,
) -> dict:
    plan = load_trusted_artifact_plan(plan) if isinstance(plan, (str, Path)) else validate_trusted_artifact_plan(plan)
    if plan["mode"] != "full":
        raise TrustedArtifactPrError(f"isolated rebuild requires a full plan, got {plan['mode']}")
    strategy = plan["execution_strategy"]
    if strategy not in EXECUTION_STRATEGIES:
        raise TrustedArtifactPrError(f"isolated rebuild strategy is unknown: {strategy!r}")
    repo = GitTreeRepository(repo_root)
    if repo.tree_sha(plan["merge_sha"]) != plan["merge_tree_sha"]:
        raise TrustedArtifactPrError("prospective merge tree drifted before isolated rebuild preparation")
    staging_root = Path(os.path.abspath(staging_root))
    _validate_checkout_external_staging(repo, staging_root)
    if staging_root.exists():
        raise TrustedArtifactPrError(f"isolated rebuild staging root already exists: {staging_root}")
    staging_root.mkdir(parents=True)
    expected_root = staging_root / "expected-bin-artifacts"
    actual_root = staging_root / "actual-bin-artifacts"
    config_root = staging_root / "configs"
    execution_root = staging_root / "execution-reports"
    expected_root.mkdir()
    actual_root.mkdir()
    config_root.mkdir()
    execution_root.mkdir()

    prepared_versions = []
    inherited_files: dict[str, list[dict]] = {}
    initial_inventories: dict[str, str] = {}
    selected_manifests: dict[str, str] = {}
    for version in plan["game_versions"]:
        if not version["invalidated_paths"] or version["merge_artifacts"] is None:
            continue
        gamever = version["game_version"]
        if game_version is not None and gamever != str(game_version):
            continue
        _atomic_write(config_root / f"{gamever}.yaml", repo.read(plan["merge_sha"], f"configs/{gamever}.yaml"))
        artifact_entries = [
            GitTreeEntry("100644", "blob", item["blob_sha"], item["path"])
            for item in version["merge_artifacts"]["files"]
        ]
        raw_by_path = repo.read_blobs(artifact_entries)
        for item in version["merge_artifacts"]["files"]:
            prefix = f"bin_artifacts/{gamever}/"
            key = item["path"].removeprefix(prefix)
            if key == item["path"]:
                raise TrustedArtifactPrError(f"plan contains an artifact outside GAMEVER {gamever}: {item['path']}")
            raw = raw_by_path[item["path"]]
            if len(raw) != item["size"] or _sha256(raw) != item["sha256"]:
                raise TrustedArtifactPrError(f"prospective merge artifact drifted: {item['path']}")
            expected_path = expected_root / gamever / key
            _atomic_write(expected_path, raw)
        inherited = []
        if strategy == BASE_INHERITED_SELECTED_STRATEGY:
            inherited = _materialize_inherited_whitelist(repo, plan, version, gamever, actual_root, expected_root)
            forbidden = [group["artifact_path"] for group in version["execute_groups"]]
            forbidden.extend(group["artifact_path"] for group in version["inherited_absent_groups"])
            forbidden.extend(version["removed_paths"])
            for path in forbidden:
                if (actual_root / gamever / path).exists():
                    raise TrustedArtifactPrError(
                        f"seeded actual root must not contain a planned execution output: {gamever}/{path}"
                    )
            initial_inventories[gamever] = _filesystem_artifact_digest(actual_root / gamever)
            manifest = _build_selected_execution_manifest(plan, version, config_root, initial_inventories[gamever])
            manifest_path = staging_root / f"selected-execution-{gamever}.json"
            _atomic_write(manifest_path, _canonical_json_bytes(manifest))
            selected_manifests[gamever] = str(manifest_path)
        inherited_files[gamever] = inherited
        prepared_versions.append(gamever)
    if game_version is not None and prepared_versions != [str(game_version)]:
        raise TrustedArtifactPrError(f"GAMEVER is not an affected full-plan target: {game_version}")

    report = {
        "schema_version": PREPARATION_SCHEMA_VERSION,
        "plan_sha256": plan["plan_sha256"],
        "execution_strategy": strategy,
        "merge_sha": plan["merge_sha"],
        "merge_tree_sha": plan["merge_tree_sha"],
        "staging_root": str(staging_root),
        "expected_artifact_root": str(expected_root),
        "actual_artifact_root": str(actual_root),
        "config_root": str(config_root),
        "binary_root": str(repo.root / "bin"),
        "execution_reports": {
            gamever: str(
                execution_root
                / (
                    f"{gamever}.selected.json"
                    if strategy == BASE_INHERITED_SELECTED_STRATEGY
                    else f"{gamever}.force-all.json"
                )
            )
            for gamever in prepared_versions
        },
        "selected_execution_manifests": selected_manifests,
        "inherited_files": inherited_files,
        "initial_actual_inventory_sha256": initial_inventories,
        "prepared_game_versions": prepared_versions,
        "source_checkout_artifact_sha256": _filesystem_artifact_digest(repo.root / "bin_artifacts"),
    }
    report["preparation_sha256"] = _digest("isolated-preparation", report)
    _atomic_write(staging_root / "preparation.json", _canonical_json_bytes(report))
    return report


def _load_force_all_execution_report(path: Path, *, preparation: dict, version: dict) -> dict:
    try:
        raw = path.read_bytes()
        report = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TrustedArtifactPrError(
            f"unable to load force-all execution report for {version['game_version']}: {exc}"
        ) from exc
    if raw != _canonical_json_bytes(report):
        raise TrustedArtifactPrError("force-all execution report is not canonical JSON")
    digest = report.get("execution_sha256")
    unsigned = dict(report)
    unsigned.pop("execution_sha256", None)
    raw_digest = b"source2-force-all-execution:v2\n" + _canonical_json_bytes(unsigned)
    if digest != f"sha256:{hashlib.sha256(raw_digest).hexdigest()}":
        raise TrustedArtifactPrError("force-all execution report digest mismatch")

    gamever = version["game_version"]
    if (
        report.get("schema_version") != 2
        or report.get("valid") is not True
        or report.get("force_all") is not True
        or report.get("required_warm_idb") is not True
        or report.get("game_version") != gamever
        or "prior_gamever" not in report
        or report.get("prior_gamever") != version["prior_gamever"]
        or Path(report.get("artifact_root", "")).resolve() != Path(preparation["actual_artifact_root"]).resolve()
        or Path(report.get("binary_root", "")).resolve() != Path(preparation["binary_root"]).resolve()
        or Path(report.get("config_path", "")).resolve()
        != (Path(preparation["config_root"]) / f"{gamever}.yaml").resolve()
    ):
        raise TrustedArtifactPrError(f"force-all execution report does not prove the required PR run for {gamever}")

    expected_files = {
        item["path"].removeprefix(f"bin_artifacts/{gamever}/"): item for item in version["merge_artifacts"]["files"]
    }
    group_records = report.get("producer_groups")
    if not isinstance(group_records, list):
        raise TrustedArtifactPrError("force-all execution report has no producer-group evidence")
    groups_by_id = {
        record.get("group_id"): record
        for record in group_records
        if isinstance(record, dict) and record.get("group_id")
    }
    if len(groups_by_id) != len(group_records):
        raise TrustedArtifactPrError("force-all execution report has duplicate or invalid producer groups")
    for planned in version["execute_groups"]:
        record = groups_by_id.get(planned["group_id"])
        if record is None:
            raise TrustedArtifactPrError(f"selected producer group was not executed: {planned['group_id']}")
        expected = expected_files.get(planned["artifact_path"])
        expected_sha256 = expected["sha256"] if expected is not None else None
        if (
            record.get("artifact_path") != planned["artifact_path"]
            or record.get("required") != planned["required"]
            or record.get("fingerprint") != planned["fingerprint"]
            or record.get("alternative_node_ids") != planned["alternative_node_ids"]
            or record.get("output_sha256") != expected_sha256
        ):
            raise TrustedArtifactPrError(
                f"producer-group execution drifted from the trusted plan: {planned['group_id']}"
            )
        winner = record.get("winner_node_id")
        if expected_sha256 is not None and winner not in planned["alternative_node_ids"]:
            raise TrustedArtifactPrError(f"producer group has no valid winning alternative: {planned['group_id']}")
        if expected_sha256 is None and winner is not None:
            raise TrustedArtifactPrError(
                f"absent optional producer group unexpectedly selected a winner: {planned['group_id']}"
            )
    return report


def _selected_execution_digest(value: object) -> str:
    raw = SELECTED_EXECUTION_DIGEST_DOMAIN.encode("utf-8") + b"\n" + _canonical_json_bytes(value)
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


LEGAL_ABSENT_SKIP_REASONS = frozenset({"optional_output_absent", "preprocess_absent"})


def _is_verified_attempt_status(
    node_record: dict, expected_files: dict, allowed_materialized_paths: frozenset[str] | set[str]
) -> bool:
    """Accept a terminal status, or a skip that provably encodes a legal absence/fallback.

    A skipped node is only accepted when the recorded skip reason is the executor's
    optional/preprocess-absent outcome and the node produced nothing. Every path it
    attempted must then either be genuinely absent from the prospective merge tree, or
    be a path this node was allowed to concede to a later winning alternative within its
    producer group (a legal fallback attempt, not an unexecuted skip).
    """
    status = node_record.get("status")
    if status in {"succeeded", "failed"}:
        return True
    if status != "skipped" or node_record.get("reason") not in LEGAL_ABSENT_SKIP_REASONS:
        return False
    if node_record.get("produced_paths"):
        return False
    for path in node_record["attempted_paths"]:
        if path in expected_files and path not in allowed_materialized_paths:
            return False
    return True


def _load_selected_execution_report(path: Path, *, preparation: dict, version: dict, plan: dict) -> dict:
    try:
        raw = path.read_bytes()
        report = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TrustedArtifactPrError(
            f"unable to load selected execution report for {version['game_version']}: {exc}"
        ) from exc
    if raw != _canonical_json_bytes(report):
        raise TrustedArtifactPrError("selected execution report is not canonical JSON")
    digest = report.get("execution_sha256")
    unsigned = dict(report)
    unsigned.pop("execution_sha256", None)
    if digest != _selected_execution_digest(unsigned):
        raise TrustedArtifactPrError("selected execution report digest mismatch")

    gamever = version["game_version"]
    manifest = preparation["selected_execution_manifests"].get(gamever)
    if not manifest:
        raise TrustedArtifactPrError(f"preparation omitted the selected manifest for {gamever}")
    manifest_document = _load_selected_execution_manifest(Path(manifest))
    if (
        report.get("schema_version") != SELECTED_EXECUTION_SCHEMA_VERSION
        or report.get("valid") is not True
        or report.get("execution_strategy") != BASE_INHERITED_SELECTED_STRATEGY
        or report.get("game_version") != gamever
        or "prior_gamever" not in report
        or report.get("prior_gamever") != version["prior_gamever"]
        or report.get("plan_sha256") != plan["plan_sha256"]
        or report.get("manifest_sha256") != manifest_document["manifest_sha256"]
        or Path(report.get("artifact_root", "")).resolve() != Path(preparation["actual_artifact_root"]).resolve()
        or Path(report.get("binary_root", "")).resolve() != Path(preparation["binary_root"]).resolve()
        or Path(report.get("config_path", "")).resolve()
        != (Path(preparation["config_root"]) / f"{gamever}.yaml").resolve()
    ):
        raise TrustedArtifactPrError(f"selected execution report does not prove the required PR run for {gamever}")

    validate_selected_execution_records(report, version)
    if report.get("inherited_initial_inventory_sha256") != preparation["initial_actual_inventory_sha256"].get(gamever):
        raise TrustedArtifactPrError(f"selected execution report lost the seeded-root binding for {gamever}")
    return report


def validate_selected_execution_records(report: dict, version: dict) -> None:
    """Validate group/node coverage and writes; callers must separately bind provenance and roots."""
    gamever = version["game_version"]
    expected_files = {
        item["path"].removeprefix(f"bin_artifacts/{gamever}/"): item for item in version["merge_artifacts"]["files"]
    }
    group_records = report.get("producer_groups")
    if not isinstance(group_records, list):
        raise TrustedArtifactPrError("selected execution report has no producer-group evidence")
    groups_by_id = {
        record.get("group_id"): record
        for record in group_records
        if isinstance(record, dict) and record.get("group_id")
    }
    if len(groups_by_id) != len(group_records):
        raise TrustedArtifactPrError("selected execution report has duplicate or invalid producer groups")
    planned_groups = {planned["group_id"]: planned for planned in version["execute_groups"]}
    if set(groups_by_id) != set(planned_groups):
        missing = sorted(set(planned_groups) - set(groups_by_id))
        extra = sorted(set(groups_by_id) - set(planned_groups))
        raise TrustedArtifactPrError(
            f"selected execution report does not match the planned execution set for {gamever}: "
            f"missing={missing!r} extra={extra!r}"
        )
    for group_id, planned in planned_groups.items():
        record = groups_by_id[group_id]
        expected = expected_files.get(planned["artifact_path"])
        expected_sha256 = expected["sha256"] if expected is not None else None
        if (
            record.get("artifact_path") != planned["artifact_path"]
            or record.get("required") != planned["required"]
            or record.get("fingerprint") != planned["fingerprint"]
            or record.get("alternative_node_ids") != planned["alternative_node_ids"]
            or record.get("output_sha256") != expected_sha256
        ):
            raise TrustedArtifactPrError(f"selected execution drifted from the trusted plan: {group_id}")
        winner = record.get("winner_node_id")
        if expected_sha256 is not None and winner not in planned["alternative_node_ids"]:
            raise TrustedArtifactPrError(f"selected producer group has no valid winning alternative: {group_id}")
        if expected_sha256 is None and winner is not None:
            raise TrustedArtifactPrError(f"absent optional producer group unexpectedly selected a winner: {group_id}")
    reported_nodes = {node.get("node_id") for node in report.get("nodes", []) if isinstance(node, dict)}
    planned_nodes = {node["node_id"]: node for node in version["execute_nodes"]}
    if reported_nodes != set(planned_nodes):
        raise TrustedArtifactPrError(
            f"selected execution node evidence does not match the plan for {gamever}: "
            f"missing={sorted(set(planned_nodes) - reported_nodes)!r} "
            f"extra={sorted(reported_nodes - set(planned_nodes))!r}"
        )

    # Independently verify the node evidence instead of trusting the self-reported valid flag:
    # no duplicates, terminal statuses for attempted nodes, writes only to authorized outputs,
    # and per-node attempt/production claims that agree with every group's attempt prefix.
    node_records_list = report.get("nodes")
    nodes_by_id: dict[str, dict] = {}
    for record in node_records_list:
        if not isinstance(record, dict) or not isinstance(record.get("node_id"), str) or not record["node_id"]:
            raise TrustedArtifactPrError("selected execution report has an invalid node record")
        if record["node_id"] in nodes_by_id:
            raise TrustedArtifactPrError(f"selected execution report has duplicate node evidence: {record['node_id']}")
        for field in ("attempted_paths", "produced_paths"):
            if not isinstance(record.get(field), list) or any(not isinstance(path, str) for path in record[field]):
                raise TrustedArtifactPrError(
                    f"selected execution report node has an invalid {field}: {record['node_id']}"
                )
        nodes_by_id[record["node_id"]] = record
    for node_id, record in nodes_by_id.items():
        authorized = set(planned_nodes[node_id]["outputs"])
        for field in ("attempted_paths", "produced_paths"):
            unauthorized = sorted(set(record[field]) - authorized)
            if unauthorized:
                raise TrustedArtifactPrError(
                    f"selected execution node recorded writes beyond its authorized outputs: {node_id} {unauthorized!r}"
                )
        if not set(record["produced_paths"]) <= set(record["attempted_paths"]):
            raise TrustedArtifactPrError(f"selected execution node produced outputs it never attempted: {node_id}")

    attempted_group_nodes: set[str] = set()
    fallback_materialized_paths: dict[str, set[str]] = {}
    for group_id, planned in planned_groups.items():
        record = groups_by_id[group_id]
        alternatives = list(planned["alternative_node_ids"])
        attempted = record.get("attempted_node_ids")
        if not isinstance(attempted, list) or any(not isinstance(node_id, str) for node_id in attempted):
            raise TrustedArtifactPrError(f"selected execution group has invalid attempt evidence: {group_id}")
        winner = record.get("winner_node_id")
        materialized = planned["artifact_path"] in expected_files
        if materialized:
            winner_index = alternatives.index(winner)
            expected_attempts = alternatives[: winner_index + 1]
        else:
            winner_index = None
            expected_attempts = alternatives
        if list(attempted) != expected_attempts:
            raise TrustedArtifactPrError(
                f"selected execution attempts drifted for {group_id}: "
                f"expected={expected_attempts!r} actual={attempted!r}"
            )
        successful = []
        for node_id in alternatives:
            node_record = nodes_by_id[node_id]
            claims_attempt = planned["artifact_path"] in node_record["attempted_paths"]
            if claims_attempt != (node_id in attempted):
                raise TrustedArtifactPrError(
                    f"selected execution node evidence contradicts the group attempts: {group_id}/{node_id}"
                )
            if node_id in attempted:
                attempted_group_nodes.add(node_id)
            if node_record.get("status") == "succeeded" and planned["artifact_path"] in node_record["produced_paths"]:
                successful.append(node_id)
        if materialized and successful != [winner]:
            raise TrustedArtifactPrError(
                f"materialized producer group must have exactly one producing winner: "
                f"{group_id} producers={successful!r}"
            )
        if not materialized and successful:
            raise TrustedArtifactPrError(
                f"absent optional output was produced by executed nodes: {group_id} {successful!r}"
            )
        if winner_index is not None:
            # A materialized path may be conceded by the failed/skipped alternatives that
            # ran before the winner: that is a legal fallback attempt, not an absent output.
            for node_id in alternatives[:winner_index]:
                fallback_materialized_paths.setdefault(node_id, set()).add(planned["artifact_path"])

    # Status verification runs after the group pass so every skipped node can be judged
    # against the exact set of paths it was allowed to concede to a later winner.
    for node_id, record in nodes_by_id.items():
        if node_id in attempted_group_nodes and not _is_verified_attempt_status(
            record, expected_files, fallback_materialized_paths.get(node_id, frozenset())
        ):
            raise TrustedArtifactPrError(f"attempted node lacks a terminal execution status: {node_id}")

    # Output-less session prerequisites belong to no producer group, so group-level
    # verification never covers them: unlike competing alternatives, a failed or skipped
    # prerequisite proves the session side effects its dependents rely on were never
    # established, so only a successful execution counts as evidence.
    group_alternative_node_ids = {
        node_id for planned_group in planned_groups.values() for node_id in planned_group["alternative_node_ids"]
    }
    for node_id, record in nodes_by_id.items():
        if node_id in group_alternative_node_ids:
            continue
        if record.get("attempted") is not True or record.get("status") != "succeeded":
            raise TrustedArtifactPrError(f"planned prerequisite node lacks successful execution evidence: {node_id}")


def _load_selected_execution_manifest(path: Path) -> dict:
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TrustedArtifactPrError(f"unable to load selected execution manifest: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != SELECTED_EXECUTION_SCHEMA_VERSION:
        raise TrustedArtifactPrError("selected execution manifest schema is invalid")
    digest = document.get("manifest_sha256")
    unsigned = dict(document)
    unsigned.pop("manifest_sha256", None)
    if digest != _digest(SELECTED_MANIFEST_DIGEST_LABEL, unsigned):
        raise TrustedArtifactPrError("selected execution manifest digest mismatch")
    for field in ("execution_strategy", "plan_sha256", "game_version"):
        if not isinstance(document.get(field), str) or not document[field]:
            raise TrustedArtifactPrError(f"selected execution manifest has an invalid {field}")
    if document["execution_strategy"] != BASE_INHERITED_SELECTED_STRATEGY:
        raise TrustedArtifactPrError("selected execution manifest strategy is invalid")
    if not isinstance(document.get("initial_actual_inventory_sha256"), str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", document["initial_actual_inventory_sha256"]
    ):
        raise TrustedArtifactPrError("selected execution manifest lacks a valid seeded-root inventory digest")
    for field in ("execute_nodes", "execute_groups", "inherit_paths", "inherited_absent_groups", "removed_paths"):
        if not isinstance(document.get(field), list):
            raise TrustedArtifactPrError(f"selected execution manifest has an invalid {field}")
    return document


def _verify_inherited_paths_against_base(repo: GitTreeRepository, plan: dict, version: dict, actual_root: Path) -> None:
    """Re-derive inherited bytes from the bound base tree and compare the final files.

    The final-state equality proves the composed inventory carried the base-owned bytes
    through execution; it does not by itself prove the executor never wrote them in
    between, and must not be presented as full write isolation.
    """
    gamever = version["game_version"]
    prefix = f"bin_artifacts/{gamever}/"
    entries = [
        GitTreeEntry("100644", "blob", item["blob_sha"], f"{prefix}{item['path']}") for item in version["inherit_paths"]
    ]
    raw_by_path = repo.read_blobs(entries)
    for item in version["inherit_paths"]:
        raw = raw_by_path[f"{prefix}{item['path']}"]
        if len(raw) != item["size"] or _sha256(raw) != item["sha256"]:
            raise TrustedArtifactPrError(f"inherited base artifact drifted from the plan: {prefix}{item['path']}")
        final_path = actual_root / gamever / item["path"]
        if not final_path.is_file() or final_path.read_bytes() != raw:
            raise TrustedArtifactPrError(
                f"inherited artifact was modified or removed during execution: {prefix}{item['path']}"
            )
    for path in version["removed_paths"]:
        if (actual_root / gamever / path).exists():
            raise TrustedArtifactPrError(f"contract-removed output was materialized: {gamever}/{path}")
    for group in version["inherited_absent_groups"]:
        if (actual_root / gamever / group["artifact_path"]).exists():
            raise TrustedArtifactPrError(
                f"legally absent optional output was created: {gamever}/{group['artifact_path']}"
            )


def _validate_isolated_rebuild(
    *, repo_root: str | Path, plan: dict | str | Path, preparation: dict | str | Path
) -> dict:
    plan = load_trusted_artifact_plan(plan) if isinstance(plan, (str, Path)) else validate_trusted_artifact_plan(plan)
    if isinstance(preparation, (str, Path)):
        try:
            preparation = json.loads(Path(preparation).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise TrustedArtifactPrError(f"unable to load isolated preparation: {exc}") from exc
    if not isinstance(preparation, dict) or preparation.get("schema_version") != PREPARATION_SCHEMA_VERSION:
        raise TrustedArtifactPrError("isolated preparation schema is invalid")
    digest = preparation.get("preparation_sha256")
    unsigned = dict(preparation)
    unsigned.pop("preparation_sha256", None)
    if digest != _digest("isolated-preparation", unsigned) or preparation.get("plan_sha256") != plan["plan_sha256"]:
        raise TrustedArtifactPrError("isolated preparation digest or plan binding mismatch")
    strategy = plan["execution_strategy"]
    if strategy not in EXECUTION_STRATEGIES:
        raise TrustedArtifactPrError(f"isolated rebuild strategy is unknown: {strategy!r}")
    if strategy == BASE_INHERITED_SELECTED_STRATEGY and not preparation.get("selected_execution_manifests"):
        raise TrustedArtifactPrError("selected-strategy preparation omitted every selected manifest")

    repo_root = Path(repo_root).resolve()
    repo = GitTreeRepository(repo_root)
    if _filesystem_artifact_digest(repo_root / "bin_artifacts") != preparation["source_checkout_artifact_sha256"]:
        raise TrustedArtifactPrError("source checkout artifacts changed during isolated rebuild")
    actual_root = Path(preparation["actual_artifact_root"])
    expected_root = Path(preparation["expected_artifact_root"])
    config_root = Path(preparation["config_root"])
    reports = []
    for version in plan["game_versions"]:
        gamever = version["game_version"]
        if gamever not in preparation["prepared_game_versions"]:
            continue
        if strategy == BASE_INHERITED_SELECTED_STRATEGY:
            execution = _load_selected_execution_report(
                Path(preparation["execution_reports"][gamever]),
                preparation=preparation,
                version=version,
                plan=plan,
            )
        else:
            execution = _load_force_all_execution_report(
                Path(preparation["execution_reports"][gamever]), preparation=preparation, version=version
            )
        try:
            actual = build_game_artifact_inventory(
                repo_root=repo_root,
                config_path=config_root / f"{gamever}.yaml",
                game_version=gamever,
                artifact_root=actual_root,
                require_tracked=False,
            )
        except ArtifactContractError as exc:
            raise TrustedArtifactPrError(f"isolated artifact contract failed for {gamever}: {exc}") from exc
        actual_items = {item.path: item for item in actual.files}
        expected_items = {item["path"]: item for item in version["merge_artifacts"]["files"]}
        if set(actual_items) != set(expected_items):
            raise TrustedArtifactPrError(
                f"isolated artifact inventory mismatch for {gamever}: "
                f"expected_count={len(expected_items)} actual_count={len(actual_items)}"
            )
        for path, expected in expected_items.items():
            actual_item = actual_items[path]
            if actual_item.size != expected["size"] or actual_item.sha256 != expected["sha256"]:
                raise TrustedArtifactPrError(f"isolated artifact byte mismatch: {path}")
            relative = path.removeprefix(f"bin_artifacts/{gamever}/")
            raw = (expected_root / gamever / relative).read_bytes()
            if len(raw) != expected["size"] or _sha256(raw) != expected["sha256"]:
                raise TrustedArtifactPrError(f"materialized expected Git blob drifted: {path}")
        if execution.get("inventory") != {
            "file_count": actual.file_count,
            "inventory_sha256": actual.inventory_sha256,
        }:
            raise TrustedArtifactPrError(f"execution inventory evidence drifted for {gamever}")
        inherited_count = 0
        removed_count = 0
        if strategy == BASE_INHERITED_SELECTED_STRATEGY:
            _verify_inherited_paths_against_base(repo, plan, version, actual_root)
            inherited_count = len(version["inherit_paths"])
            removed_count = len(version["removed_paths"])
        reports.append(
            {
                "game_version": gamever,
                "file_count": actual.file_count,
                "inventory_sha256": version["merge_artifacts"]["inventory_sha256"],
                "execution_sha256": execution["execution_sha256"],
                "executed_group_count": len(version["execute_groups"]),
                "inherited_count": inherited_count,
                "removed_count": removed_count,
            }
        )
    result = {
        "schema_version": 1,
        "plan_sha256": plan["plan_sha256"],
        "execution_strategy": strategy,
        "preparation_sha256": preparation["preparation_sha256"],
        "game_versions": reports,
    }
    result["validation_sha256"] = _digest("isolated-validation", result)
    return result


def pr_diagnostic_context(
    *,
    repo_root: Path,
    plan: dict | str | Path,
    staging_root: Path,
    game_version: str | None = None,
    plan_sha256: str | None = None,
) -> DiagnosticContext:
    """Derive evidence paths from the caller's staging, never from a failed preparation."""
    staging = external_staging(repo_root, staging_root)
    context = DiagnosticContext(
        actual_root=staging / "actual-bin-artifacts",
        evidence={"preparation.json": staging / "preparation.json"},
        metadata={"expected_source": "merge Git blob", "plan_valid": False, "preparation_valid": False},
    )
    if game_version is not None:
        context.game_versions = (safe_component(str(game_version)),)
    plan_path = Path(plan) if isinstance(plan, (str, Path)) else None
    if plan_path is not None:
        raw_plan, plan_error = read_artifact_bytes(plan_path)
        context.evidence["trusted-plan.json"] = raw_plan if raw_plan is not None else plan_path
    else:
        raw_plan, plan_error = _canonical_json_bytes(plan), None
        context.evidence["trusted-plan.json"] = raw_plan
    try:
        if raw_plan is None:
            raise TrustedArtifactPrError(f"diagnostic plan unavailable: {plan_error or 'missing'}")
        document = json.loads(raw_plan.decode("utf-8"))
        document = validate_trusted_artifact_plan(document)
        binding = plan_sha256 or os.environ.get("PLAN_SHA256")
        if binding is not None and document["plan_sha256"] != binding:
            raise TrustedArtifactPrError("diagnostic plan differs from the workflow plan binding")
        repo = GitTreeRepository(repo_root)
        if repo.tree_sha(document["merge_sha"]) != document["merge_tree_sha"]:
            raise TrustedArtifactPrError("diagnostic merge tree differs from the plan")
        versions = [
            version
            for version in document["game_versions"]
            if version["invalidated_paths"]
            and version["merge_artifacts"] is not None
            and (game_version is None or version["game_version"] == str(game_version))
        ]
        if not versions:
            raise TrustedArtifactPrError("diagnostic GAMEVER is not an affected plan target")
        context.game_versions = tuple(safe_component(version["game_version"]) for version in versions)
        context.metadata.update(
            plan_valid=True,
            plan_sha256=document["plan_sha256"],
            plan_binding="workflow digest" if binding else "caller-supplied plan",
            source_sha=document["merge_sha"],
            merge_sha=document["merge_sha"],
            merge_tree_sha=document["merge_tree_sha"],
            execution_strategy=document["execution_strategy"],
        )
        expected = {}
        for version in versions:
            gamever = version["game_version"]
            prefix = f"bin_artifacts/{gamever}/"
            entries = repo.entries(document["merge_sha"], prefix)
            for entry in entries:
                parts = entry.path.split("/")
                if entry.mode not in {"100644", "100755"} or len(parts) != 4 or not entry.path.endswith(".yaml"):
                    raise TrustedArtifactPrError(f"unsafe diagnostic Git entry: {entry.path}")
                for part in parts:
                    safe_component(part)
            raw_by_path = repo.read_blobs(entries)
            planned = {item["path"]: item for item in version["merge_artifacts"]["files"]}
            if set(planned) != set(raw_by_path):
                raise TrustedArtifactPrError("diagnostic Git inventory differs from the bound plan")
            for path, raw in raw_by_path.items():
                if len(raw) != planned[path]["size"] or _sha256(raw) != planned[path]["sha256"]:
                    raise TrustedArtifactPrError(f"diagnostic Git bytes differ from the bound plan: {path}")
            expected.update(raw_by_path)
        context.expected = expected
    except Exception as exc:
        context.errors.append(str(exc))
    context.metadata["game_versions"] = list(context.game_versions)
    context.metadata["game_version"] = context.game_versions[0] if len(context.game_versions) == 1 else None
    strategy = context.metadata.get("execution_strategy")
    for gamever in context.game_versions:
        suffixes = ("selected",) if strategy == BASE_INHERITED_SELECTED_STRATEGY else ("force-all",)
        if strategy is None:
            suffixes = ("selected", "force-all")
        for suffix in suffixes:
            relative = f"execution-reports/{gamever}.{suffix}.json"
            context.evidence[relative] = staging / relative
        if strategy != FRESH_FULL_STRATEGY:
            relative = f"selected-execution-{gamever}.json"
            context.evidence[relative] = staging / relative
    try:
        raw_preparation, preparation_error = read_artifact_bytes(staging / "preparation.json")
        if raw_preparation is None:
            raise TrustedArtifactPrError(f"diagnostic preparation unavailable: {preparation_error or 'missing'}")
        context.evidence["preparation.json"] = raw_preparation
        preparation = json.loads(raw_preparation.decode("utf-8"))
        unsigned = dict(preparation)
        digest = unsigned.pop("preparation_sha256", None)
        if (
            preparation.get("schema_version") != PREPARATION_SCHEMA_VERSION
            or digest != _digest("isolated-preparation", unsigned)
            or not context.metadata["plan_valid"]
            or preparation.get("plan_sha256") != context.metadata["plan_sha256"]
            or preparation.get("merge_sha") != context.metadata["merge_sha"]
            or Path(os.path.abspath(preparation["staging_root"])) != staging
            or Path(os.path.abspath(preparation["actual_artifact_root"])) != context.actual_root
        ):
            raise TrustedArtifactPrError("diagnostic preparation digest, layout or plan binding mismatch")
        context.metadata.update(preparation_valid=True, preparation_sha256=digest)
    except Exception as exc:
        context.errors.append(str(exc))
    return context


def prepare_isolated_rebuild(
    *,
    repo_root: str | Path,
    plan: dict | str | Path,
    staging_root: str | Path,
    game_version: str | None = None,
    diagnostic_plan_sha256: str | None = None,
) -> dict:
    try:
        return _prepare_isolated_rebuild(
            repo_root=repo_root, plan=plan, staging_root=staging_root, game_version=game_version
        )
    except Exception as exc:
        detail = append_failure_diagnostics(
            str(exc),
            lambda: pr_diagnostic_context(
                repo_root=Path(repo_root),
                plan=plan,
                staging_root=Path(staging_root),
                game_version=game_version,
                plan_sha256=diagnostic_plan_sha256,
            ),
        )
        raise TrustedArtifactPrError(detail) from exc


def _diagnostic_staging(preparation: dict | str | Path) -> Path:
    # File callers authorize only the file's parent; JSON contents cannot redirect collection.
    if isinstance(preparation, (str, Path)):
        return Path(preparation).absolute().parent
    return Path(preparation["staging_root"])


def validate_isolated_rebuild(
    *,
    repo_root: str | Path,
    plan: dict | str | Path,
    preparation: dict | str | Path,
    diagnostic_game_version: str | None = None,
    diagnostic_plan_sha256: str | None = None,
    diagnostic_staging_root: str | Path | None = None,
) -> dict:
    try:
        return _validate_isolated_rebuild(repo_root=repo_root, plan=plan, preparation=preparation)
    except Exception as exc:
        detail = append_failure_diagnostics(
            str(exc),
            lambda: pr_diagnostic_context(
                repo_root=Path(repo_root),
                plan=plan,
                staging_root=Path(diagnostic_staging_root)
                if diagnostic_staging_root is not None
                else _diagnostic_staging(preparation),
                game_version=diagnostic_game_version,
                plan_sha256=diagnostic_plan_sha256,
            ),
        )
        raise TrustedArtifactPrError(detail) from exc


def collect_pr_failure_diagnostics(
    *,
    repo_root: Path,
    plan: dict | str | Path,
    staging_root: Path,
    destination: Path,
    error: str,
    phase: str,
    game_version: str | None = None,
    plan_sha256: str | None = None,
) -> None:
    collect_failure_bundle(
        repo_root=repo_root,
        staging=staging_root,
        destination=destination,
        error=error,
        phase=phase,
        load_context=lambda: pr_diagnostic_context(
            repo_root=repo_root,
            plan=plan,
            staging_root=staging_root,
            game_version=game_version,
            plan_sha256=plan_sha256,
        ),
    )


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan")
    plan.add_argument("--repo-root", default=".")
    plan.add_argument("--trusted-context", required=True)
    plan.add_argument("--output", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--repo-root", default=".")
    prepare.add_argument("--plan", required=True)
    prepare.add_argument("--staging-root", required=True)
    prepare.add_argument("--gamever")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--repo-root", default=".")
    verify.add_argument("--plan", required=True)
    verify.add_argument("--preparation", required=True)
    verify.add_argument("--output")
    verify.add_argument("--staging-root", help="Workflow-bound staging for failure evidence")
    verify.add_argument("--gamever")
    diagnose = subparsers.add_parser("diagnose", help="Collect partial evidence after a failed workflow step")
    diagnose.add_argument("--repo-root", default=".")
    diagnose.add_argument("--plan", required=True)
    diagnose.add_argument("--staging-root", required=True)
    diagnose.add_argument("--gamever", required=True)
    diagnose.add_argument("--phase", choices=("prepare", "execute", "verify", "downstream"), required=True)
    diagnose.add_argument("--error", required=True)
    diagnose.add_argument("--error-file", help="Best-effort original prepare/verify error from an earlier safe bundle")
    for command in (prepare, verify, diagnose):
        command.add_argument("--diagnostics-dir", required=command is diagnose)
        command.add_argument("--plan-sha256", help="Workflow plan digest for diagnostic provenance")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "plan":
            result = build_trusted_artifact_plan(repo_root=args.repo_root, trusted_context=args.trusted_context)
            _atomic_write(Path(args.output), _canonical_json_bytes(result))
        elif args.command == "prepare":
            result = prepare_isolated_rebuild(
                repo_root=args.repo_root,
                plan=args.plan,
                staging_root=args.staging_root,
                game_version=args.gamever,
                diagnostic_plan_sha256=args.plan_sha256,
            )
        elif args.command == "diagnose":
            error = args.error
            if args.error_file:
                raw_error, read_error = read_artifact_bytes(Path(args.error_file))
                if raw_error is not None:
                    error = raw_error.decode("utf-8", errors="replace").rstrip("\n")
                elif read_error:
                    error += f"\nOriginal error file unavailable: {read_error}"
            collect_pr_failure_diagnostics(
                repo_root=Path(args.repo_root),
                plan=args.plan,
                staging_root=Path(args.staging_root),
                destination=Path(args.diagnostics_dir),
                error=error,
                phase=args.phase,
                game_version=args.gamever,
                plan_sha256=args.plan_sha256,
            )
            return 0
        else:
            result = validate_isolated_rebuild(
                repo_root=args.repo_root,
                plan=args.plan,
                preparation=args.preparation,
                diagnostic_game_version=args.gamever,
                diagnostic_plan_sha256=args.plan_sha256,
                diagnostic_staging_root=args.staging_root,
            )
            if args.output:
                _atomic_write(Path(args.output), _canonical_json_bytes(result))
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if args.command in {"prepare", "verify"} and args.diagnostics_dir:
            try:
                staging = Path(args.staging_root) if args.staging_root else _diagnostic_staging(args.preparation)
                collect_pr_failure_diagnostics(
                    repo_root=Path(args.repo_root),
                    plan=args.plan,
                    staging_root=staging,
                    destination=Path(args.diagnostics_dir),
                    error=f"Error: {exc}",
                    phase=args.command,
                    game_version=args.gamever,
                    plan_sha256=args.plan_sha256,
                )
            except Exception as diagnostic_error:
                print(f"Failure diagnostics unavailable: {diagnostic_error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

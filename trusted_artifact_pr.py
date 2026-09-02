#!/usr/bin/env python3
"""Plan and verify trusted, isolated source-artifact PR rebuilds."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from binary_lock import BinaryLockError, load_binary_lock_from_revision
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
from source_artifact_schema import SymbolArtifactError, canonical_symbol_yaml_bytes
from trusted_pr_context import (
    CUTOVER_MANIFEST_REPO_PATH,
    TRUSTED_FILE_PATHS,
    load_trusted_pr_context,
    validate_trusted_pr_context,
)


PLAN_SCHEMA_VERSION = 3
PREPARATION_SCHEMA_VERSION = 2
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
TRUST_ROOT_PATHS = frozenset(TRUSTED_FILE_PATHS) | frozenset(
    {
        "source_artifact_policy.yaml",
        "trusted_pr_context.py",
        "trusted_artifact_pr.py",
        "new_gamever_artifact.py",
        "gamever_baseline.py",
        "trusted_yaml.py",
        "binary_lock.py",
        "binary_hashing.py",
        "release_workflow_lib/errors.py",
        "release_workflow_lib/hashing.py",
        ".github/workflows/pr-self-runner.yml",
        ".github/workflows/source-artifact-required.yml",
        ".github/workflows/bootstrap-new-gamever-artifacts.yml",
        "pyproject.toml",
        "uv.lock",
    }
)
CUTOVER_DIGEST_EXCLUDED_PATHS = (CUTOVER_MANIFEST_REPO_PATH, "source_artifact_policy.yaml")


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


def _repository_tree_digest(repo: GitTreeRepository, revision: str) -> str:
    excluded = set(CUTOVER_DIGEST_EXCLUDED_PATHS)
    inventory = [
        {
            "mode": entry.mode,
            "object_type": entry.object_type,
            "object_sha": entry.object_sha,
            "path": entry.path,
        }
        for entry in repo.entries(revision)
        if entry.path not in excluded
    ]
    return _digest("approved-source-owned-cutover-tree", inventory)


def _approved_cutover_tree_digest(repo: GitTreeRepository, base_revision: str) -> str:
    try:
        raw = repo.read(base_revision, CUTOVER_MANIFEST_REPO_PATH)
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, TrustedArtifactPrError) as exc:
        raise TrustedArtifactPrError(f"trusted source-owned cutover manifest is invalid: {exc}") from exc
    if raw != _canonical_json_bytes(document):
        raise TrustedArtifactPrError("trusted source-owned cutover manifest is not canonical JSON")
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "excluded_paths", "prospective_tree_sha256"}
        or document.get("schema_version") != 1
        or document.get("excluded_paths") != list(CUTOVER_DIGEST_EXCLUDED_PATHS)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(document.get("prospective_tree_sha256", "")))
    ):
        raise TrustedArtifactPrError("trusted source-owned cutover manifest fields are invalid")
    return document["prospective_tree_sha256"]


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
    for key in sorted(relative_entries):
        raw = repo.read(revision, f"bin_artifacts/{gamever}/{key}")
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
    items = []
    for entry in repo.entries(revision):
        if entry.object_type != "blob":
            continue
        if _is_shared_analysis_runtime_path(entry.path) or entry.path.startswith(SOURCE_PREFIXES):
            raw = repo.read(revision, entry.path)
            items.append({"path": entry.path, "size": len(raw), "sha256": _sha256(raw)})
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


def _selected_groups(contract, plan) -> tuple[set[str], set[str]]:
    selected_groups = {
        contract.producer_group_ids_by_path[path] for path in plan.paths if path in contract.producer_group_ids_by_path
    }
    for node_id in plan.node_ids:
        for group_id, group in contract.producer_groups.items():
            if node_id in group.alternative_node_ids:
                selected_groups.add(group_id)
    while True:
        expanded = set(contract.downstream_group_ids(selected_groups))
        selected_nodes = {
            node_id for group_id in expanded for node_id in contract.producer_groups[group_id].alternative_node_ids
        }
        expanded.update(
            contract.producer_group_ids_by_path[path]
            for node_id in selected_nodes
            for path in contract.nodes[node_id].outputs
            if path in contract.producer_group_ids_by_path
        )
        if expanded == selected_groups:
            return expanded, selected_nodes
        selected_groups = expanded


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
    cutover_transition = context.get("cutover_transition") is True
    if context["artifact_policy"]["mode"] != "source-owned" and not cutover_transition:
        raise TrustedArtifactPrError("trusted source-artifact planner is not enabled by the base policy")
    if cutover_transition and (
        context["artifact_policy"]["mode"] != "bridge" or context["merge_artifact_policy"]["mode"] != "source-owned"
    ):
        raise TrustedArtifactPrError("trusted source-artifact cutover transition is invalid")
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
    cutover_tree_sha256 = None
    if cutover_transition:
        approved_cutover_tree_sha256 = _approved_cutover_tree_digest(repo, context["base_sha"])
        cutover_tree_sha256 = _repository_tree_digest(repo, context["merge_sha"])
        if cutover_tree_sha256 != approved_cutover_tree_sha256:
            raise TrustedArtifactPrError(
                "prospective source-owned cutover tree is not the exact base-approved repository inventory"
            )
    if cutover_transition and base_versions != merge_versions:
        raise TrustedArtifactPrError("source-owned cutover must preserve the configured GAMEVER set")
    if not cutover_transition:
        _validate_repository_tree_namespaces(repo, context["base_sha"], base_versions)
    _validate_repository_tree_namespaces(repo, context["merge_sha"], merge_versions)
    changes = repo.changes(context["base_sha"], context["merge_sha"])
    changed_trust_roots = sorted(
        {path for change in changes for path in (change.old_path, change.new_path) if path in TRUST_ROOT_PATHS}
    )
    if changed_trust_roots and not cutover_transition:
        raise TrustedArtifactPrError(
            "trusted validation roots require an independently merged bridge update:\n"
            + "\n".join(f"  {path}" for path in changed_trust_roots)
        )
    base_downloads = _download_identities(repo, context["base_sha"])
    merge_downloads = _download_identities(repo, context["merge_sha"])
    needs_base_sources, needs_merge_sources = required_source_index_sides(list(changes))
    base_sources = _revision_python_sources(repo, context["base_sha"]) if needs_base_sources else {}
    merge_sources = _revision_python_sources(repo, context["merge_sha"]) if needs_merge_sources else {}
    shared_analysis_changed = any(
        _is_shared_analysis_runtime_path(path)
        for change in changes
        for path in (change.old_path, change.new_path)
        if path
    )

    version_reports = []
    with tempfile.TemporaryDirectory(prefix="trusted-artifact-plan-") as temporary:
        temporary_root = Path(temporary)
        for gamever in sorted(set(base_versions) | set(merge_versions)):
            base_contract = base_config = None
            base_files = {}
            base_inventory = None
            base_binary_lock = None
            if gamever in base_versions and not cutover_transition:
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
            if cutover_transition and merge_contract is not None:
                selected_group_ids = set(merge_contract.producer_groups)
                selected_node_ids = {
                    node_id
                    for group in merge_contract.producer_groups.values()
                    for node_id in group.alternative_node_ids
                }
                invalidated_paths.update(merge_contract.formal_paths)
                reasons.append("atomic legacy-to-source-owned cutover")
            elif merge_contract is not None and base_contract is not None:
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
                selected_group_ids, selected_node_ids = _selected_groups(merge_contract, invalidation)
                invalidated_paths.update(
                    merge_contract.producer_groups[group_id].artifact_path for group_id in selected_group_ids
                )
                invalidated_paths.update(path for path in invalidation.paths if path not in merge_contract.formal_paths)
                reasons.extend(invalidation.reasons)
            elif merge_contract is not None:
                selected_group_ids = set(merge_contract.producer_groups)
                selected_node_ids = {
                    node_id
                    for group in merge_contract.producer_groups.values()
                    for node_id in group.alternative_node_ids
                }
                invalidated_paths.update(merge_contract.formal_paths)
                reasons.append("new configured GAMEVER")
            elif base_contract is not None:
                invalidated_paths.update(base_contract.formal_paths)
                reasons.append("configured GAMEVER removed")

            if shared_analysis_changed and merge_contract is not None and not cutover_transition:
                selected_group_ids = set(merge_contract.producer_groups)
                selected_node_ids = {
                    node_id
                    for group in merge_contract.producer_groups.values()
                    for node_id in group.alternative_node_ids
                }
                invalidated_paths.update(merge_contract.formal_paths)
                reasons.append("shared analyzer/serializer contract changed")

            binary_identity_changed = base_downloads.get(gamever) != merge_downloads.get(gamever) or (
                base_binary_lock.sha256 if base_binary_lock else None
            ) != (merge_binary_lock.sha256 if merge_binary_lock else None)
            if merge_contract is not None and binary_identity_changed and not cutover_transition:
                selected_group_ids = set(merge_contract.producer_groups)
                selected_node_ids = {
                    node_id
                    for group in merge_contract.producer_groups.values()
                    for node_id in group.alternative_node_ids
                }
                invalidated_paths.update(merge_contract.formal_paths)
                reasons.append("download/binary identity changed")

            artifact_changes = [
                change
                for change in changes
                if any(
                    path and path.startswith(f"bin_artifacts/{gamever}/") for path in (change.old_path, change.new_path)
                )
            ]
            if artifact_changes and not invalidated_paths:
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
                    "affected_producer_groups": groups,
                    "selected_alternative_nodes": nodes,
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
        "full"
        if cutover_transition
        else (
            "bootstrap_required"
            if any(report["bootstrap_required"] for report in version_reports)
            else ("full" if affected_versions else "light")
        )
    )
    download_raw = repo.read(context["merge_sha"], "download.yaml")
    document = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "event_kind": context["event_kind"],
        "cutover_transition": cutover_transition,
        "cutover_tree_sha256": cutover_tree_sha256,
        "mode": mode,
        "base_sha": context["base_sha"],
        "head_sha": context["head_sha"],
        "merge_sha": context["merge_sha"],
        "merge_tree_sha": context["merge_tree_sha"],
        "trusted_context_sha256": context["context_sha256"],
        "configured_game_versions": list(merge_versions),
        "affected_game_versions": affected_versions,
        "download_sha256": _sha256(download_raw),
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
    cutover_transition = document.get("cutover_transition")
    cutover_tree_sha256 = document.get("cutover_tree_sha256")
    if not isinstance(cutover_transition, bool) or (
        cutover_transition and not re.fullmatch(r"sha256:[0-9a-f]{64}", str(cutover_tree_sha256 or ""))
    ):
        raise TrustedArtifactPrError("trusted artifact plan cutover identity is invalid")
    if not cutover_transition and cutover_tree_sha256 is not None:
        raise TrustedArtifactPrError("non-cutover trusted artifact plan carries a cutover tree identity")
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


def prepare_isolated_rebuild(
    *,
    repo_root: str | Path,
    plan: dict | str | Path,
    staging_root: str | Path,
    game_version: str | None = None,
) -> dict:
    plan = load_trusted_artifact_plan(plan) if isinstance(plan, (str, Path)) else validate_trusted_artifact_plan(plan)
    if plan["mode"] != "full":
        raise TrustedArtifactPrError(f"isolated rebuild requires a full plan, got {plan['mode']}")
    repo = GitTreeRepository(repo_root)
    if repo.tree_sha(plan["merge_sha"]) != plan["merge_tree_sha"]:
        raise TrustedArtifactPrError("prospective merge tree drifted before isolated rebuild preparation")
    staging_root = Path(os.path.abspath(staging_root))
    try:
        staging_root.relative_to(repo.root)
    except ValueError:
        pass
    else:
        raise TrustedArtifactPrError("isolated rebuild staging root must be outside the source checkout")
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
    for version in plan["game_versions"]:
        if not version["invalidated_paths"] or version["merge_artifacts"] is None:
            continue
        gamever = version["game_version"]
        if game_version is not None and gamever != str(game_version):
            continue
        _atomic_write(config_root / f"{gamever}.yaml", repo.read(plan["merge_sha"], f"configs/{gamever}.yaml"))
        for item in version["merge_artifacts"]["files"]:
            prefix = f"bin_artifacts/{gamever}/"
            key = item["path"].removeprefix(prefix)
            if key == item["path"]:
                raise TrustedArtifactPrError(f"plan contains an artifact outside GAMEVER {gamever}: {item['path']}")
            raw = repo.read(plan["merge_sha"], item["path"])
            if len(raw) != item["size"] or _sha256(raw) != item["sha256"]:
                raise TrustedArtifactPrError(f"prospective merge artifact drifted: {item['path']}")
            expected_path = expected_root / gamever / key
            _atomic_write(expected_path, raw)
        prepared_versions.append(gamever)
    if game_version is not None and prepared_versions != [str(game_version)]:
        raise TrustedArtifactPrError(f"GAMEVER is not an affected full-plan target: {game_version}")

    report = {
        "schema_version": PREPARATION_SCHEMA_VERSION,
        "plan_sha256": plan["plan_sha256"],
        "merge_sha": plan["merge_sha"],
        "merge_tree_sha": plan["merge_tree_sha"],
        "staging_root": str(staging_root),
        "expected_artifact_root": str(expected_root),
        "actual_artifact_root": str(actual_root),
        "config_root": str(config_root),
        "binary_root": str(repo.root / "bin"),
        "execution_reports": {
            gamever: str(execution_root / f"{gamever}.force-all.json") for gamever in prepared_versions
        },
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
    for planned in version["affected_producer_groups"]:
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


def validate_isolated_rebuild(
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

    repo_root = Path(repo_root).resolve()
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
                f"expected={sorted(expected_items)!r} actual={sorted(actual_items)!r}"
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
            raise TrustedArtifactPrError(f"force-all inventory evidence drifted for {gamever}")
        reports.append(
            {
                "game_version": gamever,
                "file_count": actual.file_count,
                "inventory_sha256": version["merge_artifacts"]["inventory_sha256"],
                "execution_sha256": execution["execution_sha256"],
            }
        )
    result = {
        "schema_version": 1,
        "plan_sha256": plan["plan_sha256"],
        "preparation_sha256": preparation["preparation_sha256"],
        "game_versions": reports,
    }
    result["validation_sha256"] = _digest("isolated-validation", result)
    return result


def validate_exported_isolated_rebuild(
    *,
    repo_root: str | Path,
    plan: dict | str | Path,
    staging_root: str | Path,
    game_version: str,
    actual_artifact_root: str | Path,
    execution_report: str | Path,
) -> dict:
    """Re-home untrusted builder evidence and verify it with fresh base-owned tools."""
    plan = load_trusted_artifact_plan(plan) if isinstance(plan, (str, Path)) else validate_trusted_artifact_plan(plan)
    preparation = prepare_isolated_rebuild(
        repo_root=repo_root,
        plan=plan,
        staging_root=staging_root,
        game_version=game_version,
    )
    exported_root = Path(actual_artifact_root).resolve()
    if not exported_root.is_dir():
        raise TrustedArtifactPrError(f"exported actual artifact root is missing: {exported_root}")
    shutil.copytree(exported_root, preparation["actual_artifact_root"], dirs_exist_ok=True)

    exported_report = Path(execution_report)
    try:
        raw = exported_report.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TrustedArtifactPrError(f"unable to load exported execution report: {exc}") from exc
    if raw != _canonical_json_bytes(document):
        raise TrustedArtifactPrError("exported execution report is not canonical JSON")
    digest = document.get("execution_sha256")
    unsigned = dict(document)
    unsigned.pop("execution_sha256", None)
    digest_payload = b"source2-force-all-execution:v2\n" + _canonical_json_bytes(unsigned)
    if digest != f"sha256:{hashlib.sha256(digest_payload).hexdigest()}":
        raise TrustedArtifactPrError("exported execution report digest mismatch")

    document["artifact_root"] = preparation["actual_artifact_root"]
    document["binary_root"] = preparation["binary_root"]
    document["config_path"] = str(Path(preparation["config_root"]) / f"{game_version}.yaml")
    unsigned = dict(document)
    unsigned.pop("execution_sha256", None)
    document["execution_sha256"] = (
        "sha256:" + hashlib.sha256(b"source2-force-all-execution:v2\n" + _canonical_json_bytes(unsigned)).hexdigest()
    )
    normalized_report = Path(preparation["execution_reports"][str(game_version)])
    _atomic_write(normalized_report, _canonical_json_bytes(document))
    return validate_isolated_rebuild(repo_root=repo_root, plan=plan, preparation=preparation)


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
    exported = subparsers.add_parser("verify-exported")
    exported.add_argument("--repo-root", default=".")
    exported.add_argument("--plan", required=True)
    exported.add_argument("--staging-root", required=True)
    exported.add_argument("--gamever", required=True)
    exported.add_argument("--actual-root", required=True)
    exported.add_argument("--execution-report", required=True)
    exported.add_argument("--output")
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
            )
        elif args.command == "verify":
            result = validate_isolated_rebuild(
                repo_root=args.repo_root,
                plan=args.plan,
                preparation=args.preparation,
            )
            if args.output:
                _atomic_write(Path(args.output), _canonical_json_bytes(result))
        else:
            result = validate_exported_isolated_rebuild(
                repo_root=args.repo_root,
                plan=args.plan,
                staging_root=args.staging_root,
                game_version=args.gamever,
                actual_artifact_root=args.actual_root,
                execution_report=args.execution_report,
            )
            if args.output:
                _atomic_write(Path(args.output), _canonical_json_bytes(result))
    except (OSError, UnicodeError, yaml.YAMLError, TrustedArtifactPrError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

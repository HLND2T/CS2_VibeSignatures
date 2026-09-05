#!/usr/bin/env python3
"""Build, verify, and commit a new-GAMEVER source-artifact bootstrap candidate."""

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
from pathlib import Path

import yaml

from bin_artifact_contract import ArtifactContractError, build_game_artifact_inventory
from gamesymbol_snapshot_lib.paths import is_reparse_point
from trusted_artifact_pr import load_trusted_artifact_plan, validate_trusted_artifact_plan


BOOTSTRAP_CANDIDATE_SCHEMA_VERSION = 3
ALLOWED_REPOSITORY = "HLND2T/CS2_VibeSignatures"
GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$|^[1-9][0-9]*$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class NewGameverArtifactError(RuntimeError):
    """The new-GAMEVER artifact bootstrap or publication contract failed closed."""


def _canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def _digest(label: str, value: object) -> str:
    raw = f"source-artifact-bootstrap-{label}:v1\n".encode() + _canonical_json_bytes(value)
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


def _git(repo_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode:
        raise NewGameverArtifactError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def _bootstrap_version(plan: dict) -> dict:
    if plan.get("event_kind") != "pull_request" or plan.get("mode") != "bootstrap_required":
        raise NewGameverArtifactError("candidate requires a pull_request bootstrap_required plan")
    versions = [version for version in plan["game_versions"] if version.get("bootstrap_required")]
    if len(versions) != 1:
        raise NewGameverArtifactError("bootstrap publication requires exactly one new GAMEVER")
    version = versions[0]
    gamever = str(version["game_version"])
    if not GAMEVER_RE.fullmatch(gamever):
        raise NewGameverArtifactError(f"invalid bootstrap GAMEVER: {gamever!r}")
    if "prior_gamever" not in version or (
        version["prior_gamever"] is not None and not GAMEVER_RE.fullmatch(str(version["prior_gamever"]))
    ):
        raise NewGameverArtifactError("trusted bootstrap plan has an invalid prior GAMEVER binding")
    return version


def _download_has_gamever(repo_root: Path, gamever: str) -> None:
    try:
        document = yaml.safe_load((repo_root / "download.yaml").read_bytes()) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise NewGameverArtifactError(f"unable to read download.yaml: {exc}") from exc
    downloads = document.get("downloads", []) if isinstance(document, dict) else []
    matches = [item for item in downloads if isinstance(item, dict) and str(item.get("tag")) == gamever]
    if len(matches) != 1:
        raise NewGameverArtifactError(f"download.yaml must contain exactly one entry for GAMEVER {gamever}")


def _inventory_document(report) -> tuple[list[dict], str]:
    files = [item.to_dict() for item in report.files]
    return files, _digest("candidate-inventory", files)


def _load_gate_evidence(value: dict | str | Path) -> dict:
    if isinstance(value, (str, Path)):
        try:
            value = json.loads(Path(value).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise NewGameverArtifactError(f"unable to load bootstrap gate evidence: {exc}") from exc
    expected_keys = {
        "schema_version",
        "binsync_mode",
        "remote_refs_before_sha256",
        "remote_refs_after_sha256",
        "snapshot_sha256",
        "gamedata_sha256",
        "cpp_validation_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected_keys or value.get("schema_version") != 2:
        raise NewGameverArtifactError("bootstrap gate evidence schema is invalid")
    if value.get("binsync_mode") != "local-only":
        raise NewGameverArtifactError("bootstrap BinSync evidence must be local-only")
    digest_fields = (
        "remote_refs_before_sha256",
        "remote_refs_after_sha256",
        "snapshot_sha256",
        "gamedata_sha256",
        "cpp_validation_sha256",
    )
    if any(not DIGEST_RE.fullmatch(str(value.get(field, ""))) for field in digest_fields):
        raise NewGameverArtifactError("bootstrap gate evidence contains an invalid digest")
    if value["remote_refs_before_sha256"] != value["remote_refs_after_sha256"]:
        raise NewGameverArtifactError("bootstrap build changed remote BinSync refs")
    return value


def _load_force_all_execution_report(value: dict | str | Path) -> dict:
    if isinstance(value, (str, Path)):
        try:
            raw = Path(value).read_bytes()
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise NewGameverArtifactError(f"unable to load bootstrap force-all execution report: {exc}") from exc
        if raw != _canonical_json_bytes(value):
            raise NewGameverArtifactError("bootstrap force-all execution report is not canonical JSON")
    if not isinstance(value, dict):
        raise NewGameverArtifactError("bootstrap force-all execution report schema is invalid")
    digest = value.get("execution_sha256")
    unsigned = dict(value)
    unsigned.pop("execution_sha256", None)
    digest_input = b"source2-force-all-execution:v2\n" + _canonical_json_bytes(unsigned)
    if digest != f"sha256:{hashlib.sha256(digest_input).hexdigest()}":
        raise NewGameverArtifactError("bootstrap force-all execution report digest mismatch")
    return value


def _validate_force_all_execution_report(*, value: dict | str | Path, version: dict, artifact_report) -> dict:
    report = _load_force_all_execution_report(value)
    gamever = str(version["game_version"])
    if "prior_gamever" not in report or report.get("prior_gamever") != version["prior_gamever"]:
        raise NewGameverArtifactError("bootstrap force-all execution prior GAMEVER differs from the trusted plan")
    if (
        report.get("schema_version") != 2
        or report.get("valid") is not True
        or report.get("force_all") is not True
        or report.get("rename") is not True
        or report.get("required_warm_idb") is not True
        or report.get("game_version") != gamever
        or report.get("issues") != []
    ):
        raise NewGameverArtifactError("bootstrap force-all execution must prove a valid full warm-IDB run with rename")
    expected_inventory = {
        "file_count": artifact_report.file_count,
        "inventory_sha256": artifact_report.inventory_sha256,
    }
    if report.get("inventory") != expected_inventory:
        raise NewGameverArtifactError("bootstrap force-all execution inventory differs from candidate artifacts")

    planned_groups = version.get("affected_producer_groups")
    planned_nodes = version.get("selected_alternative_nodes")
    if not isinstance(planned_groups, list) or not isinstance(planned_nodes, list):
        raise NewGameverArtifactError("trusted bootstrap plan has no complete producer execution contract")
    group_records = report.get("producer_groups")
    node_records = report.get("nodes")
    if not isinstance(group_records, list) or not isinstance(node_records, list):
        raise NewGameverArtifactError("bootstrap force-all execution has no group/node evidence")
    groups_by_id = {
        record.get("group_id"): record
        for record in group_records
        if isinstance(record, dict) and isinstance(record.get("group_id"), str)
    }
    nodes_by_id = {
        record.get("node_id"): record
        for record in node_records
        if isinstance(record, dict) and isinstance(record.get("node_id"), str)
    }
    planned_groups_by_id = {group["group_id"]: group for group in planned_groups}
    planned_nodes_by_id = {node["node_id"]: node for node in planned_nodes}
    if (
        len(groups_by_id) != len(group_records)
        or set(groups_by_id) != set(planned_groups_by_id)
        or len(nodes_by_id) != len(node_records)
        or set(nodes_by_id) != set(planned_nodes_by_id)
    ):
        raise NewGameverArtifactError("bootstrap force-all execution does not cover every planned group and node")

    expected_files = {item.path.removeprefix(f"bin_artifacts/{gamever}/"): item for item in artifact_report.files}
    attempted_node_ids: set[str] = set()
    winning_paths_by_node: dict[str, list[str]] = {node_id: [] for node_id in planned_nodes_by_id}
    for group_id, planned in planned_groups_by_id.items():
        record = groups_by_id[group_id]
        alternatives = planned["alternative_node_ids"]
        attempted = record.get("attempted_node_ids")
        winner = record.get("winner_node_id")
        expected_file = expected_files.get(planned["artifact_path"])
        expected_sha256 = expected_file.sha256 if expected_file is not None else None
        if (
            record.get("artifact_path") != planned["artifact_path"]
            or record.get("required") != planned["required"]
            or record.get("fingerprint") != planned["fingerprint"]
            or record.get("alternative_node_ids") != alternatives
            or record.get("output_sha256") != expected_sha256
            or not isinstance(attempted, list)
            or len(attempted) != len(set(attempted))
            or any(node_id not in alternatives for node_id in attempted)
        ):
            raise NewGameverArtifactError(f"bootstrap producer-group execution drifted from plan: {group_id}")
        if expected_file is not None:
            if winner not in alternatives or winner not in attempted:
                raise NewGameverArtifactError(f"bootstrap producer group has no executed winner: {group_id}")
            winner_index = alternatives.index(winner)
            if attempted != alternatives[: winner_index + 1]:
                raise NewGameverArtifactError(f"bootstrap producer-group attempt order is invalid: {group_id}")
            winning_paths_by_node[winner].append(planned["artifact_path"])
        elif winner is not None or attempted != alternatives:
            raise NewGameverArtifactError(f"bootstrap absent optional producer-group evidence is invalid: {group_id}")
        attempted_node_ids.update(attempted)

    for node_id, planned in planned_nodes_by_id.items():
        record = nodes_by_id[node_id]
        produced_paths = sorted(winning_paths_by_node[node_id])
        attempted = node_id in attempted_node_ids
        if (
            record.get("module") != planned["module"]
            or record.get("platform") != planned["platform"]
            or record.get("skill") != planned["skill"]
            or record.get("fingerprint") != planned["fingerprint"]
            or record.get("attempted") is not attempted
            or record.get("produced_paths") != produced_paths
            or (produced_paths and record.get("status") != "succeeded")
            or (not attempted and record.get("status") != "skipped")
        ):
            raise NewGameverArtifactError(f"bootstrap producer-node execution drifted from plan: {node_id}")
    return report


def build_bootstrap_candidate(
    *,
    repo_root: str | Path,
    plan: dict | str | Path,
    artifact_root: str | Path,
    output_manifest: str | Path,
    repository: str,
    pr_number: int,
    workflow_run_id: str,
    workflow_run_attempt: str,
    gate_evidence: dict | str | Path,
    execution_report: dict | str | Path,
) -> dict:
    plan = load_trusted_artifact_plan(plan) if isinstance(plan, (str, Path)) else validate_trusted_artifact_plan(plan)
    version = _bootstrap_version(plan)
    if repository != ALLOWED_REPOSITORY:
        raise NewGameverArtifactError(f"bootstrap repository is not allowlisted: {repository}")
    if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number < 1:
        raise NewGameverArtifactError("bootstrap PR number must be a positive integer")
    repo_root = Path(repo_root).resolve()
    if _git(repo_root, "rev-parse", "HEAD").lower() != plan["merge_sha"]:
        raise NewGameverArtifactError("bootstrap build checkout does not match the bound prospective merge SHA")
    gamever = version["game_version"]
    _download_has_gamever(repo_root, gamever)
    try:
        report = build_game_artifact_inventory(
            repo_root=repo_root,
            config_path=repo_root / "configs" / f"{gamever}.yaml",
            game_version=gamever,
            artifact_root=artifact_root,
            require_tracked=False,
        )
    except ArtifactContractError as exc:
        raise NewGameverArtifactError(f"bootstrap candidate contract failed: {exc}") from exc
    files, inventory_sha256 = _inventory_document(report)
    gates = _load_gate_evidence(gate_evidence)
    execution = _validate_force_all_execution_report(
        value=execution_report,
        version=version,
        artifact_report=report,
    )
    if report.required_count != version["merge_artifacts"]["required_count"]:
        raise NewGameverArtifactError("bootstrap candidate formal required count drifted from the trusted plan")
    if report.file_count < report.required_count:
        raise NewGameverArtifactError("bootstrap candidate is missing required artifacts")
    artifact_name = f"new-gamever-artifacts-{pr_number}-{gamever}-{workflow_run_id}-{workflow_run_attempt}"
    document = {
        "schema_version": BOOTSTRAP_CANDIDATE_SCHEMA_VERSION,
        "repository": repository,
        "pull_request_number": pr_number,
        "game_version": gamever,
        "prior_gamever": version["prior_gamever"],
        "head_sha": plan["head_sha"],
        "prospective_merge_sha": plan["merge_sha"],
        "prospective_merge_tree_sha": plan["merge_tree_sha"],
        "plan_sha256": plan["plan_sha256"],
        "config_sha256": version["merge_config_sha256"],
        "workflow_run_id": str(workflow_run_id),
        "workflow_run_attempt": str(workflow_run_attempt),
        "actions_artifact_name": artifact_name,
        "file_count": len(files),
        "artifact_inventory_sha256": inventory_sha256,
        "execution_sha256": execution["execution_sha256"],
        "files": files,
        "gates": gates,
    }
    document["candidate_sha256"] = _digest("candidate-manifest", document)
    _atomic_write(Path(output_manifest), _canonical_json_bytes(document))
    return document


def load_bootstrap_candidate(path: str | Path) -> dict:
    path = Path(path)
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NewGameverArtifactError(f"unable to load bootstrap candidate manifest: {exc}") from exc
    if raw != _canonical_json_bytes(document):
        raise NewGameverArtifactError("bootstrap candidate manifest is not canonical JSON")
    if not isinstance(document, dict) or document.get("schema_version") != BOOTSTRAP_CANDIDATE_SCHEMA_VERSION:
        raise NewGameverArtifactError("bootstrap candidate manifest schema is invalid")
    digest = document.get("candidate_sha256")
    unsigned = dict(document)
    unsigned.pop("candidate_sha256", None)
    if digest != _digest("candidate-manifest", unsigned):
        raise NewGameverArtifactError("bootstrap candidate manifest digest mismatch")
    return document


def verify_bootstrap_candidate(
    *,
    repo_root: str | Path,
    plan: dict | str | Path,
    artifact_root: str | Path,
    manifest: dict | str | Path,
    repository: str,
    default_branch: str,
    base_repository: str,
    base_ref: str,
    base_sha: str,
    head_repository: str,
    head_ref: str,
    head_sha: str,
    current_remote_head: str,
    pr_number: int,
    actions_artifact_name: str,
    actions_artifact_digest: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    execution_report: dict | str | Path,
) -> dict:
    plan = load_trusted_artifact_plan(plan) if isinstance(plan, (str, Path)) else validate_trusted_artifact_plan(plan)
    manifest = load_bootstrap_candidate(manifest) if isinstance(manifest, (str, Path)) else manifest
    version = _bootstrap_version(plan)
    gamever = version["game_version"]
    expected_ref = f"bump-download/{gamever}"
    if repository != ALLOWED_REPOSITORY or manifest.get("repository") != repository:
        raise NewGameverArtifactError("bootstrap publisher repository is not allowlisted")
    if head_repository != repository:
        raise NewGameverArtifactError("bootstrap publisher only accepts a same-repository PR")
    if default_branch not in {"main", "master"}:
        raise NewGameverArtifactError(f"unexpected default branch: {default_branch!r}")
    if (
        base_repository != repository
        or base_ref != default_branch
        or base_sha != plan["base_sha"]
        or not SHA_RE.fullmatch(base_sha)
    ):
        raise NewGameverArtifactError("bootstrap publisher base is not the bound default branch SHA")
    if head_ref != expected_ref:
        raise NewGameverArtifactError(f"bootstrap publisher head ref must be {expected_ref}")
    if (
        head_sha != plan["head_sha"]
        or current_remote_head != head_sha
        or manifest.get("head_sha") != head_sha
        or not SHA_RE.fullmatch(head_sha)
    ):
        raise NewGameverArtifactError("bootstrap publisher remote head drifted from the bound head SHA")
    if pr_number != manifest.get("pull_request_number") or not isinstance(pr_number, int) or pr_number < 1:
        raise NewGameverArtifactError("bootstrap publisher PR identity mismatch")
    if (
        manifest.get("plan_sha256") != plan["plan_sha256"]
        or manifest.get("game_version") != gamever
        or "prior_gamever" not in manifest
        or manifest.get("prior_gamever") != version["prior_gamever"]
    ):
        raise NewGameverArtifactError("bootstrap candidate plan or GAMEVER binding mismatch")
    if (
        manifest.get("prospective_merge_sha") != plan["merge_sha"]
        or manifest.get("prospective_merge_tree_sha") != plan["merge_tree_sha"]
        or manifest.get("config_sha256") != version["merge_config_sha256"]
    ):
        raise NewGameverArtifactError("bootstrap candidate prospective merge/config binding mismatch")
    if manifest.get("workflow_run_id") != str(workflow_run_id) or manifest.get("workflow_run_attempt") != str(
        workflow_run_attempt
    ):
        raise NewGameverArtifactError("bootstrap candidate workflow run identity mismatch")
    if actions_artifact_name != manifest.get("actions_artifact_name"):
        raise NewGameverArtifactError("downloaded Actions Artifact name mismatch")
    if not DIGEST_RE.fullmatch(actions_artifact_digest):
        raise NewGameverArtifactError("downloaded Actions Artifact digest is invalid")
    if _load_gate_evidence(manifest.get("gates")) != manifest.get("gates"):
        raise NewGameverArtifactError("bootstrap candidate required gate evidence is incomplete")

    repo_root = Path(repo_root).resolve()
    if _git(repo_root, "rev-parse", "HEAD").lower() != plan["merge_sha"]:
        raise NewGameverArtifactError("hosted verifier checkout does not match the bound prospective merge SHA")
    _download_has_gamever(repo_root, gamever)
    try:
        report = build_game_artifact_inventory(
            repo_root=repo_root,
            config_path=repo_root / "configs" / f"{gamever}.yaml",
            game_version=gamever,
            artifact_root=artifact_root,
            require_tracked=False,
        )
    except ArtifactContractError as exc:
        raise NewGameverArtifactError(f"hosted bootstrap candidate verification failed: {exc}") from exc
    files, inventory_sha256 = _inventory_document(report)
    if (
        files != manifest.get("files")
        or inventory_sha256 != manifest.get("artifact_inventory_sha256")
        or len(files) != manifest.get("file_count")
        or report.required_count != version["merge_artifacts"]["required_count"]
    ):
        raise NewGameverArtifactError("bootstrap candidate inventory differs from its bound manifest or plan")
    execution = _validate_force_all_execution_report(
        value=execution_report,
        version=version,
        artifact_report=report,
    )
    if manifest.get("execution_sha256") != execution["execution_sha256"]:
        raise NewGameverArtifactError("bootstrap execution report differs from its bound candidate manifest")
    return {
        "schema_version": 1,
        "repository": repository,
        "pull_request_number": pr_number,
        "game_version": gamever,
        "prior_gamever": version["prior_gamever"],
        "base_ref": base_ref,
        "base_sha": base_sha,
        "head_ref": head_ref,
        "head_sha": head_sha,
        "candidate_sha256": manifest["candidate_sha256"],
        "artifact_inventory_sha256": inventory_sha256,
        "execution_sha256": execution["execution_sha256"],
        "actions_artifact_name": actions_artifact_name,
        "actions_artifact_digest": actions_artifact_digest,
    }


def _ensure_clean_checkout(repo_root: Path, expected_head: str) -> None:
    if _git(repo_root, "rev-parse", "HEAD").lower() != expected_head:
        raise NewGameverArtifactError("publication checkout does not match the bound PR head")
    if _git(repo_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise NewGameverArtifactError("publication checkout must be clean before applying candidate artifacts")


def prepare_bootstrap_commit(
    *,
    repo_root: str | Path,
    artifact_root: str | Path,
    verification: dict,
    workflow_run_url: str,
) -> dict:
    repo_root = Path(repo_root).resolve()
    gamever = str(verification.get("game_version", ""))
    head_sha = str(verification.get("head_sha", ""))
    if not GAMEVER_RE.fullmatch(gamever) or not SHA_RE.fullmatch(head_sha):
        raise NewGameverArtifactError("publication verification identity is invalid")
    if verification.get("repository") != ALLOWED_REPOSITORY:
        raise NewGameverArtifactError("publication verification repository is not allowlisted")
    if not DIGEST_RE.fullmatch(str(verification.get("execution_sha256", ""))):
        raise NewGameverArtifactError("publication verification execution digest is invalid")
    _ensure_clean_checkout(repo_root, head_sha)
    candidate_root = Path(artifact_root).resolve() / gamever
    if not candidate_root.is_dir() or is_reparse_point(candidate_root):
        raise NewGameverArtifactError(f"candidate artifact GAMEVER root is missing or linked: {candidate_root}")
    destination = repo_root / "bin_artifacts" / gamever
    if destination.exists() and is_reparse_point(destination):
        raise NewGameverArtifactError(f"publication destination must not be a link/reparse point: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    candidate_files = []
    for source in sorted(candidate_root.rglob("*")):
        if source.is_dir():
            continue
        if is_reparse_point(source) or source.suffix.lower() != ".yaml":
            raise NewGameverArtifactError(f"candidate contains an invalid publication file: {source}")
        relative = source.relative_to(candidate_root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        candidate_files.append(f"bin_artifacts/{gamever}/{relative.as_posix()}")
    for target in sorted(destination.rglob("*"), reverse=True):
        if target.is_file() and target.relative_to(repo_root).as_posix() not in candidate_files:
            target.unlink()
        elif target.is_dir() and not any(target.iterdir()):
            target.rmdir()

    _git(repo_root, "add", "-A", "--", f"bin_artifacts/{gamever}")
    staged = set(filter(None, _git(repo_root, "diff", "--cached", "--name-only", "--").splitlines()))
    tracked_after = set(
        filter(None, _git(repo_root, "ls-files", "--cached", "--", f"bin_artifacts/{gamever}").splitlines())
    )
    allowed_prefix = f"bin_artifacts/{gamever}/"
    if (
        not staged
        or any(not path.startswith(allowed_prefix) for path in staged)
        or tracked_after != set(candidate_files)
    ):
        raise NewGameverArtifactError(
            "bootstrap commit changed-path allowlist or final inventory mismatch: "
            f"staged={sorted(staged)!r} tracked={sorted(tracked_after)!r} expected={sorted(candidate_files)!r}"
        )
    subject = f"feat(artifacts): bootstrap {gamever}"
    body = "\n".join(
        (
            f"Source-Head-SHA: {head_sha}",
            f"Game-Version: {gamever}",
            f"Prior-Game-Version: {verification.get('prior_gamever') or 'none'}",
            f"Artifact-Inventory-SHA256: {verification['artifact_inventory_sha256']}",
            f"Force-All-Execution-SHA256: {verification['execution_sha256']}",
            f"Actions-Artifact-Digest: {verification['actions_artifact_digest']}",
            f"Workflow-Run: {workflow_run_url}",
            "Co-Authored-By: Codex <codex@openai.com>",
        )
    )
    _git(repo_root, "commit", "-m", subject, "-m", body)
    commit_sha = _git(repo_root, "rev-parse", "HEAD").lower()
    parent_sha = _git(repo_root, "rev-parse", "HEAD^1").lower()
    if parent_sha != head_sha or not SHA_RE.fullmatch(commit_sha):
        raise NewGameverArtifactError("bootstrap artifact commit is not a direct child of the bound PR head")
    return {
        "schema_version": 1,
        "repository": ALLOWED_REPOSITORY,
        "game_version": gamever,
        "prior_gamever": verification.get("prior_gamever"),
        "head_ref": verification["head_ref"],
        "parent_sha": parent_sha,
        "commit_sha": commit_sha,
        "changed_paths": sorted(staged),
        "artifact_inventory_sha256": verification["artifact_inventory_sha256"],
        "execution_sha256": verification["execution_sha256"],
    }


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--repo-root", default=".")
    build.add_argument("--plan", required=True)
    build.add_argument("--artifact-root", required=True)
    build.add_argument("--output-manifest", required=True)
    build.add_argument("--repository", required=True)
    build.add_argument("--pr-number", required=True, type=int)
    build.add_argument("--workflow-run-id", required=True)
    build.add_argument("--workflow-run-attempt", required=True)
    build.add_argument("--gate-evidence", required=True)
    build.add_argument("--execution-report", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--repo-root", default=".")
    verify.add_argument("--plan", required=True)
    verify.add_argument("--artifact-root", required=True)
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--repository", required=True)
    verify.add_argument("--default-branch", required=True)
    verify.add_argument("--base-repository", required=True)
    verify.add_argument("--base-ref", required=True)
    verify.add_argument("--base-sha", required=True)
    verify.add_argument("--head-repository", required=True)
    verify.add_argument("--head-ref", required=True)
    verify.add_argument("--head-sha", required=True)
    verify.add_argument("--current-remote-head", required=True)
    verify.add_argument("--pr-number", required=True, type=int)
    verify.add_argument("--actions-artifact-name", required=True)
    verify.add_argument("--actions-artifact-digest", required=True)
    verify.add_argument("--workflow-run-id", required=True)
    verify.add_argument("--workflow-run-attempt", required=True)
    verify.add_argument("--execution-report", required=True)
    verify.add_argument("--output", required=True)
    commit = subparsers.add_parser("commit")
    commit.add_argument("--repo-root", default=".")
    commit.add_argument("--artifact-root", required=True)
    commit.add_argument("--verification", required=True)
    commit.add_argument("--workflow-run-url", required=True)
    commit.add_argument("--output", required=True)
    return parser.parse_args(argv)


def _load_json(path: str | Path) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NewGameverArtifactError(f"unable to load JSON evidence {path}: {exc}") from exc


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "build":
            result = build_bootstrap_candidate(
                repo_root=args.repo_root,
                plan=args.plan,
                artifact_root=args.artifact_root,
                output_manifest=args.output_manifest,
                repository=args.repository,
                pr_number=args.pr_number,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
                gate_evidence=args.gate_evidence,
                execution_report=args.execution_report,
            )
        elif args.command == "verify":
            result = verify_bootstrap_candidate(
                repo_root=args.repo_root,
                plan=args.plan,
                artifact_root=args.artifact_root,
                manifest=args.manifest,
                repository=args.repository,
                default_branch=args.default_branch,
                base_repository=args.base_repository,
                base_ref=args.base_ref,
                base_sha=args.base_sha,
                head_repository=args.head_repository,
                head_ref=args.head_ref,
                head_sha=args.head_sha,
                current_remote_head=args.current_remote_head,
                pr_number=args.pr_number,
                actions_artifact_name=args.actions_artifact_name,
                actions_artifact_digest=args.actions_artifact_digest,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
                execution_report=args.execution_report,
            )
            _atomic_write(Path(args.output), _canonical_json_bytes(result))
        else:
            result = prepare_bootstrap_commit(
                repo_root=args.repo_root,
                artifact_root=args.artifact_root,
                verification=_load_json(args.verification),
                workflow_run_url=args.workflow_run_url,
            )
            _atomic_write(Path(args.output), _canonical_json_bytes(result))
    except (OSError, UnicodeError, yaml.YAMLError, NewGameverArtifactError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

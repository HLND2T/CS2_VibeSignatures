#!/usr/bin/env python3
"""One-off Phase-D continuation of run 34031704261; never emits a production attestation."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
from pathlib import Path

from gamesymbol_snapshot_lib.config import load_contract
from phase_d_validation import GAMEVER, compare_inventories, inventory, run_logged, version, write_json
from idb_cache import restore_cache
from release_workflow_lib.binary_cache import verify_source_binary_root
from trusted_artifact_pr import (
    GitTreeRepository,
    _canonical_json_bytes,
    _digest,
    _selected_execution_digest,
    _load_selected_execution_manifest,
    load_trusted_artifact_plan,
    prepare_isolated_rebuild,
    validate_isolated_rebuild,
    validate_selected_execution_records,
)


TARGET = "server/CFlashbangProjectile_Spawn_NetworkStateChangedNotify.linux.yaml"
NODE = "7:241:server:linux:find-CFlashbangProjectile_Spawn_NetworkStateChangedNotify"
SOURCE = "b46ae7aae6e388ce3854ec02a82bbf4e57932e33"


def check_failed_records(report: dict, planned: dict) -> None:
    """Reject every failure shape except the one unattempted skip found in the archived run."""
    if report.get("valid") is not False or len(report.get("issues", [])) != 1:
        raise ValueError("unexpected original failure shape")
    missing = [node for node in report["nodes"] if node["node_id"] == NODE]
    if len(missing) != 1 or missing[0].get("reason") != "skip_if_exists" or missing[0].get("attempted") is not False:
        raise ValueError("expected the single skipped, unattempted node")
    if missing[0]["attempted_paths"] or missing[0]["produced_paths"]:
        raise ValueError("skipped node recorded writes")
    missing_groups = [group for group in report["producer_groups"] if group["artifact_path"] == TARGET]
    if (
        len(missing_groups) != 1
        or missing_groups[0].get("attempted_node_ids") != []
        or missing_groups[0].get("winner_node_id") is not None
        or missing_groups[0].get("output_sha256") is not None
    ):
        raise ValueError("missing group already claims execution or production")
    subset = copy.deepcopy(planned)
    subset["execute_nodes"] = [node for node in planned["execute_nodes"] if node["node_id"] != NODE]
    subset["execute_groups"] = [group for group in planned["execute_groups"] if group["artifact_path"] != TARGET]
    retained = {
        "nodes": [node for node in report["nodes"] if node["node_id"] != NODE],
        "producer_groups": [group for group in report["producer_groups"] if group["artifact_path"] != TARGET],
    }
    validate_selected_execution_records(retained, subset)


def retry_plan(original: dict) -> dict:
    """Explicit maintenance plan: one node executes, all other bytes come from exact source Git blobs."""
    result = copy.deepcopy(original)
    result.update(base_sha=SOURCE, head_sha=SOURCE, merge_sha=SOURCE)
    selected = version(result)
    selected["base_artifacts"] = selected["merge_artifacts"]
    selected["base_config_sha256"] = selected["merge_config_sha256"]
    selected["base_binary_lock_sha256"] = selected["merge_binary_lock_sha256"]
    groups = selected["execute_groups"]
    selected["execute_groups"] = [group for group in groups if group["artifact_path"] == TARGET]
    selected["execute_nodes"] = [node for node in selected["execute_nodes"] if node["node_id"] == NODE]
    if len(selected["execute_groups"]) != 1 or len(selected["execute_nodes"]) != 1:
        raise ValueError("retry closure is not exactly the reviewed node")
    prefix = f"bin_artifacts/{GAMEVER}/"
    selected["inherit_paths"] = [
        dict(item, path=item["path"].removeprefix(prefix))
        for item in selected["merge_artifacts"]["files"]
        if item["path"] != prefix + TARGET
    ]
    present = {item["path"].removeprefix(prefix) for item in selected["merge_artifacts"]["files"]}
    selected["inherited_absent_groups"] = [group for group in groups if group["artifact_path"] not in present]
    selected["removed_paths"] = []
    selected["invalidated_paths"] = [TARGET]
    selected["reasons"] = ["Explicit one-off Phase-D repair of an unattempted node"]
    result.pop("plan_sha256")
    result["plan_sha256"] = _digest("trusted-pr-plan", result)
    return result


def resume(args) -> dict:
    repo = GitTreeRepository(args.repo_root)
    if repo.resolve_commit("HEAD") != SOURCE:
        raise ValueError("continuation requires the original reviewed source checkout")
    if os.environ.get("CS2VIBE_STRING_MIN_LENGTH") != "4":
        raise ValueError("continuation must preserve string minimum 4")
    root = args.evidence_root.resolve()
    output = args.output_root.resolve()
    if output.is_relative_to(args.repo_root.resolve()) or output.is_relative_to(root):
        raise ValueError("continuation output must be fresh and outside source/old evidence")
    output.mkdir(parents=True, exist_ok=False)
    previous = json.loads((root / "comparison.json").read_text())
    if previous["source_sha"] != SOURCE or previous["string_min_length"] != "4":
        raise ValueError("previous experiment identity drifted")
    expected_names = {"pr-926", "artifact-only", "cross-stage", "fresh-full"}
    if {item["name"] for item in previous["results"]} != expected_names or len(previous["results"]) != 4:
        raise ValueError("previous successful experiment set drifted")
    baseline_root = root / "fresh-full/rebuild/actual-bin-artifacts"
    for item in previous["results"]:
        name = item["name"]
        validation = validate_isolated_rebuild(
            repo_root=repo.root,
            plan=root / name / "experimental-plan.json",
            preparation=root / name / "rebuild/preparation.json",
        )
        if validation != item["validation"]:
            raise ValueError(f"archived validation drifted: {name}")
        compare_inventories(baseline_root, root / name / "rebuild/actual-bin-artifacts")
    original = load_trusted_artifact_plan(root / "shared-runtime/experimental-plan.json")
    if original["merge_tree_sha"] != repo.tree_sha(SOURCE):
        raise ValueError("archived source tree differs from the reviewed experiment")
    planned = version(original)
    preparation = json.loads((root / "shared-runtime/rebuild/preparation.json").read_text())
    unsigned_preparation = {key: value for key, value in preparation.items() if key != "preparation_sha256"}
    if preparation["preparation_sha256"] != _digest("isolated-preparation", unsigned_preparation):
        raise ValueError("archived preparation digest drifted")
    if preparation["plan_sha256"] != original["plan_sha256"] or Path(preparation["staging_root"]).parents[1] != root:
        raise ValueError("archived evidence must be restored to its exact bound runner path")
    manifest = _load_selected_execution_manifest(Path(preparation["selected_execution_manifests"][GAMEVER]))
    failed_path = root / "shared-runtime/rebuild/execution-reports/14178b.selected.json"
    raw = failed_path.read_bytes()
    failed = json.loads(raw)
    unsigned = {key: value for key, value in failed.items() if key != "execution_sha256"}
    if raw != _canonical_json_bytes(failed) or failed["execution_sha256"] != _selected_execution_digest(unsigned):
        raise ValueError("archived failed execution digest drifted")
    if failed["plan_sha256"] != original["plan_sha256"] or failed["manifest_sha256"] != manifest["manifest_sha256"]:
        raise ValueError("archived selected provenance drifted")
    if (
        failed["artifact_root"] != preparation["actual_artifact_root"]
        or failed["binary_root"] != preparation["binary_root"]
        or failed["config_path"] != str(Path(preparation["config_root"]) / f"{GAMEVER}.yaml")
        or failed.get("required_warm_idb") is not True
    ):
        raise ValueError("archived execution root bindings drifted")
    if failed["inherited_initial_inventory_sha256"] != preparation["initial_actual_inventory_sha256"][GAMEVER]:
        raise ValueError("archived initial inventory binding drifted")
    if manifest["execute_nodes"] != planned["execute_nodes"] or manifest["execute_groups"] != planned["execute_groups"]:
        raise ValueError("archived manifest closure drifted")
    check_failed_records(failed, planned)
    baseline = inventory(baseline_root)
    retained = inventory(root / "shared-runtime/rebuild/actual-bin-artifacts")
    if retained != {path: value for path, value in baseline.items() if path != f"{GAMEVER}/{TARGET}"}:
        raise ValueError("previous artifacts differ beyond the single missing output")

    # The executor delta is deliberately restricted: all retained nodes avoided this branch.
    tool_root = Path(__file__).resolve().parent
    original_executor = repo.read(SOURCE, "ida_analyze_bin.py")
    old = b"            if skip_for_existing_artifacts:\n"
    new = b"            if skip_for_existing_artifacts and not force_all:\n"
    executor = GitTreeRepository(tool_root).read("HEAD", "ida_analyze_bin.py")
    if original_executor.count(old) != 1 or executor != original_executor.replace(old, new):
        raise ValueError("executor differs beyond the reviewed one-line skip fix")
    contract = load_contract(repo.root / "configs/14178b.yaml", GAMEVER, repo.root / "bin")
    if planned["inherit_paths"] or {group["group_id"] for group in planned["execute_groups"]} != set(
        contract.producer_groups
    ):
        raise ValueError("archived shared-runtime plan is not a full execution closure")
    node = contract.nodes[NODE]
    group = contract.producer_group_for_path(TARGET)
    if (
        node.prerequisites
        or node.outputs != {TARGET}
        or contract.downstream_group_ids({group.group_id}) != {group.group_id}
    ):
        raise ValueError("the retry node now has prerequisites, extra outputs or downstream dependencies")
    maintenance_plan = retry_plan(original)
    write_json(output / "maintenance-plan.json", maintenance_plan)
    prepared = prepare_isolated_rebuild(
        repo_root=repo.root, plan=maintenance_plan, staging_root=output / "retry", game_version=GAMEVER
    )
    warm = previous["results"][0]["warm_restore"]
    if any(item["warm_restore"] != warm for item in previous["results"]):
        raise ValueError("previous warm identities differ")
    if json.loads((root / "shared-runtime/warm-restore.json").read_text()) != warm:
        raise ValueError("failed sample warm identity differs")
    restored = restore_cache(
        repo_root=repo.root,
        persisted_root=args.persisted_root,
        gamever=GAMEVER,
        generation=warm["generation"],
        expected_cache_key=warm["cache_key"],
        ida_version=warm["ida_version"],
    )
    write_json(output / "warm-restore.json", restored)
    lock = verify_source_binary_root(
        repo_root=repo.root,
        gamever=GAMEVER,
        binary_root=repo.root / "bin" / GAMEVER,
        label="Phase-D continuation binaries",
    )
    if lock.sha256 != planned["merge_binary_lock_sha256"]:
        raise ValueError("continuation binary identity drifted")
    import sys

    command = [
        sys.executable,
        str(tool_root / "ida_analyze_bin.py"),
        "-gamever",
        GAMEVER,
        "-configyaml",
        str(Path(prepared["config_root"]) / f"{GAMEVER}.yaml"),
        "-bindir",
        "bin",
        "-artifactdir",
        prepared["actual_artifact_root"],
        "-oldartifactdir",
        "bin_artifacts",
        "-execution_report",
        prepared["execution_reports"][GAMEVER],
        "-require_warm_idb",
        "-selected_execution",
        prepared["selected_execution_manifests"][GAMEVER],
    ]
    elapsed = run_logged(repo.root, command, output / "retry.log")
    validation = validate_isolated_rebuild(repo_root=repo.root, plan=maintenance_plan, preparation=prepared)
    write_json(output / "retry-validation.json", validation)
    supplemental = json.loads(Path(prepared["execution_reports"][GAMEVER]).read_text())
    # Validate a records-only coverage view. Never fabricate a successful original report.
    records = {
        "nodes": [record for record in failed["nodes"] if record["node_id"] != NODE] + supplemental["nodes"],
        "producer_groups": [record for record in failed["producer_groups"] if record["artifact_path"] != TARGET]
        + supplemental["producer_groups"],
    }
    validate_selected_execution_records(records, planned)
    combined = output / "combined-artifacts"
    shutil.copytree(root / "shared-runtime/rebuild/actual-bin-artifacts", combined)
    target = combined / GAMEVER / TARGET
    shutil.copyfile(Path(prepared["actual_artifact_root"]) / GAMEVER / TARGET, target)
    comparison = compare_inventories(baseline_root, combined)
    compare_inventories(baseline_root, Path(prepared["actual_artifact_root"]))
    result = {
        "schema_version": 1,
        "purpose": "phase-d-cross-run-continuation-not-pr-attestation",
        "valid": True,
        "original_run": 34031704261,
        "source_sha": SOURCE,
        "source_tree_sha": original["merge_tree_sha"],
        "original_failed_report_sha256": failed["execution_sha256"],
        "supplemental_report_sha256": supplemental["execution_sha256"],
        "executor_sha256": hashlib.sha256(executor).hexdigest(),
        "executor_delta": "one-line forced skip guard",
        "retained_successful_nodes": sum(record["status"] == "succeeded" for record in failed["nodes"]),
        "retried_nodes": [NODE],
        "covered_groups": len(records["producer_groups"]),
        "comparison": comparison,
        "warm_restore": restored,
        "binary_lock_sha256": lock.sha256,
        "producer_seconds": elapsed,
        "downstream_evidence": "reused verified fresh-full result after exact source/config/inventory equality",
        "prior_results": previous["results"],
    }
    write_json(output / "continuation.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo-root", "evidence-root", "output-root", "persisted-root"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    resume(parser.parse_args())

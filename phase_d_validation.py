#!/usr/bin/env python3
"""Temporary, non-gating selected/full migration experiment; remove after PR 926 merges."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

from bin_artifact_contract import _category_for, _category_map
from gamesymbol_snapshot_lib.config import load_contract
from ida_analyze_util import canonical_symbol_yaml_bytes
from idb_cache import restore_cache
from release_workflow_lib.binary_cache import verify_source_binary_root
from trusted_artifact_pr import (
    GitTreeRepository,
    _digest,
    build_trusted_artifact_plan,
    prepare_isolated_rebuild,
    validate_isolated_rebuild,
)
from trusted_pr_context import EXECUTION_STRATEGIES, build_trusted_pr_context


SELECTED = "base-inherited-selected-v1"
FULL = "fresh-full-v1"
GAMEVER = "14178b"
ARTIFACT_SAMPLE = "engine/CNetworkClientSpawnGroupCreatePrerequisites_Init.windows.yaml"


def write_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def experimental_plan(original: dict, strategy: str) -> dict:
    """Change only strategy/digest for this maintenance experiment, never the closure."""
    if strategy not in EXECUTION_STRATEGIES:
        raise ValueError(f"unknown experiment strategy: {strategy}")
    result = copy.deepcopy(original)
    result.pop("plan_sha256", None)
    result["execution_strategy"] = strategy
    result["plan_sha256"] = _digest("trusted-pr-plan", result)
    return result


def inventory(root: Path) -> dict:
    return {
        path.relative_to(root).as_posix(): {
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def compare_inventories(full: Path, selected: Path) -> dict:
    expected, actual = inventory(full), inventory(selected)
    if expected != actual:
        different = sorted(path for path in expected.keys() | actual.keys() if expected.get(path) != actual.get(path))
        raise RuntimeError(f"selected/full inventory differs: {different[:20]}")
    return {"file_count": len(actual), "sha256": _digest("phase-d-inventory", actual)}


def git_object(repo: GitTreeRepository, arguments: list[str], *, payload: bytes = b"", env=None) -> str:
    environment = dict(
        os.environ,
        GIT_AUTHOR_NAME="Codex",
        GIT_AUTHOR_EMAIL="codex@openai.com",
        GIT_COMMITTER_NAME="Codex",
        GIT_COMMITTER_EMAIL="codex@openai.com",
    )
    environment.update(env or {})
    result = subprocess.run(
        ["git", "-C", str(repo.root), *arguments],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=True,
    )
    return result.stdout.decode().strip()


def synthetic_base(repo: GitTreeRepository, source: str, path: str, raw: bytes, scratch: Path) -> str:
    """Write fixture commits through Git plumbing with an isolated index, leaving HEAD untouched."""
    scratch.mkdir(parents=True, exist_ok=False)
    environment = {"GIT_INDEX_FILE": str((scratch / "index").resolve())}
    git_object(repo, ["read-tree", source], env=environment)
    blob = git_object(repo, ["hash-object", "-w", "--stdin"], payload=raw)
    git_object(repo, ["update-index", "--add", "--cacheinfo", f"100644,{blob},{path}"], env=environment)
    tree = git_object(repo, ["write-tree"], env=environment)
    return git_object(repo, ["commit-tree", tree, "-p", source], payload=b"Phase-D synthetic base fixture\n")


def fixture_plan(repo: GitTreeRepository, source: str, path: str, raw: bytes, scratch: Path) -> dict:
    base = synthetic_base(repo, source, path, raw, scratch)
    merge = git_object(
        repo,
        ["commit-tree", repo.tree_sha(source), "-p", base, "-p", source],
        payload=b"Phase-D fixture merge with exact experiment source tree\n",
    )
    context = build_trusted_pr_context(repo_root=repo.root, base_ref=base, head_ref=source, merge_ref=merge)
    write_json(scratch / "context.json", context)
    return build_trusted_artifact_plan(repo_root=repo.root, trusted_context=context)


def version(plan: dict) -> dict:
    return next(item for item in plan["game_versions"] if item["game_version"] == GAMEVER)


def cross_stage_source(contract, repo: GitTreeRepository, source: str) -> tuple[str, set[str]]:
    """Choose a real, small upstream closure containing a later-stage artifact consumer."""
    candidates = []
    for group_id, group in contract.producer_groups.items():
        downstream = contract.downstream_group_ids({group_id})
        upstream_nodes = [contract.nodes[node_id] for node_id in group.alternative_node_ids]
        downstream_nodes = [
            contract.nodes[node_id]
            for other in downstream - {group_id}
            for node_id in contract.producer_groups[other].alternative_node_ids
        ]
        for node in upstream_nodes:
            if any(other.stage_index > node.stage_index for other in downstream_nodes):
                candidates.append((len(downstream), node.skill_name, downstream))
    for _, skill, downstream in sorted(candidates, key=lambda item: (item[0], item[1])):
        path = f"ida_preprocessor_scripts/{skill}.py"
        if repo.entries(source, path):
            return path, set(downstream)
    raise RuntimeError("no real cross-stage source fixture found")


def plan_samples(args, root: Path) -> list[tuple[str, dict]]:
    repo = GitTreeRepository(args.repo_root)
    if repo.resolve_commit("HEAD") != args.source_sha:
        raise RuntimeError("experiment checkout differs from the bound source")
    context = build_trusted_pr_context(
        repo_root=repo.root, base_ref=args.base_sha, head_ref=args.head_sha, merge_ref=args.source_sha
    )
    write_json(root / "real-context.json", context)
    print("Planning the bound PR sample...", flush=True)
    real = build_trusted_artifact_plan(repo_root=repo.root, trusted_context=context)
    if real["affected_game_versions"] != [GAMEVER] or real["mode"] != "full":
        raise RuntimeError("expected the maintained 14178b full-route sample")
    added = [change["new_path"] for change in real["changed_paths"] if change["status"] == "A"]
    modified = [change["new_path"] for change in real["changed_paths"] if change["status"] == "M"]
    if not any(path.startswith(f"bin_artifacts/{GAMEVER}/") for path in added):
        raise RuntimeError("real PR no longer covers a new symbol")
    if not any(path.startswith("ida_preprocessor_scripts/find-") for path in modified):
        raise RuntimeError("real PR no longer covers a finder modification")
    contract = load_contract(
        repo.root / "configs" / f"{GAMEVER}.yaml", GAMEVER, repo.root / "bin", artifactdir=repo.root / "bin_artifacts"
    )
    artifact_path = f"bin_artifacts/{GAMEVER}/{ARTIFACT_SAMPLE}"
    payload = yaml.safe_load(repo.read(args.source_sha, artifact_path))
    payload["func_va"] = hex(int(str(payload["func_va"]), 0) + 1)
    payload["func_rva"] = hex(int(str(payload["func_rva"]), 0) + 1)
    categories = _category_map(repo.root / "configs" / f"{GAMEVER}.yaml")
    raw = canonical_symbol_yaml_bytes(payload, category=_category_for(ARTIFACT_SAMPLE, payload, categories))
    print("Planning the artifact-only fixture...", flush=True)
    artifact = fixture_plan(repo, args.source_sha, artifact_path, raw, root / "artifact-only-fixture")
    cross_path, expected_groups = cross_stage_source(contract, repo, args.source_sha)
    print(f"Planning the cross-stage fixture: {cross_path}", flush=True)
    cross = fixture_plan(
        repo,
        args.source_sha,
        cross_path,
        repo.read(args.source_sha, cross_path) + b"\n# Phase-D source invalidation fixture.\n",
        root / "cross-stage-fixture",
    )
    if not expected_groups.issubset({group["group_id"] for group in version(cross)["execute_groups"]}):
        raise RuntimeError("cross-stage fixture did not select the downstream closure")
    if len({node["stage_index"] for node in version(cross)["execute_nodes"]}) < 2:
        raise RuntimeError("cross-stage sample must execute at least two stages")
    shared_path = "ida_analyze_util.py"
    print("Planning the shared-runtime fixture...", flush=True)
    shared = fixture_plan(
        repo,
        args.source_sha,
        shared_path,
        repo.read(args.source_sha, shared_path) + b"\n# Phase-D shared runtime fixture.\n",
        root / "shared-runtime-fixture",
    )
    if version(shared)["inherit_paths"] or len(version(shared)["execute_groups"]) != len(contract.producer_groups):
        raise RuntimeError("shared runtime fixture did not force the complete contract")
    samples = [("pr-926", real), ("artifact-only", artifact), ("cross-stage", cross), ("shared-runtime", shared)]
    for name, plan in samples:
        if plan["merge_tree_sha"] != real["merge_tree_sha"]:
            raise RuntimeError("sample source trees differ")
        if version(plan)["merge_binary_lock_sha256"] != args.binary_lock_sha256:
            raise RuntimeError("sample binary lock differs from warmup")
        write_json(root / f"{name}.original-plan.json", plan)
        print(
            f"Planned {name}: {len(version(plan)['execute_groups'])} groups, "
            f"{len(version(plan)['execute_nodes'])} nodes, {len(version(plan)['inherit_paths'])} inherited",
            flush=True,
        )
    write_json(
        root / "samples.json",
        {
            "cross_stage_source": cross_path,
            "artifact_only_path": artifact_path,
            "synthetic_base_samples": ["artifact-only", "cross-stage", "shared-runtime"],
        },
    )
    return samples


def run_logged(repo_root: Path, command: list[str], log: Path) -> float:
    started = time.monotonic()
    print(f"Running {' '.join(command)}", flush=True)
    with log.open("w", encoding="utf-8") as stream:
        process = subprocess.Popen(
            command,
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=dict(os.environ, PYTHONUNBUFFERED="1"),
        )
        for line in process.stdout:
            stream.write(line)
            stream.flush()
            print(line, end="", flush=True)
        code = process.wait()
    if code:
        raise RuntimeError(f"command failed with exit {code}; see {log}")
    return time.monotonic() - started


def execute_sample(args, root: Path, name: str, original: dict, strategy: str) -> dict:
    started = time.monotonic()
    destination = root / name
    destination.mkdir()
    plan = experimental_plan(original, strategy)
    write_json(destination / "experimental-plan.json", plan)
    preparation = prepare_isolated_rebuild(
        repo_root=args.repo_root, plan=plan, staging_root=destination / "rebuild", game_version=GAMEVER
    )
    prepare_seconds = time.monotonic() - started
    restore_start = time.monotonic()
    restored = restore_cache(
        repo_root=args.repo_root,
        persisted_root=args.persisted_root,
        gamever=GAMEVER,
        generation=args.warm_generation,
        expected_cache_key=args.cache_key,
        ida_version=args.ida_version,
    )
    write_json(destination / "warm-restore.json", restored)
    lock = verify_source_binary_root(
        repo_root=args.repo_root,
        gamever=GAMEVER,
        binary_root=args.repo_root / "bin" / GAMEVER,
        label="Phase-D restored binaries",
    )
    if lock.sha256 != args.binary_lock_sha256:
        raise RuntimeError("restored binary lock differs from the experiment")
    restore_seconds = time.monotonic() - restore_start
    config = str(Path(preparation["config_root"]) / f"{GAMEVER}.yaml")
    actual = preparation["actual_artifact_root"]
    command = [
        sys.executable,
        "ida_analyze_bin.py",
        "-gamever",
        GAMEVER,
        "-configyaml",
        config,
        "-bindir",
        "bin",
        "-artifactdir",
        actual,
        "-oldartifactdir",
        "bin_artifacts",
        "-execution_report",
        preparation["execution_reports"][GAMEVER],
        "-require_warm_idb",
    ]
    command += (
        ["-selected_execution", preparation["selected_execution_manifests"][GAMEVER]]
        if strategy == SELECTED
        else ["-force_all"]
    )
    producer_seconds = run_logged(args.repo_root, command, destination / "producer.log")
    verify_source_binary_root(
        repo_root=args.repo_root,
        gamever=GAMEVER,
        binary_root=args.repo_root / "bin" / GAMEVER,
        label="Phase-D executed binaries",
    )
    verify_start = time.monotonic()
    validation = validate_isolated_rebuild(repo_root=args.repo_root, plan=plan, preparation=preparation)
    write_json(destination / "validation.json", validation)
    verify_seconds = time.monotonic() - verify_start
    downstream = destination / "downstream"
    downstream.mkdir()
    snapshot, session = str(downstream / "snapshot.yaml"), str(downstream / "snapshot.session.json")
    gamedata_session = str(downstream / "gamedata.session.json")
    commands = [
        [
            sys.executable,
            "gamesymbol_candidate.py",
            "build",
            "-gamever",
            GAMEVER,
            "-bindir",
            "bin",
            "-artifactdir",
            actual,
            "-configyaml",
            config,
            "-output",
            snapshot,
            "-session",
            session,
        ],
        [
            sys.executable,
            "gamedata_candidate.py",
            "build",
            "-gamever",
            GAMEVER,
            "-build-id",
            f"phase-d-{name}",
            "-snapshot",
            snapshot,
            "-configyaml",
            config,
            "-candidate-root",
            str(downstream / "gamedata"),
            "-session",
            gamedata_session,
        ],
        [sys.executable, "gamedata_candidate.py", "guard", "-session", gamedata_session],
        [sys.executable, "run_cpp_tests.py", "-gamever", GAMEVER, "-snapshot", snapshot, "-configyaml", config],
    ]
    downstream_seconds = sum(
        run_logged(args.repo_root, command, destination / f"downstream-{index}.log")
        for index, command in enumerate(commands)
    )
    execution = json.loads(Path(preparation["execution_reports"][GAMEVER]).read_text(encoding="utf-8"))
    producer_log = (destination / "producer.log").read_text(encoding="utf-8")
    return {
        "name": name,
        "strategy": strategy,
        "original_plan_sha256": original["plan_sha256"],
        "experimental_plan_sha256": plan["plan_sha256"],
        "merge_tree_sha": plan["merge_tree_sha"],
        "binary_lock_sha256": args.binary_lock_sha256,
        "warm_restore": restored,
        "actual_root": actual,
        "validation": validation,
        "executed_group_count": len(execution["producer_groups"]),
        "ida_session_starts": producer_log.count("Starting idalib-mcp:"),
        "timing_seconds": {
            "prepare": prepare_seconds,
            "restore": restore_seconds,
            "producer": producer_seconds,
            "verify": verify_seconds,
            "downstream": downstream_seconds,
            "total": time.monotonic() - started,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    for name in (
        "base-sha",
        "head-sha",
        "source-sha",
        "binary-lock-sha256",
        "warm-generation",
        "cache-key",
        "ida-version",
    ):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--persisted-root", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    args.repo_root = args.repo_root.resolve()
    root = args.output_root.resolve()
    if root.is_relative_to(args.repo_root):
        raise RuntimeError("experiment evidence must live outside the checkout")
    root.mkdir(parents=True, exist_ok=False)
    report = {
        "schema_version": 1,
        "purpose": "phase-d-migration-experiment-not-pr-attestation",
        "valid": False,
        "source_sha": args.source_sha,
        "string_min_length": os.environ.get("CS2VIBE_STRING_MIN_LENGTH"),
        "results": [],
    }
    try:
        samples = plan_samples(args, root)
        if args.plan_only:
            return 0
        if args.persisted_root is None:
            raise RuntimeError("persisted root is required for real runner execution")
        # Every sample has exactly the same executed source tree. One full baseline therefore
        # provides the byte comparator for all selected trials; each restores the same generation.
        trials = [(name, plan, SELECTED) for name, plan in samples[:-1]]
        trials += [("fresh-full", samples[0][1], FULL), (samples[-1][0], samples[-1][1], SELECTED)]
        for name, plan, strategy in trials:
            report["results"].append(execute_sample(args, root, name, plan, strategy))
            write_json(root / "comparison.json", report)
        baseline = next(result for result in report["results"] if result["strategy"] == FULL)
        for result in report["results"]:
            result["comparison"] = compare_inventories(Path(baseline["actual_root"]), Path(result["actual_root"]))
        report["valid"] = True
        return 0
    except Exception as exc:
        report["error"] = str(exc)
        raise
    finally:
        write_json(root / "comparison.json", report)


if __name__ == "__main__":
    raise SystemExit(main())

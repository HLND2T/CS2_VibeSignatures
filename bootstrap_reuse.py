#!/usr/bin/env python3
"""Reuse authenticated bootstrap execution for an unchanged new-GAMEVER artifact tree.

The hosted probe authenticates Actions provenance. Workers consume its immutable,
same-run evidence artifact and recheck Git bytes before using it downstream.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

import yaml

import new_gamever_artifact as bootstrap
from bin_artifact_contract import ArtifactContractError, build_game_artifact_inventory
from trusted_artifact_pr import (
    GitTreeRepository,
    TrustedArtifactPrError,
    load_trusted_artifact_plan,
    validate_trusted_artifact_plan,
)


MAX_PUBLICATIONS = 20
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
WORKFLOW_PATH = ".github/workflows/source-artifact-required.yml"
# Conservative compatibility: unknown changes cause a normal rebuild. These paths
# cannot affect IDA production; downstream consumers and repository tests still run.
NON_PRODUCER_PREFIXES = (
    "docs/",
    "memory/",
    "tests/",
    "pages/",
    "cpp_tests/",
    "gamedata-generators/",
)
NON_PRODUCER_FILES = frozenset(
    {
        "release_publish.py",
        "README.md",
        "README_CN.md",
        ".claude/skills/trigger-release-build/SKILL.md",
        ".github/workflows/publish-release-bundle.yml",
    }
)


class BootstrapReuseError(RuntimeError):
    """Evidence cannot replace the current producer execution."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BootstrapReuseError(message)


def _version(plan: dict, gamever: str) -> dict:
    matches = [item for item in plan["game_versions"] if item["game_version"] == gamever]
    _require(len(matches) == 1, "GAMEVER is absent or ambiguous")
    return matches[0]


def _diagnostics_only_change(repo: GitTreeRepository, before: str, after: str, path: str) -> bool:
    if path != ".github/workflows/bootstrap-new-gamever-artifacts.yml":
        return False
    documents = []
    for revision in (before, after):
        raw = repo.read(revision, path).decode("utf-8")
        # Run-scoping these existing local evidence paths does not change producer
        # inputs. Keep every command/flag and all other workflow bytes significant.
        raw = raw.replace(
            "new-gamever-force-all-execution-${{ github.run_id }}-${{ github.run_attempt }}.json",
            "new-gamever-force-all-execution.json",
        )
        raw = raw.replace("new-gamever-gates\\${{ github.run_id }}-${{ github.run_attempt }}", "new-gamever-gates")
        document = yaml.safe_load(raw)
        for job in document.get("jobs", {}).values():
            if "steps" in job:
                job["steps"] = [
                    step
                    for step in job["steps"]
                    if not (
                        step.get("name") == "Upload failed bootstrap diagnostics"
                        and str(step.get("if", "")).strip().startswith("failure() &&")
                    )
                ]
        documents.append(document)
    return documents[0] == documents[1]


def _materialize(repo: GitTreeRepository, revision: str, gamever: str, destination: Path) -> tuple[Path, Path]:
    artifact_root = destination / "bin_artifacts"
    entries = repo.entries(revision, f"bin_artifacts/{gamever}/")
    for entry in entries:
        _require(entry.mode == "100644" and entry.object_type == "blob", "artifact is not a regular Git blob")
    for path, raw in repo.read_blobs(entries).items():
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    config = destination / "configs" / f"{gamever}.yaml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_bytes(repo.read(revision, f"configs/{gamever}.yaml"))
    return artifact_root, config


def verify_reuse(*, repo_root: str | Path, plan: dict, gamever: str, evidence: dict) -> dict:
    """Rebind trusted downloaded evidence to the current plan, never to commit prose."""
    try:
        plan = validate_trusted_artifact_plan(plan)
        old = validate_trusted_artifact_plan(evidence["bootstrap_plan"])
        version = _version(plan, gamever)
        prior_version = bootstrap._bootstrap_version(old)
        _require(
            plan["mode"] == "full" and version["base_config_sha256"] is None,
            "reuse applies only to a newly configured GAMEVER",
        )
        _require(prior_version["game_version"] == gamever, "bootstrap GAMEVER differs")
        _require(not version["bootstrap_required"], "current artifacts are incomplete")
        for key in (
            "merge_config_sha256",
            "merge_binary_lock_sha256",
            "prior_gamever",
            "binary_inventory_sha256",
            "execute_groups",
            "execute_nodes",
        ):
            _require(version[key] == prior_version[key], f"bootstrap input changed: {key}")
        repo = GitTreeRepository(repo_root)
        _require(repo.resolve_commit("HEAD") == plan["merge_sha"], "checkout differs from current plan")
        _require(repo.tree_sha(plan["merge_sha"]) == plan["merge_tree_sha"], "current tree differs from plan")
        _require(repo.tree_sha(old["merge_sha"]) == old["merge_tree_sha"], "bootstrap tree differs from plan")
        publication = evidence["publication_sha"]
        _require(bool(bootstrap.SHA_RE.fullmatch(publication)), "invalid publication SHA")
        parents = repo.run("show", "-s", "--format=%P", publication).decode().split()
        _require(parents == [old["head_sha"]], "publication is not a direct child of the bootstrap source")
        repo.run("merge-base", "--is-ancestor", publication, plan["head_sha"])
        prefix = f"bin_artifacts/{gamever}/"
        published_changes = (
            repo.run("diff", "--name-only", "--no-renames", old["head_sha"], publication).decode().splitlines()
        )
        _require(
            bool(published_changes) and all(path.startswith(prefix) for path in published_changes),
            "publication changed files outside the GAMEVER artifacts",
        )
        _require(
            repo.entries(publication, prefix) == repo.entries(plan["merge_sha"], prefix),
            "current artifacts differ from published Git bytes",
        )
        changes = (
            repo.run("diff", "--name-only", "--no-renames", old["merge_sha"], plan["merge_sha"]).decode().splitlines()
        )
        for path in changes:
            _require(
                path.startswith(prefix)
                or path.startswith(NON_PRODUCER_PREFIXES)
                or path in NON_PRODUCER_FILES
                or _diagnostics_only_change(repo, old["merge_sha"], plan["merge_sha"], path),
                f"bootstrap producer input changed: {path}",
            )
        manifest = evidence["manifest"]
        unsigned = dict(manifest)
        unsigned.pop("candidate_sha256", None)
        _require(
            manifest.get("schema_version") == bootstrap.BOOTSTRAP_CANDIDATE_SCHEMA_VERSION
            and manifest.get("candidate_sha256") == bootstrap._digest("candidate-manifest", unsigned),
            "candidate manifest digest/schema mismatch",
        )
        for key, expected in {
            "repository": bootstrap.ALLOWED_REPOSITORY,
            "game_version": gamever,
            "head_sha": old["head_sha"],
            "prospective_merge_sha": old["merge_sha"],
            "prospective_merge_tree_sha": old["merge_tree_sha"],
            "plan_sha256": old["plan_sha256"],
            "config_sha256": version["merge_config_sha256"],
            "prior_gamever": version["prior_gamever"],
        }.items():
            _require(key in manifest and manifest[key] == expected, f"candidate binding mismatch: {key}")
        bootstrap._load_gate_evidence(manifest["gates"])
        with tempfile.TemporaryDirectory(prefix="bootstrap-reuse-") as temporary:
            artifacts, config = _materialize(repo, plan["merge_sha"], gamever, Path(temporary))
            report = build_game_artifact_inventory(
                repo_root=repo.root, config_path=config, game_version=gamever, artifact_root=artifacts
            )
            files, digest = bootstrap._inventory_document(report)
            _require(
                files == manifest["files"]
                and digest == manifest["artifact_inventory_sha256"]
                and len(files) == manifest["file_count"],
                "Git inventory differs from bootstrap candidate",
            )
            execution = bootstrap._validate_force_all_execution_report(
                value=evidence["execution"], version=version, artifact_report=report
            )
            _require(execution["execution_sha256"] == manifest["execution_sha256"], "execution differs from manifest")
        return {
            "schema_version": 1,
            "strategy": "bootstrap-evidence-reuse-v1",
            "game_version": gamever,
            "plan_sha256": plan["plan_sha256"],
            "merge_sha": plan["merge_sha"],
            "merge_tree_sha": plan["merge_tree_sha"],
            "binary_lock_sha256": version["merge_binary_lock_sha256"],
            "publication_sha": publication,
            "candidate_sha256": manifest["candidate_sha256"],
            "execution_sha256": execution["execution_sha256"],
            "workflow_run_id": manifest["workflow_run_id"],
            "workflow_run_attempt": manifest["workflow_run_attempt"],
        }
    except (
        yaml.YAMLError,
        TrustedArtifactPrError,
        bootstrap.NewGameverArtifactError,
        ArtifactContractError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise BootstrapReuseError(str(exc)) from exc


def _api(path: str, *, raw: bool = False):
    result = subprocess.run(["gh", "api", path], capture_output=True, check=False)
    _require(result.returncode == 0, f"GitHub evidence unavailable: {path}")
    return result.stdout if raw else json.loads(result.stdout)


def _pages(path: str, field: str) -> list:
    items = []
    for page in range(1, 101):
        batch = _api(f"{path}?per_page=100&page={page}")[field]
        items.extend(batch)
        if len(batch) < 100:
            return items
    raise BootstrapReuseError("GitHub evidence pagination limit exceeded")


def authenticate_run(run: dict, jobs: list, *, head: str, gamever: str, run_id: str, attempt: str) -> None:
    _require(str(run["id"]) == run_id and str(run["run_attempt"]) == attempt, "run/attempt mismatch")
    _require(
        run["repository"]["full_name"] == bootstrap.ALLOWED_REPOSITORY
        and run["head_repository"]["full_name"] == bootstrap.ALLOWED_REPOSITORY,
        "bootstrap run is from another repository",
    )
    _require(
        run["event"] == "pull_request_target"
        and run["path"] == WORKFLOW_PATH
        and run["head_sha"] == head
        and run["head_branch"] == f"bump-download/{gamever}",
        "bootstrap workflow/source identity mismatch",
    )
    by_name = {job["name"]: job for job in jobs}
    _require(
        by_name.get("bind-source-artifact-plan", {}).get("conclusion") == "success",
        "bootstrap planning did not succeed",
    )
    _require(
        by_name.get("bootstrap-new-gamever / build-bootstrap-candidate", {}).get("conclusion") == "success",
        "bootstrap candidate job did not succeed",
    )
    publisher = by_name.get("bootstrap-new-gamever / publish-new-gamever-artifacts", {})
    steps = {step["name"]: step.get("conclusion") for step in publisher.get("steps", [])}
    _require(
        steps.get("Revalidate PR, remote head, candidate, and allowed branch") == "success"
        and steps.get("Create direct-child artifact-only commit") == "success",
        "hosted bootstrap verification/publication preparation did not succeed",
    )


def _archive(artifact: dict, name: str) -> zipfile.ZipFile:
    _require(artifact["name"] == name and not artifact["expired"], "artifact missing or expired")
    _require(0 < artifact["size_in_bytes"] <= MAX_ARCHIVE_BYTES, "artifact exceeds reuse size limit")
    raw = _api(f"repos/{bootstrap.ALLOWED_REPOSITORY}/actions/artifacts/{int(artifact['id'])}/zip", raw=True)
    _require(
        len(raw) <= MAX_ARCHIVE_BYTES and "sha256:" + hashlib.sha256(raw).hexdigest() == artifact.get("digest"),
        "Actions archive digest mismatch",
    )
    archive = zipfile.ZipFile(io.BytesIO(raw))
    _require(len(archive.namelist()) == len(set(archive.namelist())), "duplicate archive members")
    _require(
        sum(item.file_size for item in archive.infolist()) <= MAX_ARCHIVE_BYTES, "expanded artifact exceeds size limit"
    )
    return archive


def _archive_json(archive: zipfile.ZipFile, name: str) -> dict:
    raw = archive.read(name)
    value = json.loads(raw)
    _require(raw == bootstrap._canonical_json_bytes(value), f"noncanonical evidence: {name}")
    return value


def discover_reuse(*, repo_root: str | Path, plan: dict, gamever: str) -> dict:
    version = _version(plan, gamever)
    _require(version["base_config_sha256"] is None, "not a new GAMEVER")
    repo = GitTreeRepository(repo_root)
    commits = (
        repo.run("log", f"-{MAX_PUBLICATIONS}", "--format=%H", plan["head_sha"], "--", f"bin_artifacts/{gamever}/")
        .decode()
        .splitlines()
    )
    for commit in commits:
        message = repo.run("show", "-s", "--format=%B", commit).decode()
        match = re.search(
            r"^Workflow-Run: https://github\.com/HLND2T/CS2_VibeSignatures/actions/runs/([0-9]+)$", message, re.M
        )
        if not match:
            continue
        run_id = match[1]
        endpoint = f"repos/{bootstrap.ALLOWED_REPOSITORY}/actions/runs/{run_id}"
        artifacts = _pages(f"{endpoint}/artifacts", "artifacts")
        pattern = re.compile(rf"new-gamever-artifacts-([0-9]+)-{re.escape(gamever)}-{run_id}-([0-9]+)")
        for artifact in artifacts:
            candidate_match = pattern.fullmatch(artifact["name"])
            if not candidate_match:
                continue
            pr_number, attempt = candidate_match.groups()
            run = _api(f"{endpoint}/attempts/{attempt}")
            jobs = _pages(f"{endpoint}/attempts/{attempt}/jobs", "jobs")
            head = repo.run("rev-parse", f"{commit}^").decode().strip()
            authenticate_run(run, jobs, head=head, gamever=gamever, run_id=run_id, attempt=attempt)
            plan_name = f"trusted-source-artifact-plan-{run_id}-{attempt}"
            matches = [item for item in artifacts if item["name"] == plan_name]
            _require(len(matches) == 1, "bootstrap plan artifact missing or ambiguous")
            with _archive(matches[0], plan_name) as archive:
                old_plan = _archive_json(archive, "trusted-source-artifact-plan.json")
            with _archive(artifact, artifact["name"]) as archive:
                manifest = _archive_json(archive, "candidate-manifest.json")
                execution = _archive_json(archive, "force-all-execution.json")
            _require(
                manifest["workflow_run_id"] == run_id
                and manifest["workflow_run_attempt"] == attempt
                and manifest["pull_request_number"] == int(pr_number)
                and manifest["actions_artifact_name"] == artifact["name"],
                "candidate Actions identity mismatch",
            )
            _require(old_plan["head_sha"] == head, "plan does not bind the authenticated run head")
            for sha in (old_plan["merge_sha"], old_plan["base_sha"]):
                _require(bool(bootstrap.SHA_RE.fullmatch(sha)), "invalid bootstrap revision")
                repo.run("fetch", "--no-tags", "origin", sha)
            evidence = {
                "bootstrap_plan": old_plan,
                "manifest": manifest,
                "execution": execution,
                "publication_sha": commit,
                "origin": {
                    "run_id": run_id,
                    "run_attempt": attempt,
                    "artifact_id": artifact["id"],
                    "artifact_digest": artifact["digest"],
                },
            }
            evidence["receipt"] = verify_reuse(repo_root=repo_root, plan=plan, gamever=gamever, evidence=evidence)
            return evidence
    raise BootstrapReuseError("no authenticated bootstrap publication evidence available")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("probe", "prepare"))
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--gamever", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--output-root")
    parser.add_argument("--github-output", required=True)
    args = parser.parse_args()
    plan = load_trusted_artifact_plan(args.plan)
    _require(plan["plan_sha256"] == args.plan_sha256, "current workflow plan digest mismatch")
    if args.command == "probe":
        try:
            evidence = discover_reuse(repo_root=args.repo_root, plan=plan, gamever=args.gamever)
            bootstrap._atomic_write(Path(args.evidence), bootstrap._canonical_json_bytes(evidence))
            hit = True
            print(f"Reusing bootstrap run {evidence['manifest']['workflow_run_id']} for {args.gamever}")
        except (
            BootstrapReuseError,
            TrustedArtifactPrError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            zipfile.BadZipFile,
        ) as exc:
            hit = False
            print(f"Bootstrap reuse unavailable; normal validation will run: {exc}")
        with open(args.github_output, "a", encoding="utf-8") as handle:
            handle.write(f"reused={str(hit).lower()}\n")
    else:
        evidence = json.loads(Path(args.evidence).read_bytes())
        repo = GitTreeRepository(args.repo_root)
        old = validate_trusted_artifact_plan(evidence["bootstrap_plan"])
        # Prospective merge commits are not necessarily reachable from current refs.
        try:
            repo.resolve_commit(old["merge_sha"])
        except TrustedArtifactPrError:
            repo.run("fetch", "--no-tags", "origin", old["merge_sha"])
        receipt = verify_reuse(repo_root=args.repo_root, plan=plan, gamever=args.gamever, evidence=evidence)
        _require(receipt == evidence["receipt"], "hosted receipt differs from current verification")
        _require(bool(args.output_root), "prepare requires an output root")
        destination = Path(args.output_root).resolve()
        _require(not destination.exists(), "reuse destination already exists")
        destination.mkdir(parents=True)
        artifacts, config = _materialize(
            GitTreeRepository(args.repo_root), plan["merge_sha"], args.gamever, destination
        )
        verification = destination / "validation.json"
        bootstrap._atomic_write(verification, bootstrap._canonical_json_bytes(receipt))
        execution = destination / "bootstrap-execution.json"
        bootstrap._atomic_write(execution, bootstrap._canonical_json_bytes(evidence["execution"]))
        with open(args.github_output, "a", encoding="utf-8") as handle:
            for key, value in {
                "actual-root": artifacts,
                "config": config,
                "verification": verification,
                "execution-report": execution,
                "preparation": args.evidence,
            }.items():
                handle.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

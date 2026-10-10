#!/usr/bin/env python3
"""Portable, content-bound inputs and evidence for hosted C++ ABI validation."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from ci_s3_cache import write_outputs
from gamesymbol_store import SymbolStoreError, open_snapshot_store
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import file_inventory, load_json_object, sha256_file, write_canonical_json
from run_cpp_tests import parse_config, select_platform_tests

PLATFORMS = ("windows", "linux")
INPUT_NAME = "cpp-input.json"
RESULT_NAME = "result.json"
LOG_NAME = "validation.log"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def git(repo_root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo_root), *args], text=True).strip()


def source_identity(repo_root: Path, source_sha: str) -> dict:
    if not SHA_RE.fullmatch(source_sha) or git(repo_root, "rev-parse", "HEAD") != source_sha:
        raise ValueError("C++ source checkout differs from the immutable source SHA")
    sdk_sha = git(repo_root, "rev-parse", f"{source_sha}:hl2sdk_cs2")
    sdk_root = repo_root / "hl2sdk_cs2"
    if git(sdk_root, "rev-parse", "HEAD") != sdk_sha:
        raise ValueError("C++ SDK differs from the source gitlink")
    if git(sdk_root, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("C++ SDK has modified tracked files")
    return {"source_sha": source_sha, "sdk_sha": sdk_sha}


def export_inputs(
    *, repo_root: Path, source_sha: str, gamever: str, snapshot: Path, config: Path, output: Path
) -> dict:
    identity = source_identity(repo_root, source_sha)
    store = open_snapshot_store(snapshot_path=snapshot, config_path=config, expected_game_version=gamever)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(snapshot, output / "snapshot.yaml")
    shutil.copyfile(config, output / "analysis-config.yaml")
    document = {
        "schema_version": 1,
        **identity,
        "gamever": gamever,
        "snapshot_sha256": store.candidate_sha256,
        "config_sha256": store.config_sha256,
        "config_file_sha256": sha256_file(config),
    }
    write_canonical_json(output / INPUT_NAME, document)
    return document


def validate_inputs(
    root: Path, *, repo_root: Path | None = None, source_sha: str | None = None, gamever: str | None = None
) -> dict:
    expected_files = {INPUT_NAME, "snapshot.yaml", "analysis-config.yaml"}
    if {item["path"] for item in file_inventory(root)} != expected_files:
        raise ValueError("C++ input inventory is invalid")
    document = load_json_object(root / INPUT_NAME)
    if set(document) != {
        "schema_version",
        "source_sha",
        "sdk_sha",
        "gamever",
        "snapshot_sha256",
        "config_sha256",
        "config_file_sha256",
    }:
        raise ValueError("C++ input descriptor is invalid")
    if (
        document["schema_version"] != 1
        or not SHA_RE.fullmatch(document["source_sha"])
        or not SHA_RE.fullmatch(document["sdk_sha"])
    ):
        raise ValueError("C++ input identity is invalid")
    if source_sha is not None and document["source_sha"] != source_sha:
        raise ValueError("C++ inputs belong to a different source SHA")
    if gamever is not None and document["gamever"] != gamever:
        raise ValueError("C++ inputs belong to a different GAMEVER")
    if sha256_file(root / "analysis-config.yaml") != document["config_file_sha256"]:
        raise ValueError("C++ configuration bytes changed")
    store = open_snapshot_store(
        snapshot_path=root / "snapshot.yaml",
        config_path=root / "analysis-config.yaml",
        expected_game_version=document["gamever"],
    )
    if store.candidate_sha256 != document["snapshot_sha256"] or store.config_sha256 != document["config_sha256"]:
        raise ValueError("C++ snapshot identity changed")
    if repo_root is not None and source_identity(repo_root, document["source_sha"]) != {
        "source_sha": document["source_sha"],
        "sdk_sha": document["sdk_sha"],
    }:
        raise ValueError("C++ SDK identity changed")
    return document


def validate_result(document: dict, inputs: dict, platform: str, configured: int) -> None:
    for field in ("gamever", "snapshot_sha256", "config_sha256"):
        if document.get(field) != inputs[field]:
            raise ValueError(f"C++ result {field} mismatch")
    if (
        document.get("platform") != platform
        or type(document.get("configured")) is not int
        or document["configured"] != configured
    ):
        raise ValueError("C++ result ABI or configured test count mismatch")
    if type(document.get("executed")) is not int:
        raise ValueError("C++ result has no execution count")
    if configured == 0:
        if document.get("status") != "no-tests" or document["executed"] != 0:
            raise ValueError("Empty C++ ABI must explicitly report no-tests")
    elif document.get("status") != "passed" or document["executed"] != configured:
        raise ValueError("Not every configured C++ test passed")


def run_validation(*, root: Path, repo_root: Path, platform: str, output: Path, source_sha: str, gamever: str) -> int:
    inputs = validate_inputs(root, repo_root=repo_root, source_sha=source_sha, gamever=gamever)
    output.mkdir(parents=True, exist_ok=False)
    result_path = output / "test-result.json"
    command = [
        sys.executable,
        str(Path(__file__).with_name("run_cpp_tests.py")),
        "-gamever",
        inputs["gamever"],
        "-snapshot",
        str(root / "snapshot.yaml"),
        "-configyaml",
        str(root / "analysis-config.yaml"),
        "--source-root",
        str(repo_root),
        "--platform",
        platform,
        "--allow-empty",
        "--result-json",
        str(result_path),
        "-debug",
    ]
    with (output / LOG_NAME).open("w", encoding="utf-8", newline="\n") as log:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace"
        )
        try:
            for line in process.stdout:
                print(line, end="", flush=True)
                log.write(line)
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()
        code = process.wait()
    if code:
        return code
    validate_inputs(root, repo_root=repo_root, source_sha=source_sha, gamever=gamever)
    result = load_json_object(result_path)
    configured = len(select_platform_tests(parse_config(root / "analysis-config.yaml"), platform))
    validate_result(result, inputs, platform, configured)
    receipt = {
        **result,
        "schema_version": 1,
        "source_sha": inputs["source_sha"],
        "sdk_sha": inputs["sdk_sha"],
        "config_file_sha256": inputs["config_file_sha256"],
        "log_sha256": sha256_file(output / LOG_NAME),
    }
    write_canonical_json(output / RESULT_NAME, receipt)
    return 0


def aggregate(*, root: Path, results: Path, output: Path) -> dict:
    inputs = validate_inputs(root)
    receipts = []
    combined = bytearray()
    tests = parse_config(root / "analysis-config.yaml")
    for platform in PLATFORMS:
        leg = results / platform
        receipt = load_json_object(leg / RESULT_NAME)
        for field in ("source_sha", "sdk_sha", "config_file_sha256"):
            if receipt.get(field) != inputs[field]:
                raise ValueError(f"C++ {platform} receipt {field} mismatch")
        if receipt.get("schema_version") != 1 or receipt.get("log_sha256") != sha256_file(leg / LOG_NAME):
            raise ValueError(f"C++ {platform} log digest mismatch")
        validate_result(receipt, inputs, platform, len(select_platform_tests(tests, platform)))
        combined.extend(f"=== {platform}: {receipt['status']} ({receipt['executed']} tests) ===\n".encode())
        combined.extend((leg / LOG_NAME).read_bytes())
        combined.extend(b"\n")
        receipts.append(receipt)
    output.mkdir(parents=True, exist_ok=False)
    (output / LOG_NAME).write_bytes(combined)
    document = {
        "schema_version": 1,
        "inputs": inputs,
        "results": receipts,
        "log_sha256": sha256_file(output / LOG_NAME),
    }
    write_canonical_json(output / "evidence.json", document)
    return document


def validate_evidence(root: Path, inputs: dict, config: Path) -> dict:
    evidence = load_json_object(root / "evidence.json")
    if evidence.get("schema_version") != 1 or evidence.get("inputs") != inputs:
        raise ValueError("C++ aggregate input identity mismatch")
    if evidence.get("log_sha256") != sha256_file(root / LOG_NAME):
        raise ValueError("C++ aggregate log digest mismatch")
    results = evidence.get("results", [])
    if len(results) != 2:
        raise ValueError("C++ aggregate must contain both ABIs")
    tests = parse_config(config)
    for platform, receipt in zip(PLATFORMS, results):
        for field in ("source_sha", "sdk_sha", "config_file_sha256"):
            if receipt.get(field) != inputs[field]:
                raise ValueError("C++ aggregate receipt identity mismatch")
        configured = len(select_platform_tests(tests, platform))
        validate_result(receipt, inputs, platform, configured)
    return evidence


def bind_artifact(artifact_id: str, digest: str) -> dict:
    if not artifact_id.isdecimal() or int(artifact_id) < 1:
        raise ValueError("Invalid Actions artifact ID")
    digest = digest.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Invalid Actions artifact digest")
    raw = subprocess.check_output(
        ["gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/artifacts/{artifact_id}"], text=True
    )
    artifact = json.loads(raw)
    if artifact.get("expired") or str(artifact.get("workflow_run", {}).get("id")) != os.environ["GITHUB_RUN_ID"]:
        raise ValueError("Actions artifact is expired or belongs to another run")
    if artifact.get("digest") != "sha256:" + digest:
        raise ValueError("Actions artifact digest mismatch")
    return artifact


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("--repo-root", type=Path, default=Path.cwd())
    export.add_argument("--source-sha", required=True)
    export.add_argument("--gamever", required=True)
    export.add_argument("--snapshot", type=Path, required=True)
    export.add_argument("--config", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("--root", type=Path, required=True)
    run.add_argument("--repo-root", type=Path, default=Path.cwd())
    run.add_argument("--source-sha", required=True)
    run.add_argument("--gamever", required=True)
    run.add_argument("--platform", choices=PLATFORMS, required=True)
    run.add_argument("--output", type=Path, required=True)
    merge = commands.add_parser("aggregate")
    merge.add_argument("--root", type=Path, required=True)
    merge.add_argument("--results", type=Path, required=True)
    merge.add_argument("--output", type=Path, required=True)
    bind = commands.add_parser("bind")
    bind.add_argument("--artifact-id", required=True)
    bind.add_argument("--digest", required=True)
    args = parser.parse_args(argv)
    try:
        options = vars(args).copy()
        options.pop("command")
        if args.command == "export":
            export_inputs(**options)
            write_outputs({"root": str(args.output)}, os.environ.get("GITHUB_OUTPUT"))
        elif args.command == "run":
            return run_validation(**options)
        elif args.command == "aggregate":
            aggregate(**options)
        else:
            bind_artifact(**options)
    except (OSError, ValueError, SymbolStoreError, ReleaseWorkflowError, subprocess.CalledProcessError) as exc:
        print(f"C++ validation evidence error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

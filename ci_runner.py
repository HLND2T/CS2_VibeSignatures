#!/usr/bin/env python3
"""Shared CI orchestration; shells only launch one checked Python command."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

import ci_s3_cache
from ci_cpp_validation import bind_artifact, export_inputs, source_identity, validate_evidence, validate_inputs
from release_workflow_lib.hashing import file_inventory, reject_reparse_components, sha256_file, write_canonical_json

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def env(name: str, default=None) -> str:
    value = os.environ.get(name, default)
    if value is None or not str(value).strip():
        raise ValueError(f"{name} is required")
    return str(value)


def workspace() -> Path:
    return Path(env("GITHUB_WORKSPACE")).resolve()


def temporary(*parts) -> Path:
    return Path(env("RUNNER_TEMP")).joinpath(*parts)


def run_key() -> str:
    return f"{env('GITHUB_RUN_ID')}-{env('GITHUB_RUN_ATTEMPT')}"


def emit(values: dict, *, environment=False):
    ci_s3_cache.write_outputs(values, os.environ.get("GITHUB_ENV" if environment else "GITHUB_OUTPUT"))


def command(args, *, capture=False):
    result = subprocess.run(
        [str(arg) for arg in args], check=True, text=True, encoding="utf-8", stdout=subprocess.PIPE if capture else None
    )
    return result.stdout.strip() if capture else None


def tool(script: str, *args, project: str | None = None, capture=False):
    prefix = ["uv", "run"] + (["--project", project] if project else [])
    path = str(Path(project) / script) if project else script
    return command([*prefix, "python", path, *args], capture=capture)


def document(script: str, *args, project: str | None = None) -> dict:
    return json.loads(tool(script, *args, project=project, capture=True))


def binary_tool() -> tuple[str, str | None]:
    kind = os.environ.get("CI_KIND", "warmup")
    if kind in ("bridge-warmup", "bridge-pr"):
        return "source_artifact_accepted_bin.py", ".trusted-tools"
    if kind == "pr":
        return "accepted_bin.py", ".trusted-tools"
    return "accepted_bin.py", None


def real_bin_root():
    root = workspace()
    target = root / "bin"
    reject_reparse_components(root, target)
    target.mkdir(exist_ok=True)


def require_lock(value):
    if not DIGEST_RE.fullmatch(str(value)):
        raise ValueError("Source binary lock digest is invalid")
    return value


def check_lock(result, expected):
    if require_lock(result.get("binary_lock_sha256")) != require_lock(expected):
        raise ValueError("Source binary lock identity drifted")


def accepted_restore():
    real_bin_root()
    kind = env("CI_KIND", "warmup")
    required = []
    expected = os.environ.get("BINARY_LOCK_SHA256")
    reused = os.environ.get("BOOTSTRAP_REUSED") == "true"
    if kind == "release":
        expected = env("SOURCE_BINARY_LOCK_SHA256")
        if env("SOURCE_ARTIFACT_MODE", "rebuild") != "tracked":
            if env("WARMUP_BINARY_LOCK_SHA256") != expected:
                raise ValueError("Release warmup differs from source preflight")
            required = ["--required"]
    elif kind in ("bootstrap", "pr", "bridge-pr"):
        source = env("SOURCE_SHA")
        if command(["git", "rev-parse", "HEAD"], capture=True).lower() != source.lower():
            raise ValueError("Source checkout drifted")
        plan_root = "source-artifact-plan" if kind == "bootstrap" else "trusted-pr-plan"
        plan = json.loads(
            Path(env("CI_PLAN", str(temporary(plan_root, "trusted-source-artifact-plan.json")))).read_text(
                encoding="utf-8"
            )
        )
        versions = [item for item in plan["game_versions"] if item["game_version"] == env("GAMEVER")]
        if len(versions) != 1:
            raise ValueError("Trusted plan does not select exactly one GAMEVER")
        if kind != "bootstrap" and not DIGEST_RE.fullmatch(env("PLAN_SHA256")):
            raise ValueError("Trusted plan digest is invalid")
        if reused:
            expected = versions[0]["merge_binary_lock_sha256"]
            os.environ["BINARY_LOCK_SHA256"] = expected
            emit({"BINARY_LOCK_SHA256": expected}, environment=True)
        if versions[0]["merge_binary_lock_sha256"] != require_lock(expected):
            raise ValueError("Warmup source binary lock differs from trusted plan")
        if kind != "bridge-pr" and not reused:
            required = ["--required"]
    script, project = binary_tool()
    result = document(
        script,
        "restore",
        "--repo-root",
        workspace(),
        "--persisted-root",
        env("CI_CACHE_ROOT"),
        "--gamever",
        env("GAMEVER"),
        *required,
        project=project,
    )
    if expected:
        check_lock(result, expected)
    else:
        expected = require_lock(result.get("binary_lock_sha256"))
        emit({"BINARY_LOCK_SHA256": expected}, environment=True)
    if kind in ("pr", "bridge-pr"):
        init_binaries()
        check_lock(
            document(script, "verify", "--repo-root", workspace(), "--gamever", env("GAMEVER"), project=project),
            expected,
        )


def accepted_verify():
    script, project = binary_tool()
    check_lock(
        document(script, "verify", "--repo-root", workspace(), "--gamever", env("GAMEVER"), project=project),
        env("BINARY_LOCK_SHA256"),
    )


def accepted_stage():
    result = document(
        "accepted_bin.py",
        "sync",
        "--repo-root",
        workspace(),
        "--persisted-root",
        env("CI_CACHE_ROOT"),
        "--gamever",
        env("GAMEVER"),
        project=".cache-tools",
    )
    expected = os.environ.get("BINARY_LOCK_SHA256") or os.environ.get("SOURCE_BINARY_LOCK_SHA256")
    if expected:
        check_lock(result, expected)
    emit({"binary-lock-sha256": require_lock(result.get("binary_lock_sha256"))})


def init_binaries():
    tool("init_gamebin.py", "prepare", env("GAMEVER"), "--binsync", "skip")


def host_tool(name):
    # uv prepends the workflow's dependency venv. IDA belongs to the runner's
    # separate installation, so discover it on the original host PATH.
    excluded = [Path(sys.prefix).resolve(), workspace() / ".venv", workspace() / ".cache-tools" / ".venv"]
    paths = [
        entry
        for entry in os.get_exec_path()
        if not any(Path(entry).absolute().is_relative_to(root) for root in excluded)
    ]
    found = shutil.which(name, path=os.pathsep.join(paths))
    if not found:
        raise ValueError(f"Runner tool {name} is unavailable on the host PATH")
    return str(Path(found).absolute())


def resolve_ida(*, consumer=False):
    python = host_tool("python")
    version = command([python, "warmup_idb_worker.py", "--print-ida-version"], capture=True)
    if not version:
        raise ValueError("IDA did not report its runtime version")
    if consumer:
        mcp = host_tool("idalib-mcp")
        python_dir, mcp_dir = Path(python).parent, Path(mcp).parent
        allowed = (python_dir, python_dir / "Scripts")
        if os.path.normcase(str(mcp_dir)) not in {os.path.normcase(str(path)) for path in allowed}:
            # POSIX entry points may live outside the venv but name its Python.
            shebang = (
                Path(mcp).read_bytes().split(b"\n", 1)[0].decode("utf-8", errors="replace") if os.name != "nt" else ""
            )
            if not shebang.startswith("#!/") or Path(shebang[2:].strip()).resolve() != Path(python).resolve():
                raise ValueError("python and idalib-mcp resolve to different installations")
        host_tool(os.environ.get("CS2VIBE_AGENT") or "claude")
    emit({"python": python, "ida-version": version, "ida_runtime_identity": version})
    emit({"IDA_PYTHON": python, "IDA_VERSION": version}, environment=True)
    os.environ.update(IDA_PYTHON=python, IDA_VERSION=version)


def idb(operation):
    if operation == "restore" and not os.environ.get("IDA_VERSION"):
        resolve_ida(consumer=True)
    args = [
        operation,
        "--repo-root",
        workspace(),
        "--persisted-root",
        env("CI_CACHE_ROOT"),
        "--gamever",
        env("GAMEVER"),
        "--ida-version",
        env("IDA_VERSION"),
        "--repository",
        env("GITHUB_REPOSITORY"),
        "--run-id",
        env("GITHUB_RUN_ID"),
        "--run-attempt",
        env("GITHUB_RUN_ATTEMPT"),
    ]
    if operation == "restore":
        args += [
            "--generation",
            env("IDB_CACHE_GENERATION"),
            "--cache-key",
            env("IDB_CACHE_KEY"),
            "--lease-id",
            env("IDB_CACHE_LEASE_ID"),
            "--lease-sha256",
            env("IDB_CACHE_LEASE_SHA256"),
        ]
    elif operation == "publish":
        args += ["--generation-suffix", run_key()]
    result = document("idb_cache.py", *args, project=".cache-tools")
    outputs = {key.replace("_", "-"): value for key, value in result.items() if not isinstance(value, (dict, list))}
    emit(outputs)
    if operation in ("probe", "publish") and result.get("cache_hit", operation == "publish"):
        emit(
            {
                "IDB_CACHE_GENERATION": result["generation"],
                "IDB_CACHE_KEY": result["cache_key"],
                "IDB_CACHE_LEASE_ID": result["lease_id"],
                "IDB_CACHE_LEASE_SHA256": result["lease_sha256"],
            },
            environment=True,
        )


def resolve_selection():
    selection = {
        "generation": env("IDB_CACHE_GENERATION"),
        "cache-key": env("IDB_CACHE_KEY"),
        "lease-id": env("IDB_CACHE_LEASE_ID"),
        "lease-sha256": env("IDB_CACHE_LEASE_SHA256"),
    }
    if not re.fullmatch(r"[0-9a-f]{64}-[0-9]+-[0-9]+", selection["generation"]) or not re.fullmatch(
        r"[0-9a-f]{64}", selection["cache-key"]
    ):
        raise ValueError("Warm IDB generation selection is invalid")
    if not re.fullmatch(r"[0-9a-f]{32}", selection["lease-id"]) or not re.fullmatch(
        r"[0-9a-f]{64}", selection["lease-sha256"]
    ):
        raise ValueError("Warm IDB lease selection is invalid")
    emit(selection)


def warmup():
    tool(
        "warmup_idb.py",
        env("GAMEVER"),
        "--python",
        env("IDA_PYTHON"),
        "--max-concurrency",
        os.environ.get("IDB_WARMUP_MAX_CONCURRENCY") or "2",
        "--force",
    )


def resolve_config():
    config = workspace() / "configs" / f"{env('GAMEVER')}.yaml"
    emit({"ANALYSIS_CONFIG": str(config), "ANALYSIS_CONFIG_SHA256": sha256_file(config)}, environment=True)


def pr_paths():
    key = f"{run_key()}-{env('GAMEVER')}"
    emit(
        {
            "staging": str(temporary("trusted-pr-rebuild", key)),
            "diagnostics": str(temporary("trusted-pr-diagnostics", key)),
            "plan": str(temporary("trusted-pr-plan", "trusted-source-artifact-plan.json")),
        }
    )


def pr_prepare():
    gamever = env("GAMEVER")
    staging = Path(env("CI_STAGING", str(temporary("trusted-pr-rebuild", f"{run_key()}-{gamever}"))))
    plan = env("CI_PLAN", str(temporary("trusted-pr-plan", "trusted-source-artifact-plan.json")))
    if os.environ.get("BOOTSTRAP_REUSED") == "true":
        tool(
            "bootstrap_reuse.py",
            "prepare",
            "--repo-root",
            workspace(),
            "--plan",
            plan,
            "--gamever",
            gamever,
            "--plan-sha256",
            env("PLAN_SHA256"),
            "--output-root",
            staging,
            "--evidence",
            temporary("trusted-bootstrap-reuse", "bootstrap-reuse.json"),
            "--github-output",
            env("GITHUB_OUTPUT"),
            project=".trusted-tools",
        )
        return
    args = ["prepare", "--repo-root", workspace(), "--plan", plan, "--gamever", gamever, "--staging-root", staging]
    if env("CI_KIND") == "pr":
        args += ["--plan-sha256", env("PLAN_SHA256"), "--diagnostics-dir", env("CI_DIAGNOSTICS")]
    tool("trusted_artifact_pr.py", *args, project=".trusted-tools")
    preparation = staging / "preparation.json"
    data = json.loads(preparation.read_text(encoding="utf-8"))
    if data["plan_sha256"] != env("PLAN_SHA256"):
        raise ValueError("Preparation is not bound to the trusted plan")
    report = data["execution_reports"].get(gamever)
    if not report:
        raise ValueError("Preparation omitted execution evidence")
    emit(
        {
            "plan": plan,
            "preparation": str(preparation),
            "strategy": data.get("execution_strategy", ""),
            "actual-root": data["actual_artifact_root"],
            "config": str(Path(data["config_root"]) / f"{gamever}.yaml"),
            "execution-report": report,
            "selected-manifest": data.get("selected_execution_manifests", {}).get(gamever) or "",
            "verification": str(staging / "validation.json"),
        }
    )


def pr_execute():
    args = [
        "-gamever",
        env("GAMEVER"),
        "-configyaml",
        env("CI_CONFIG"),
        "-bindir",
        "bin",
        "-artifactdir",
        env("CI_ACTUAL_ROOT"),
        "-oldartifactdir",
        "bin_artifacts",
        "-execution_report",
        env("CI_EXECUTION_REPORT"),
        "-require_warm_idb",
        "-debug",
    ]
    if env("CI_KIND") == "pr":
        args += ["-parallel_platforms", temporary(f"pr-platform-analysis-{run_key()}-{env('GAMEVER')}")]
    if os.environ.get("CI_STRATEGY") == "base-inherited-selected-v1":
        args += ["-selected_execution", env("CI_SELECTED_MANIFEST")]
    else:
        args += ["-force_all"]
    tool("ida_analyze_bin.py", *args)


def pr_verify():
    args = [
        "verify",
        "--repo-root",
        workspace(),
        "--plan",
        env("CI_PLAN"),
        "--preparation",
        env("CI_PREPARATION"),
        "--output",
        env("CI_VERIFICATION"),
    ]
    if env("CI_KIND") == "pr":
        args += [
            "--staging-root",
            env("CI_STAGING"),
            "--gamever",
            env("GAMEVER"),
            "--plan-sha256",
            env("PLAN_SHA256"),
            "--diagnostics-dir",
            env("CI_DIAGNOSTICS"),
        ]
    tool("trusted_artifact_pr.py", *args, project=".trusted-tools")


def downstream():
    root = temporary("trusted-pr-downstream", f"{run_key()}-{env('GAMEVER')}")
    root.mkdir(parents=True, exist_ok=True)
    snapshot, session = root / f"{env('GAMEVER')}.yaml", root / f"{env('GAMEVER')}.session.json"
    config = env("CI_CONFIG")
    tool(
        "gamesymbol_candidate.py",
        "build",
        "-gamever",
        env("GAMEVER"),
        "-bindir",
        "bin",
        "-artifactdir",
        env("CI_ACTUAL_ROOT"),
        "-configyaml",
        config,
        "-output",
        snapshot,
        "-session",
        session,
    )
    tool(
        "gamedata_candidate.py",
        "build",
        "-gamever",
        env("GAMEVER"),
        "-build-id",
        run_key(),
        "-snapshot",
        snapshot,
        "-configyaml",
        config,
        "-candidate-root",
        root / "gamedata",
        "-session",
        root / "gamedata.session.json",
        "-debug",
    )
    tool("gamedata_candidate.py", "guard", "-session", root / "gamedata.session.json")
    output = root / "cpp-inputs"
    export_inputs(
        repo_root=workspace(),
        source_sha=env("SOURCE_SHA"),
        gamever=env("GAMEVER"),
        snapshot=snapshot,
        config=Path(config),
        output=output,
    )
    emit({"snapshot": str(snapshot), "cpp-input-root": str(output)})


def pr_diagnose():
    original = Path(env("CI_DIAGNOSTICS"))
    diagnostics = Path(f"{original}-{uuid.uuid4().hex}")
    emit({"diagnostics": str(diagnostics)})
    phase = next(
        (
            name
            for name in ("prepare", "execute", "verify")
            if os.environ.get(f"CI_{name.upper()}_OUTCOME") == "failure"
        ),
        "downstream",
    )
    tool(
        "trusted_artifact_pr.py",
        "diagnose",
        "--repo-root",
        workspace(),
        "--plan",
        env("CI_PLAN"),
        "--plan-sha256",
        env("PLAN_SHA256"),
        "--gamever",
        env("GAMEVER"),
        "--staging-root",
        env("CI_STAGING"),
        "--diagnostics-dir",
        diagnostics,
        "--phase",
        phase,
        "--error",
        f"{phase} workflow step failed; original error is retained in that step's job log.",
        "--error-file",
        original / "verification-error.txt",
        project=".trusted-tools",
    )


def release_prepare():
    staging = temporary("release-artifact-rebuild", env("BUILD_ID"))
    args = ["--full-rebuild"] if env("SOURCE_ARTIFACT_MODE", "rebuild") == "full-rebuild" else []
    tool(
        "release_artifact_rebuild.py",
        "prepare",
        "--repo-root",
        workspace(),
        "--source-sha",
        env("SOURCE_SHA"),
        "--gamever",
        env("GAMEVER"),
        "--binary-root",
        "bin",
        "--staging-root",
        staging,
        *args,
    )
    preparation = staging / "release-rebuild-preparation.json"
    data = json.loads(preparation.read_text(encoding="utf-8"))
    emit(
        {
            "RELEASE_REBUILD_PREPARATION": str(preparation),
            "RELEASE_REBUILD_VERIFICATION": str(staging / "release-rebuild-verification.json"),
            "ACTUAL_ARTIFACT_ROOT": data["actual_artifact_root"],
            "RELEASE_ARTIFACT_ROOT": str(workspace() / "bin_artifacts"),
            "FORCE_ALL_EXECUTION_REPORT": data["execution_report"],
            "RELEASE_REBUILD_DIAGNOSTICS": str(
                temporary("release-rebuild-diagnostics", f"{run_key()}-{env('GAMEVER')}")
            ),
        },
        environment=True,
    )


def release_analyze():
    full = env("SOURCE_ARTIFACT_MODE", "rebuild") == "full-rebuild"
    args = [
        "-gamever",
        env("GAMEVER"),
        "-configyaml",
        env("ANALYSIS_CONFIG"),
        "-bindir",
        "bin",
        "-artifactdir",
        env("ACTUAL_ARTIFACT_ROOT"),
        "-oldartifactdir",
        env("ACTUAL_ARTIFACT_ROOT") if full else "bin_artifacts",
        "-execution_report",
        env("FORCE_ALL_EXECUTION_REPORT"),
        "-parallel_platforms",
        temporary(f"release-platform-analysis-{run_key()}-{env('GAMEVER')}"),
        "-require_warm_idb",
        "-force_all",
        "-rename",
        "-debug",
    ]
    if full:
        args += ["-oldgamever", "none"]
    tool("ida_analyze_bin.py", *args)


def release_verify():
    tool(
        "release_artifact_rebuild.py",
        "verify",
        "--repo-root",
        workspace(),
        "--preparation",
        env("RELEASE_REBUILD_PREPARATION"),
        "--output",
        env("RELEASE_REBUILD_VERIFICATION"),
        "--diagnostics-dir",
        env("RELEASE_REBUILD_DIAGNOSTICS"),
    )


def release_bind():
    binding = Path(env("RELEASE_REBUILD_PREPARATION")).parent / "tracked-artifact-binding.json"
    tool(
        "release_artifact_rebuild.py",
        "bind-tracked",
        "--repo-root",
        workspace(),
        "--preparation",
        env("RELEASE_REBUILD_PREPARATION"),
        "--output",
        binding,
    )
    emit(
        {
            "RELEASE_TRACKED_BINDING": str(binding),
            "ACTUAL_ARTIFACT_ROOT": str(workspace() / "bin_artifacts"),
            "RELEASE_ARTIFACT_ROOT": str(workspace() / "bin_artifacts"),
        },
        environment=True,
    )


def release_binsync():
    root = temporary("release-binsync-candidate", env("BUILD_ID"))
    name = f"binsync-candidate-{env('SOURCE_SHA')}-{env('GAMEVER')}"
    tool(
        "push_binsync_symbols.py",
        env("GAMEVER"),
        "--prepare-only",
        "--candidate-dir",
        root,
        "--artifactdir",
        env("RELEASE_ARTIFACT_ROOT"),
        "--preparation",
        env("RELEASE_REBUILD_PREPARATION"),
        "--release-version",
        env("GAMEVER"),
        "--build-id",
        env("BUILD_ID"),
        "--ida-runtime-identity",
        env("IDA_VERSION"),
        "--actions-artifact-name",
        name,
        "--binsync-user",
        "release-automation",
        "--python",
        env("IDA_PYTHON"),
    )
    emit({"BINSYNC_CANDIDATE_ROOT": str(root)}, environment=True)
    emit({"artifact_name": name})


def release_candidates():
    root = temporary("release-candidates", env("BUILD_ID"))
    root.mkdir(parents=True, exist_ok=True)
    gamever = env("GAMEVER")
    snapshot, session = root / f"{gamever}.yaml", root / f"{gamever}.session.json"
    gamedata_root, gamedata_session = root / "gamedata-candidate", root / f"{gamever}.gamedata.session.json"
    metadata = root / f"{gamever}.metadata.yaml"
    emit(
        {
            "CANDIDATE_ROOT": str(root),
            "ACTUAL_CANDIDATE_SNAPSHOT": str(snapshot),
            "CANDIDATE_SESSION": str(session),
            "GAMEDATA_CANDIDATE_ROOT": str(gamedata_root),
            "GAMEDATA_SESSION": str(gamedata_session),
            "CANDIDATE_METADATA": str(metadata),
        },
        environment=True,
    )
    tool(
        "gamesymbol_candidate.py",
        "build",
        "-gamever",
        gamever,
        "-bindir",
        "bin",
        "-artifactdir",
        env("RELEASE_ARTIFACT_ROOT"),
        "-configyaml",
        env("ANALYSIS_CONFIG"),
        "-output",
        snapshot,
        "-session",
        session,
        "-last-publish-time",
        env("RELEASE_PUBLISH_TIME"),
    )
    tool("gamesymbol_candidate.py", "guard", "-candidate", snapshot, "-session", session)
    tool(
        "gamedata_candidate.py",
        "build",
        "-gamever",
        gamever,
        "-build-id",
        env("BUILD_ID"),
        "-snapshot",
        snapshot,
        "-configyaml",
        env("ANALYSIS_CONFIG"),
        "-candidate-root",
        gamedata_root,
        "-session",
        gamedata_session,
        "-debug",
    )
    tool("gamedata_candidate.py", "guard", "-session", gamedata_session)
    tool(
        "gamesymbol_metadata.py",
        "generate",
        "-gamever",
        gamever,
        "-configyaml",
        env("ANALYSIS_CONFIG"),
        "-output",
        metadata,
    )
    tool("gamesymbol_candidate.py", "guard", "-candidate", snapshot, "-session", session)
    tool("gamesymbol_candidate.py", "mark", "-candidate", snapshot, "-session", session, "-step", "gamedata")


def select_sdk():
    identity = source_identity(workspace(), env("SOURCE_SHA"))
    emit({"SDK_ABI_REF": "source-gitlink", "SDK_ABI_SHA": identity["sdk_sha"]}, environment=True)


def release_bundle_prepare():
    root = temporary("prepared-release", env("BUILD_ID"))
    name = f"release-bundle-{env('SOURCE_SHA')}-{env('GAMEVER')}"
    tracked = env("SOURCE_ARTIFACT_MODE", "rebuild") == "tracked"
    args = (
        ["--tracked-binding", env("RELEASE_TRACKED_BINDING")]
        if tracked
        else ["--rebuild-verification", env("RELEASE_REBUILD_VERIFICATION")]
    )
    if not tracked:
        args += [
            "--binsync-candidate-root",
            env("BINSYNC_CANDIDATE_ROOT"),
            "--ida-runtime-identity",
            env("IDA_VERSION"),
            "--warm-idb-generation",
            env("IDB_CACHE_GENERATION"),
            "--warm-idb-cache-key",
            env("IDB_CACHE_KEY"),
        ]
    tool(
        "release_bundle.py",
        "prepare",
        "--repo-root",
        workspace(),
        "--bundle-root",
        root,
        "--repository",
        env("GITHUB_REPOSITORY"),
        "--release-version",
        env("GAMEVER"),
        "--build-id",
        env("BUILD_ID"),
        "--preparation",
        env("RELEASE_REBUILD_PREPARATION"),
        *args,
        "--snapshot",
        env("ACTUAL_CANDIDATE_SNAPSHOT"),
        "--metadata",
        env("CANDIDATE_METADATA"),
        "--gamedata-candidate-root",
        env("GAMEDATA_CANDIDATE_ROOT"),
        "--gamedata-session",
        env("GAMEDATA_SESSION"),
        "--actions-artifact-name",
        name,
        "--cpp-sdk-ref",
        env("SDK_ABI_REF"),
        "--cpp-sdk-sha",
        env("SDK_ABI_SHA"),
        project=".cache-tools",
    )
    emit({"RELEASE_BUNDLE_ROOT": str(root)}, environment=True)
    emit({"artifact_name": "prepared-" + name})


def cleanup():
    temp = Path(env("RUNNER_TEMP")).resolve()
    for name in ("CANDIDATE_ROOT", "BINSYNC_CANDIDATE_ROOT", "RELEASE_BUNDLE_ROOT"):
        value = os.environ.get(name)
        if not value:
            continue
        path = Path(value).absolute()
        reject_reparse_components(temp, path)
        if path == temp or not path.is_relative_to(temp):
            raise ValueError("Candidate cleanup path is outside RUNNER_TEMP")
        if path.exists():
            shutil.rmtree(path)


def bootstrap_analyze():
    actual = temporary("new-gamever-bin-artifacts", run_key())
    candidate = temporary("bootstrap-binsync-local-only", run_key())
    report = temporary(f"new-gamever-force-all-execution-{run_key()}.json")
    actual.mkdir(parents=True, exist_ok=False)
    emit({"ACTUAL_ARTIFACT_ROOT": str(actual), "EXECUTION_REPORT": str(report)}, environment=True)
    tool(
        "ida_analyze_bin.py",
        "-gamever",
        env("GAMEVER"),
        "-configyaml",
        f"configs/{env('GAMEVER')}.yaml",
        "-bindir",
        "bin",
        "-artifactdir",
        actual,
        "-oldartifactdir",
        "bin_artifacts",
        "-oldgamever",
        env("PRIOR_GAMEVER"),
        "-require_warm_idb",
        "-force_all",
        "-execution_report",
        report,
        "-rename",
        "-debug",
    )
    tool(
        "push_binsync_symbols.py",
        env("GAMEVER"),
        "--prepare-only",
        "--no-publication-candidate",
        "--bootstrap-local-init",
        "--candidate-dir",
        candidate,
        "--artifactdir",
        actual,
        "--binsync-user",
        "bootstrap-validation",
        "--python",
        env("IDA_PYTHON"),
    )
    evidence = json.loads((candidate / "local-evidence.json").read_text(encoding="utf-8"))
    emit(
        {
            "remote_refs_before": evidence["remote_refs_before_sha256"],
            "remote_refs_after": evidence["remote_refs_after_sha256"],
        }
    )


def bootstrap_gates():
    root = temporary("new-gamever-gates", run_key())
    root.mkdir(parents=True, exist_ok=True)
    gamever = env("GAMEVER")
    snapshot, session = root / f"{gamever}.yaml", root / f"{gamever}.session.json"
    config = workspace() / "configs" / f"{gamever}.yaml"
    tool(
        "gamesymbol_candidate.py",
        "build",
        "-gamever",
        gamever,
        "-bindir",
        "bin",
        "-artifactdir",
        env("ACTUAL_ARTIFACT_ROOT"),
        "-configyaml",
        config,
        "-output",
        snapshot,
        "-session",
        session,
    )
    gamedata_session = root / "gamedata.session.json"
    tool(
        "gamedata_candidate.py",
        "build",
        "-gamever",
        gamever,
        "-build-id",
        run_key(),
        "-snapshot",
        snapshot,
        "-configyaml",
        config,
        "-modulesdir",
        "gamedata-generators",
        "-candidate-root",
        root / "gamedata",
        "-session",
        gamedata_session,
    )
    tool("gamedata_candidate.py", "guard", "-session", gamedata_session)
    export_inputs(
        repo_root=workspace(),
        source_sha=env("SOURCE_SHA"),
        gamever=gamever,
        snapshot=snapshot,
        config=config,
        output=root / "cpp-inputs",
    )
    emit({"snapshot": "sha256:" + sha256_file(snapshot), "gamedata": "sha256:" + sha256_file(gamedata_session)})


def bootstrap_package():
    root = temporary("new-gamever-prepared", run_key())
    root.mkdir(parents=True, exist_ok=False)
    shutil.copytree(Path(env("ACTUAL_ARTIFACT_ROOT")) / env("GAMEVER"), root / "bin_artifacts" / env("GAMEVER"))
    shutil.copyfile(env("EXECUTION_REPORT"), root / "force-all-execution.json")
    gates_root = temporary("new-gamever-gates", run_key())
    shutil.copytree(gates_root / "cpp-inputs", root / "cpp-inputs")
    # The guarded session is bound to this runner's paths/inodes. Only its
    # digest and the validated content cross the runner boundary.
    shutil.copytree(gates_root / "gamedata", root / "gamedata")
    write_canonical_json(
        root / "prepared-gates.json",
        {
            "schema_version": 2,
            "binsync_mode": "local-only",
            "remote_refs_before_sha256": env("CI_REFS_BEFORE"),
            "remote_refs_after_sha256": env("CI_REFS_AFTER"),
            "snapshot_sha256": env("CI_SNAPSHOT_DIGEST"),
            "gamedata_sha256": env("CI_GAMEDATA_DIGEST"),
            "gamedata_files": file_inventory(root / "gamedata"),
        },
    )
    emit({"CANDIDATE_PACKAGE": str(root)}, environment=True)
    emit({"candidate-artifact-name": f"prepared-new-gamever-{env('PR_NUMBER')}-{env('GAMEVER')}-{run_key()}"})


def bootstrap_finalize():
    prepared = Path(env("CI_PREPARED_ROOT", str(temporary("prepared-bootstrap"))))
    inputs = validate_inputs(
        prepared / "cpp-inputs", repo_root=workspace(), source_sha=env("SOURCE_SHA"), gamever=env("GAMEVER")
    )
    evidence = validate_evidence(
        Path(env("CI_CPP_EVIDENCE", str(temporary("cpp-evidence")))),
        inputs,
        prepared / "cpp-inputs" / "analysis-config.yaml",
    )
    gates = json.loads((prepared / "prepared-gates.json").read_text(encoding="utf-8"))
    if (
        gates["snapshot_sha256"] != inputs["snapshot_sha256"]
        or not DIGEST_RE.fullmatch(gates["gamedata_sha256"])
        or not gates.get("gamedata_files")
        or gates.pop("gamedata_files") != file_inventory(prepared / "gamedata")
    ):
        raise ValueError("Prepared bootstrap gate identities changed")
    gates["cpp_validation_sha256"] = "sha256:" + evidence["log_sha256"]
    root = temporary("new-gamever-package", run_key())
    root.mkdir(parents=True, exist_ok=False)
    shutil.copytree(prepared / "bin_artifacts", root / "bin_artifacts")
    shutil.copyfile(prepared / "force-all-execution.json", root / "force-all-execution.json")
    write_canonical_json(root / "gate-evidence.json", gates)
    tool(
        "new_gamever_artifact.py",
        "build",
        "--repo-root",
        workspace(),
        "--plan",
        env("CI_PLAN", str(temporary("source-artifact-plan", "trusted-source-artifact-plan.json"))),
        "--artifact-root",
        root / "bin_artifacts",
        "--output-manifest",
        root / "candidate-manifest.json",
        "--repository",
        env("GITHUB_REPOSITORY"),
        "--pr-number",
        env("PR_NUMBER"),
        "--workflow-run-id",
        env("GITHUB_RUN_ID"),
        "--workflow-run-attempt",
        env("GITHUB_RUN_ATTEMPT"),
        "--gate-evidence",
        root / "gate-evidence.json",
        "--execution-report",
        root / "force-all-execution.json",
        project=".cache-tools",
    )
    emit({"CANDIDATE_PACKAGE": str(root)}, environment=True)
    emit({"candidate-artifact-name": f"new-gamever-artifacts-{env('PR_NUMBER')}-{env('GAMEVER')}-{run_key()}"})


def bump_enroll():
    host_tool("DepotDownloader")
    gamever = env("CANDIDATE_GAMEVER")
    root = temporary("bump-binary-enrollment", f"{run_key()}-{gamever}")
    if root.exists():
        raise ValueError("Fresh binary enrollment root already exists")
    (root / "depot").mkdir(parents=True)
    (root / "bin").mkdir()
    tool(
        "download_depot.py",
        "-tag",
        gamever,
        "-config",
        "download.yaml",
        "-configyaml",
        f"configs/{gamever}.yaml",
        "-depotdir",
        root / "depot",
        "-username",
        env("DEPOTDOWNLOADER_STEAM_USERNAME"),
        "-password",
        env("DEPOTDOWNLOADER_STEAM_PASSWORD"),
        "-remember-password",
    )
    tool(
        "copy_depot_bin.py",
        "-gamever",
        gamever,
        "-platform",
        "all-platform",
        "-config",
        f"configs/{gamever}.yaml",
        "-depotdir",
        root / "depot",
        "-bindir",
        root / "bin",
    )
    data = document(
        "bump_download_candidate.py",
        "enroll-lock",
        "--repo-root",
        workspace(),
        "--base-sha",
        env("GITHUB_SHA"),
        "--gamever",
        gamever,
        "--source-gamever",
        env("CANDIDATE_SOURCE_GAMEVER"),
        "--repository",
        env("GITHUB_REPOSITORY"),
        "--binary-root",
        root / "bin" / gamever,
    )
    emit({"binary_lock_sha256": require_lock(data.get("binary_lock_sha256"))})


def bump_package():
    gamever = env("CANDIDATE_GAMEVER")
    root = temporary("bump-download-candidate", run_key())
    tool(
        "bump_download_candidate.py",
        "build",
        "--repo-root",
        workspace(),
        "--base-sha",
        env("GITHUB_SHA"),
        "--gamever",
        gamever,
        "--source-gamever",
        env("CANDIDATE_SOURCE_GAMEVER"),
        "--repository",
        env("GITHUB_REPOSITORY"),
        "--workflow-run-id",
        env("GITHUB_RUN_ID"),
        "--workflow-run-attempt",
        env("GITHUB_RUN_ATTEMPT"),
        "--output-root",
        root,
    )
    emit({"artifact_name": f"bump-download-candidate-{gamever}-{run_key()}", "run_attempt": env("GITHUB_RUN_ATTEMPT")})
    emit({"CANDIDATE_ROOT": str(root)}, environment=True)


def bump_sync():
    command(["git", "config", "--global", "--add", "safe.directory", workspace().as_posix()])
    command(["git", "fetch", "origin", "--prune", "--prune-tags", "--tags", "+refs/heads/*:refs/remotes/origin/*"])
    if command(["git", "rev-parse", "HEAD"], capture=True).lower() != env("GITHUB_SHA").lower():
        raise ValueError("Bump checkout drifted from the immutable workflow SHA")


def bump_apply(*, preview=False):
    host_tool("DepotDownloader")
    tool(
        "bump_download.py",
        "-config",
        "download.yaml",
        "-configs-dir",
        "configs",
        "-depotdir",
        "cs2_depot",
        "-username",
        env("DEPOTDOWNLOADER_STEAM_USERNAME"),
        "-password",
        env("DEPOTDOWNLOADER_STEAM_PASSWORD"),
        "-remember-password",
        *(["-dry-run"] if preview else []),
        "-github-output",
        env("GITHUB_OUTPUT"),
    )


def sync_submodules():
    command(["git", "submodule", "sync", "--recursive"])
    command(["git", "submodule", "update", "--init", "--recursive", "--depth", "1", "--jobs", "8"])


def repo_tests():
    tool("format_repo_files.py", "--check")
    tool("tests/run_test_suite.py", "all", "-b", "--durations", "30")


def configure_git():
    command(["git", "config", "user.name", "github-actions[bot]"])
    command(["git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"])


def reject_restored():
    raise ValueError("Restored S3 IDB generation failed identity or integrity validation")


def release_finalize():
    from release_bundle import finalize_release_bundle

    root = temporary("release-bundle", env("SOURCE_SHA"))
    manifest = finalize_release_bundle(
        repo_root=workspace(),
        prepared_root=env("CI_PREPARED_ROOT", str(temporary("prepared-release"))),
        bundle_root=root,
        cpp_evidence_root=env("CI_CPP_EVIDENCE", str(temporary("cpp-evidence"))),
    )
    emit({"RELEASE_BUNDLE_ROOT": str(root)}, environment=True)
    emit({"artifact_name": manifest["actions_artifact_name"]})


def bind_current_artifact():
    bind_artifact(
        env("CI_ARTIFACT_ID", os.environ.get("INPUT_ARTIFACT_ID")),
        env("CI_ARTIFACT_DIGEST", os.environ.get("INPUT_ARTIFACT_DIGEST")),
    )


def cache_command(operation):
    if ci_s3_cache.main([operation]) != 0:
        raise ValueError(f"Cache {operation} failed")


def cpp_run():
    from ci_cpp_validation import run_validation

    code = run_validation(
        root=temporary("cpp-input-artifact", os.environ.get("INPUT_PATH", ".")),
        repo_root=workspace(),
        platform=env("ABI_PLATFORM"),
        output=temporary("cpp-result"),
        source_sha=env("SOURCE_SHA"),
        gamever=env("GAMEVER"),
    )
    if code:
        raise ValueError(f"C++ validation failed with exit code {code}")


COMMANDS = {
    "accepted-restore": accepted_restore,
    "accepted-verify": accepted_verify,
    "accepted-stage": accepted_stage,
    "init-binaries": init_binaries,
    "resolve-ida": resolve_ida,
    "resolve-consumer-ida": lambda: resolve_ida(consumer=True),
    "idb-probe": lambda: idb("probe"),
    "idb-publish": lambda: idb("publish"),
    "idb-restore": lambda: idb("restore"),
    "resolve-selection": resolve_selection,
    "warmup": warmup,
    "resolve-config": resolve_config,
    "pr-paths": pr_paths,
    "pr-prepare": pr_prepare,
    "pr-execute": pr_execute,
    "pr-verify": pr_verify,
    "downstream": downstream,
    "pr-diagnose": pr_diagnose,
    "release-prepare": release_prepare,
    "release-analyze": release_analyze,
    "release-verify": release_verify,
    "release-bind": release_bind,
    "release-binsync": release_binsync,
    "release-candidates": release_candidates,
    "select-sdk": select_sdk,
    "release-bundle-prepare": release_bundle_prepare,
    "cleanup": cleanup,
    "bootstrap-analyze": bootstrap_analyze,
    "bootstrap-gates": bootstrap_gates,
    "bootstrap-package": bootstrap_package,
    "bootstrap-finalize": bootstrap_finalize,
    "bump-enroll": bump_enroll,
    "bump-package": bump_package,
    "bump-sync": bump_sync,
    "bump-preview": lambda: bump_apply(preview=True),
    "bump-apply": bump_apply,
    "sync-submodules": sync_submodules,
    "repo-tests": repo_tests,
    "configure-git": configure_git,
    "reject-restored": reject_restored,
    "release-finalize": release_finalize,
    "bind-artifact": bind_current_artifact,
    "sync-trusted": lambda: command(["uv", "sync", "--project", ".trusted-tools", "--locked"]),
    "cpp-run": cpp_run,
    **{
        f"cache-{name}": (lambda name=name: cache_command(name))
        for name in ("prepare", "identity", "selection", "depot-ready", "verify-restored")
    },
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", default=os.environ.get("CI_RUNNER_COMMAND"), choices=COMMANDS)
    args = parser.parse_args(argv)
    try:
        if args.command not in COMMANDS:
            raise ValueError("CI command is required")
        COMMANDS[args.command]()
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        # Never print argv: depot commands can carry credentials.
        detail = (
            f"command exited with code {exc.returncode}" if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        )
        print(f"CI {args.command} failed: {detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

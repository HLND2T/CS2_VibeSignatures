import shutil
from pathlib import Path, PurePosixPath

from binary_hashing import hash_file
from gamedata_candidate import GamedataCandidateError, verify_published_gamedata
from gamesymbol_snapshot_lib.codec import BINARY_METADATA_KEYS
from gamesymbol_snapshot_lib.operations import load_snapshot_context
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    contained_path,
    file_inventory,
    inventory_sha256,
    load_json_object,
    reject_reparse_components,
    reject_reparse_points,
    sha256_file,
    tracked_output_inventory,
    verify_inventory,
    write_canonical_json,
)
from release_workflow_lib.manifests import (
    ALLOWED_REPOSITORIES,
    SCHEMA_VERSION,
    build_tracked_manifest,
    load_tracked_manifest,
    parse_abandon_output_branch,
    parse_output_branch,
    require_build_id,
    require_gamever,
    require_sha,
    tracked_fields_for_schema,
    validate_tracked_manifest,
    verify_tracked_outputs,
)


ABANDON_REASON_MAX_LENGTH = 500
PROMOTION_STATE_MARKERS = ("PROMOTION_STARTED", "PROMOTED.json", "PROMOTION_COMPLETE")


def verify_snapshot_binaries(document: dict, stage_bin: Path) -> int:
    """Bind v4 snapshot binary metadata to the immutable staged binary tree."""
    binaries = document.get("binaries")
    if binaries is None:
        return 0
    checked = 0
    for module, platforms in binaries.items():
        for platform, metadata in platforms.items():
            binary = contained_path(stage_bin, module, PurePosixPath(metadata["path"]).name)
            reject_reparse_components(stage_bin, binary)
            if not binary.is_file():
                raise ReleaseWorkflowError(f"snapshot binary is missing from staged bin: {module}/{platform}: {binary}")
            try:
                actual = hash_file(binary)
            except OSError as exc:
                raise ReleaseWorkflowError(f"unable to hash staged snapshot binary {binary}: {exc}") from exc
            expected = {key: metadata[key] for key in BINARY_METADATA_KEYS if key != "path"}
            if actual != expected:
                raise ReleaseWorkflowError(
                    f"snapshot binary hash mismatch for {module}/{platform}: expected={expected!r} actual={actual!r}"
                )
            checked += 1
    return checked


def staging_directory(staging_root: Path, gamever: str, build_id: str) -> Path:
    require_gamever(gamever)
    staging_root = Path(staging_root)
    staging_root.mkdir(parents=True, exist_ok=True)
    target = contained_path(staging_root, gamever, build_id)
    reject_reparse_components(staging_root, target)
    return target


def _ready_builds(staging_root: Path, gamever: str) -> list[Path]:
    game_root = contained_path(Path(staging_root), gamever)
    if not game_root.is_dir():
        return []
    return sorted(path.parent for path in game_root.glob("*/READY") if path.is_file())


def assert_no_other_ready_build(staging_root: Path, gamever: str, build_id: str) -> None:
    active = [path for path in _ready_builds(staging_root, gamever) if path.name != build_id]
    if active:
        raise ReleaseWorkflowError(f"another ready staged build blocks {gamever}: {active[0]}")


def _validate_stage_request(*, staging_root: Path, repository: str, output_branch: str, gamever: str, build_id: str):
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    gamever = require_gamever(gamever)
    if parse_output_branch(output_branch) != (gamever, build_id):
        raise ReleaseWorkflowError("output branch does not match GAMEVER and BUILD_ID")
    assert_no_other_ready_build(staging_root, gamever, build_id)
    stage_dir = staging_directory(staging_root, gamever, build_id)
    if stage_dir.exists():
        raise ReleaseWorkflowError(f"staging directory already exists: {stage_dir}")
    return gamever, stage_dir


def _pending_payload(
    *, tracked: dict, repository: str, output_branch: str, bin_files: list, tracked_files: list
) -> dict:
    return {
        **tracked,
        "repository": repository,
        "output_branch": output_branch,
        "pr_head_sha": None,
        "bin_files": bin_files,
        "tracked_files": tracked_files,
    }


def _write_stage_manifests(
    *,
    repo_root: Path,
    stage_dir: Path,
    stage_bin: Path,
    candidate: Path,
    repository: str,
    output_branch: str,
    gamever: str,
    mode: str,
    build_id: str,
    source_sha: str,
    workflow_run_url: str,
    analysis_config: Path,
    gamedata_session: Path,
) -> dict:
    bin_files = file_inventory(stage_bin)
    tracked_files = tracked_output_inventory(repo_root, gamever)
    analysis_config = Path(analysis_config).resolve()
    expected_config = (repo_root / "configs" / f"{gamever}.yaml").resolve()
    if analysis_config != expected_config or not analysis_config.is_file():
        raise ReleaseWorkflowError(f"analysis config must be {expected_config}")
    analysis_config_sha256 = sha256_file(analysis_config)
    try:
        candidate_context = load_snapshot_context(candidate, analysis_config, gamever, repo_root / "bin")
    except Exception as exc:
        raise ReleaseWorkflowError(f"candidate snapshot provenance is invalid: {exc}") from exc
    candidate_document = candidate_context.document
    verify_snapshot_binaries(candidate_document, stage_bin)
    try:
        gamedata = verify_published_gamedata(
            session_path=gamedata_session,
            repo_root=repo_root,
            gamever=gamever,
            candidate=candidate,
            analysis_config=analysis_config,
        )
    except GamedataCandidateError as exc:
        raise ReleaseWorkflowError(f"versioned gamedata provenance is invalid: {exc}") from exc
    tracked = build_tracked_manifest(
        gamever=gamever,
        mode=mode,
        build_id=build_id,
        source_sha=source_sha,
        candidate_sha256=sha256_file(candidate),
        bin_manifest_sha256=inventory_sha256(bin_files),
        tracked_output_manifest_sha256=inventory_sha256(tracked_files),
        workflow_run_url=workflow_run_url,
        analysis_config_path=f"configs/{gamever}.yaml",
        analysis_config_sha256=analysis_config_sha256,
        analysis_config_contract_digest_version=candidate_context.contract.config_digest_version,
        analysis_config_contract_sha256=candidate_document["config_sha256"],
        gamedata_path=gamedata["gamedata_path"],
        gamedata_manifest_sha256=gamedata["gamedata_manifest_sha256"],
        generator_contract_sha256=gamedata["generator_contract_sha256"],
    )
    write_canonical_json(repo_root / "release-manifests" / f"{gamever}.json", tracked)
    pending = _pending_payload(
        tracked=tracked,
        repository=repository,
        output_branch=output_branch,
        bin_files=bin_files,
        tracked_files=tracked_files,
    )
    write_canonical_json(stage_dir / "manifest.json", pending)
    return pending


def stage_build(
    *,
    repo_root: Path,
    staging_root: Path,
    bin_source: Path,
    candidate: Path,
    repository: str,
    output_branch: str,
    gamever: str,
    mode: str,
    build_id: str,
    source_sha: str,
    workflow_run_url: str,
    analysis_config: Path,
    gamedata_session: Path,
) -> dict:
    repo_root = Path(repo_root)
    staging_root = Path(staging_root)
    gamever, stage_dir = _validate_stage_request(
        staging_root=staging_root,
        repository=repository,
        output_branch=output_branch,
        gamever=gamever,
        build_id=build_id,
    )
    reject_reparse_points(bin_source)
    stage_bin = stage_dir / "bin" / gamever
    stage_bin.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copytree(bin_source, stage_bin, copy_function=shutil.copy2)
        return _write_stage_manifests(
            repo_root=repo_root,
            stage_dir=stage_dir,
            stage_bin=stage_bin,
            candidate=candidate,
            repository=repository,
            output_branch=output_branch,
            gamever=gamever,
            mode=mode,
            build_id=build_id,
            source_sha=source_sha,
            workflow_run_url=workflow_run_url,
            analysis_config=analysis_config,
            gamedata_session=gamedata_session,
        )
    except Exception:
        if stage_dir.exists():
            shutil.rmtree(stage_dir)
        raise


def finalize_stage(*, repo_root: Path, staging_root: Path, gamever: str, build_id: str, pr_head_sha: str) -> dict:
    pr_head_sha = require_sha(pr_head_sha, "PR head SHA")
    stage_dir = staging_directory(staging_root, gamever, build_id)
    reject_reparse_components(staging_root, stage_dir / "manifest.json")
    reject_reparse_components(staging_root, stage_dir / "READY")
    if (stage_dir / "READY").exists():
        pending = load_json_object(stage_dir / "manifest.json")
        if pending.get("pr_head_sha") != pr_head_sha:
            raise ReleaseWorkflowError("ready staging manifest has a different PR head SHA")
        return pending
    pending = load_json_object(stage_dir / "manifest.json")
    tracked_path = Path(repo_root) / "release-manifests" / f"{gamever}.json"
    tracked = load_tracked_manifest(tracked_path)
    if {key: pending.get(key) for key in tracked} != tracked:
        raise ReleaseWorkflowError("private and tracked release manifests disagree")
    verify_tracked_outputs(repo_root, tracked)
    bin_hash = verify_inventory(stage_dir / "bin" / gamever, pending.get("bin_files", []))
    if bin_hash != tracked["bin_manifest_sha256"]:
        raise ReleaseWorkflowError("staged bin manifest hash mismatch")
    snapshot_context = load_snapshot_context(
        Path(repo_root) / "gamesymbols" / f"{gamever}.yaml",
        Path(repo_root) / "configs" / f"{gamever}.yaml",
        gamever,
        Path(repo_root) / "bin",
    )
    verify_snapshot_binaries(snapshot_context.document, stage_dir / "bin" / gamever)
    pending["pr_head_sha"] = pr_head_sha
    write_canonical_json(stage_dir / "manifest.json", pending)
    ready_hash = sha256_file(stage_dir / "manifest.json")
    (stage_dir / "READY").write_text(f"{ready_hash}\n", encoding="ascii")
    return pending


def write_pr_index(*, staging_root: Path, pr_number: int, gamever: str, build_id: str, pr_head_sha: str) -> Path:
    if pr_number <= 0:
        raise ReleaseWorkflowError("PR number must be positive")
    pr_head_sha = require_sha(pr_head_sha, "PR head SHA")
    stage_dir = staging_directory(staging_root, gamever, build_id)
    if not (stage_dir / "READY").is_file():
        raise ReleaseWorkflowError("cannot index staging state before READY")
    pending = load_json_object(stage_dir / "manifest.json")
    if pending.get("pr_head_sha") != pr_head_sha:
        raise ReleaseWorkflowError("PR head SHA does not match private manifest")
    index = {
        "schema_version": SCHEMA_VERSION,
        "pr_number": pr_number,
        "gamever": gamever,
        "build_id": build_id,
        "pr_head_sha": pr_head_sha,
        "output_branch": pending["output_branch"],
    }
    index_path = contained_path(Path(staging_root), "pr-index", f"{pr_number}.json")
    reject_reparse_components(staging_root, index_path)
    if index_path.exists() and load_json_object(index_path) != index:
        raise ReleaseWorkflowError(f"PR index already exists with different identity: {index_path}")
    write_canonical_json(index_path, index)
    return index_path


def load_indexed_pending(
    staging_root: Path, pr_number: int, event_head_sha: str, *, allow_legacy_schema: bool = False
) -> tuple[dict, dict, Path]:
    event_head_sha = require_sha(event_head_sha, "event head SHA")
    index_path = contained_path(Path(staging_root), "pr-index", f"{pr_number}.json")
    reject_reparse_components(staging_root, index_path)
    index = load_json_object(index_path)
    expected_index_fields = {"schema_version", "pr_number", "gamever", "build_id", "pr_head_sha", "output_branch"}
    if set(index) != expected_index_fields:
        raise ReleaseWorkflowError("pending PR index has unexpected or missing fields")
    if index.get("pr_number") != pr_number or index.get("pr_head_sha") != event_head_sha:
        raise ReleaseWorkflowError("PR event identity does not match pending index")
    stage_dir = staging_directory(staging_root, index.get("gamever", ""), index.get("build_id", ""))
    reject_reparse_components(staging_root, stage_dir / "manifest.json")
    reject_reparse_components(staging_root, stage_dir / "READY")
    pending = load_json_object(stage_dir / "manifest.json")
    if not allow_legacy_schema and pending.get("schema_version") != SCHEMA_VERSION:
        raise ReleaseWorkflowError("pending staging state does not use the current schema")
    tracked_fields = tracked_fields_for_schema(pending.get("schema_version"))
    expected_fields = tracked_fields | {"repository", "output_branch", "pr_head_sha", "bin_files", "tracked_files"}
    if set(pending) != expected_fields:
        raise ReleaseWorkflowError("private pending manifest has unexpected or missing fields")
    if pending.get("schema_version") != index.get("schema_version"):
        raise ReleaseWorkflowError("private manifest schema does not match pending PR index")
    if pending.get("pr_head_sha") != event_head_sha or pending.get("output_branch") != index.get("output_branch"):
        raise ReleaseWorkflowError("private manifest identity does not match PR index")
    ready = stage_dir / "READY"
    if not ready.is_file() or ready.read_text(encoding="ascii").strip() != sha256_file(stage_dir / "manifest.json"):
        raise ReleaseWorkflowError("pending staging READY marker is invalid")
    validate_tracked_manifest({key: pending[key] for key in tracked_fields})
    return index, pending, stage_dir


def cleanup_unmerged(staging_root: Path, pr_number: int, event_head_sha: str) -> None:
    _index, _pending, stage_dir = load_indexed_pending(staging_root, pr_number, event_head_sha)
    _remove_indexed_pending(staging_root, pr_number, stage_dir)


def _remove_indexed_pending(staging_root: Path, pr_number: int, stage_dir: Path) -> None:
    index_path = contained_path(Path(staging_root), "pr-index", f"{pr_number}.json")
    reject_reparse_points(stage_dir)
    shutil.rmtree(stage_dir)
    index_path.unlink()


def abandon_pending(
    *,
    staging_root: Path,
    persisted_root: Path,
    repository: str,
    output_branch: str,
    gamever: str,
    build_id: str,
    pr_number: int,
    event_head_sha: str,
    confirmation: str,
    reason: str,
) -> dict:
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    gamever = require_gamever(gamever)
    build_id = require_build_id(build_id)
    expected_identity = (gamever, build_id)
    if parse_abandon_output_branch(output_branch) != expected_identity:
        raise ReleaseWorkflowError("output branch does not match requested build identity")
    expected_confirmation = f"ABANDON {gamever}/{build_id}"
    if confirmation != expected_confirmation:
        raise ReleaseWorkflowError(f"confirmation must exactly equal {expected_confirmation!r}")
    reason = str(reason).strip()
    if not reason or len(reason) > ABANDON_REASON_MAX_LENGTH or any(char in reason for char in "\r\n"):
        raise ReleaseWorkflowError("abandon reason must be one non-empty line of at most 500 characters")

    index, pending, stage_dir = load_indexed_pending(staging_root, pr_number, event_head_sha, allow_legacy_schema=True)
    if (index.get("gamever"), index.get("build_id")) != expected_identity:
        raise ReleaseWorkflowError("requested build identity does not match pending PR index")
    if (pending.get("gamever"), pending.get("build_id")) != expected_identity:
        raise ReleaseWorkflowError("requested build identity does not match private pending manifest")
    if index.get("output_branch") != output_branch or pending.get("output_branch") != output_branch:
        raise ReleaseWorkflowError("requested output branch does not match indexed pending state")
    if pending.get("repository") != repository:
        raise ReleaseWorkflowError("requested repository does not match private pending manifest")

    for marker in PROMOTION_STATE_MARKERS:
        marker_path = stage_dir / marker
        reject_reparse_components(staging_root, marker_path)
        if marker_path.exists():
            raise ReleaseWorkflowError(
                f"promotion state exists; recovery must resume instead of abandon: {marker_path}"
            )

    persisted_root = Path(persisted_root)
    reject_reparse_components(persisted_root, persisted_root)
    accepted_root = contained_path(persisted_root, "bin")
    for suffix in ("incoming", "backup"):
        recovery_path = contained_path(accepted_root, f".{gamever}.{build_id}.{suffix}")
        reject_reparse_components(persisted_root, recovery_path)
        if recovery_path.exists():
            raise ReleaseWorkflowError(f"promotion recovery path exists; refusing abandon: {recovery_path}")

    _remove_indexed_pending(staging_root, pr_number, stage_dir)
    return {
        "gamever": gamever,
        "build_id": build_id,
        "pr_number": pr_number,
        "pr_head_sha": require_sha(event_head_sha, "event head SHA"),
        "reason": reason,
    }


def cleanup_incomplete(staging_root: Path, gamever: str, build_id: str) -> bool:
    stage_dir = staging_directory(staging_root, gamever, build_id)
    if not stage_dir.exists() or (stage_dir / "READY").is_file():
        return False
    reject_reparse_points(stage_dir)
    shutil.rmtree(stage_dir)
    return True

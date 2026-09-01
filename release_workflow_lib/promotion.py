import os
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.filesystem import remove_tree
from release_workflow_lib.hashing import (
    contained_path,
    file_inventory,
    inventory_sha256,
    load_json_object,
    reject_reparse_points,
    reject_reparse_components,
    validate_output_paths,
    verify_inventory,
    write_canonical_json,
    sha256_file,
)
from release_workflow_lib.manifests import (
    ALLOWED_REPOSITORIES,
    LEGACY_ACTIONS_BOT_LOGIN,
    SCHEMA_VERSION,
    TRUSTED_PR_AUTHOR_ASSOCIATIONS,
    load_tracked_manifest,
    parse_output_branch,
    require_build_id,
    require_gamever,
    require_sha,
    verify_tracked_outputs,
)
from gamesymbol_snapshot_lib.operations import load_snapshot_context
from release_workflow_lib.staging import is_recoverable_analysis_path, load_indexed_pending, verify_snapshot_binaries

COMPLETION_SCHEMA_VERSION = 1
COMPLETION_FIELDS = {
    "schema_version",
    "gamever",
    "build_id",
    "pr_number",
    "pr_head_sha",
    "output_merge_sha",
    "candidate_sha256",
    "gamedata_manifest_sha256",
    "bin_manifest_sha256",
    "release_provenance_sha256",
}
LEGACY_COMPLETION_FIELDS = {
    "schema_version",
    "gamever",
    "build_id",
    "pr_head_sha",
    "output_merge_sha",
    "candidate_sha256",
    "tracked_output_manifest_sha256",
    "bin_manifest_sha256",
    "release_provenance_sha256",
}


def _git_output(arguments: list[str]) -> str:
    result = subprocess.run(["git", *arguments], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise ReleaseWorkflowError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def _is_ancestor(ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def _require_trusted_pr_author(author: str, author_association: str, context: str) -> None:
    if author == LEGACY_ACTIONS_BOT_LOGIN:
        return
    if (author_association or "").strip().upper() in TRUSTED_PR_AUTHOR_ASSOCIATIONS:
        return
    raise ReleaseWorkflowError(
        f"{context} requires {LEGACY_ACTIONS_BOT_LOGIN} or a trusted "
        f"{'/'.join(sorted(TRUSTED_PR_AUTHOR_ASSOCIATIONS))} author"
    )


def verify_output_pr(
    *,
    repo_root: Path,
    repository: str,
    head_repository: str,
    author: str,
    author_association: str,
    branch: str,
    base_sha: str,
    head_sha: str,
) -> dict:
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    base_sha = require_sha(base_sha, "PR base SHA")
    head_sha = require_sha(head_sha, "PR head SHA")
    if repository != head_repository:
        raise ReleaseWorkflowError("generated-output PR must originate from the base repository")
    _require_trusted_pr_author(author, author_association, "generated-output PR author")
    gamever, build_id = parse_output_branch(branch)
    manifest = load_tracked_manifest(Path(repo_root) / "release-manifests" / f"{gamever}.json")
    if manifest["build_id"] != build_id:
        raise ReleaseWorkflowError("output PR manifest identity does not match the branch")
    source_sha = manifest["source_sha"]
    head_parents = _git_output(["rev-list", "--parents", "-n", "1", head_sha]).split()
    if len(head_parents) != 2 or head_parents[1] != source_sha:
        raise ReleaseWorkflowError("generated-output commit is not directly based on SOURCE_SHA")
    if not _is_ancestor(source_sha, base_sha):
        raise ReleaseWorkflowError("generated-output PR base must descend from SOURCE_SHA")
    paths = [line for line in _git_output(["diff", "--name-only", source_sha, head_sha, "--"]).splitlines() if line]
    validate_output_paths(paths, gamever)
    verify_tracked_outputs(repo_root, manifest)
    return manifest


def verify_promotion(
    *,
    repo_root: Path,
    staging_root: Path,
    repository: str,
    head_repository: str,
    author: str,
    author_association: str,
    branch: str,
    base_branch: str,
    default_branch: str,
    pr_number: int,
    event_head_sha: str,
    merge_sha: str,
) -> dict:
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    merge_sha = require_sha(merge_sha, "OUTPUT_MERGE_SHA")
    if repository != head_repository:
        raise ReleaseWorkflowError("promotion requires a same-repository PR")
    _require_trusted_pr_author(author, author_association, "promotion")
    if base_branch != default_branch:
        raise ReleaseWorkflowError("generated-output PR base is not the default branch")
    gamever, build_id = parse_output_branch(branch)
    index, pending, stage_dir = load_indexed_pending(staging_root, pr_number, event_head_sha)
    if index["output_branch"] != branch or (index["gamever"], index["build_id"]) != (gamever, build_id):
        raise ReleaseWorkflowError("pull request branch does not match pending index")
    if pending.get("repository") != repository:
        raise ReleaseWorkflowError("private manifest repository identity mismatch")
    parents = _git_output(["rev-list", "--parents", "-n", "1", merge_sha]).split()
    if len(parents) != 3:
        raise ReleaseWorkflowError("promotion requires a two-parent merge commit")
    base_parent_sha, merged_head_sha = parents[1:]
    if merged_head_sha != event_head_sha:
        raise ReleaseWorkflowError("merge second parent does not match PR head SHA")
    head_parents = _git_output(["rev-list", "--parents", "-n", "1", event_head_sha]).split()
    if len(head_parents) != 2 or head_parents[1] != pending["source_sha"]:
        raise ReleaseWorkflowError("generated-output commit is not directly based on SOURCE_SHA")
    if not _is_ancestor(pending["source_sha"], base_parent_sha):
        raise ReleaseWorkflowError("merge first parent must descend from SOURCE_SHA")
    paths = [
        line for line in _git_output(["diff", "--name-only", base_parent_sha, merge_sha, "--"]).splitlines() if line
    ]
    validate_output_paths(paths, gamever)
    tracked = load_tracked_manifest(Path(repo_root) / "release-manifests" / f"{gamever}.json")
    if {key: pending.get(key) for key in tracked} != tracked:
        raise ReleaseWorkflowError("tracked and private manifests disagree during promotion")
    tracked_files = verify_tracked_outputs(repo_root, tracked)
    if tracked_files != pending.get("tracked_files"):
        raise ReleaseWorkflowError("tracked output inventory differs from pending build")
    bin_hash = verify_inventory(stage_dir / "bin" / gamever, pending.get("bin_files", []))
    if bin_hash != tracked["bin_manifest_sha256"]:
        raise ReleaseWorkflowError("staged bin hash differs from tracked manifest")
    snapshot_context = load_snapshot_context(
        Path(repo_root) / "gamesymbols" / f"{gamever}.yaml",
        Path(repo_root) / "configs" / f"{gamever}.yaml",
        gamever,
        Path(repo_root) / "bin",
        artifactdir=Path(repo_root) / "bin_artifacts",
    )
    verify_snapshot_binaries(snapshot_context.document, stage_dir / "bin" / gamever)
    return {**tracked, "stage_dir": str(stage_dir), "output_merge_sha": merge_sha}


def reconstruct_workspace(repo_root: Path, stage_dir: Path, gamever: str) -> Path:
    repo_root = Path(repo_root).resolve()
    stage_dir = Path(stage_dir)
    reject_reparse_components(stage_dir, stage_dir)
    source = contained_path(stage_dir, "bin", gamever)
    reject_reparse_points(source)
    target = contained_path(repo_root, "bin", gamever)
    if target.exists():
        reject_reparse_points(target)
        remove_tree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target, copy_function=shutil.copy2)
    return target


@contextmanager
def _version_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except OSError as exc:
        raise ReleaseWorkflowError(f"unable to acquire per-version promotion lock: {lock_path}") from exc
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()


def _write_promoted_state(*, stage_dir: Path, target: Path, backup: Path | None) -> dict:
    state = {
        "schema_version": SCHEMA_VERSION,
        "accepted": str(target),
        "backup": str(backup) if backup else None,
    }
    write_canonical_json(stage_dir / "PROMOTED.json", state)
    return state


def _swap_verified_bin(
    *,
    source: Path,
    target: Path,
    incoming: Path,
    backup: Path,
    expected_files: list[dict],
    expected_hash: str,
) -> bool:
    if backup.exists():
        raise ReleaseWorkflowError(f"promotion backup already exists while accepted bin differs: {backup}")
    if incoming.exists():
        reject_reparse_points(incoming)
        remove_tree(incoming)
    shutil.copytree(source, incoming, copy_function=shutil.copy2)
    if verify_inventory(incoming, expected_files) != expected_hash:
        remove_tree(incoming)
        raise ReleaseWorkflowError("incoming accepted-bin directory failed verification")
    moved_old = False
    try:
        if target.exists():
            os.replace(target, backup)
            moved_old = True
        os.replace(incoming, target)
    except OSError as exc:
        if moved_old and not target.exists() and backup.exists():
            os.replace(backup, target)
        raise ReleaseWorkflowError(f"transactional accepted-bin swap failed: {exc}") from exc
    return moved_old


def promote_bin(*, persisted_root: Path, stage_dir: Path, gamever: str, build_id: str) -> dict:
    gamever = require_gamever(gamever)
    build_id = require_build_id(build_id)
    persisted_root = Path(persisted_root)
    reject_reparse_components(persisted_root, persisted_root)
    persisted_root = persisted_root.resolve()
    stage_dir = Path(stage_dir)
    reject_reparse_components(stage_dir, stage_dir)
    source = contained_path(stage_dir, "bin", gamever)
    reject_reparse_components(stage_dir, stage_dir / "manifest.json")
    pending = load_json_object(stage_dir / "manifest.json")
    if (pending.get("gamever"), pending.get("build_id")) != (gamever, build_id):
        raise ReleaseWorkflowError("promotion request does not match private pending manifest")
    expected_files = pending.get("bin_files", [])
    for entry in expected_files:
        path = entry.get("path") if isinstance(entry, dict) else None
        if isinstance(path, str) and is_recoverable_analysis_path(Path(path)):
            raise ReleaseWorkflowError(f"staged bin inventory contains recoverable analysis state: {path}")
    expected_hash = pending.get("bin_manifest_sha256")
    if verify_inventory(source, expected_files) != expected_hash:
        raise ReleaseWorkflowError("staged bin failed verification before promotion")
    accepted_root = contained_path(persisted_root, "bin")
    reject_reparse_components(persisted_root, accepted_root)
    accepted_root.mkdir(parents=True, exist_ok=True)
    target = contained_path(accepted_root, gamever)
    incoming = contained_path(accepted_root, f".{gamever}.{build_id}.incoming")
    backup = contained_path(accepted_root, f".{gamever}.{build_id}.backup")
    lock_path = contained_path(persisted_root, "release-staging", "locks", f"{gamever}.lock")
    with _version_lock(lock_path):
        started_path = stage_dir / "PROMOTION_STARTED"
        reject_reparse_components(stage_dir, started_path)
        write_canonical_json(
            started_path,
            {"schema_version": SCHEMA_VERSION, "gamever": gamever, "build_id": build_id},
        )
        if target.is_dir() and inventory_sha256(file_inventory(target)) == expected_hash:
            return _write_promoted_state(stage_dir=stage_dir, target=target, backup=backup if backup.exists() else None)
        moved_old = _swap_verified_bin(
            source=source,
            target=target,
            incoming=incoming,
            backup=backup,
            expected_files=expected_files,
            expected_hash=expected_hash,
        )
        return _write_promoted_state(stage_dir=stage_dir, target=target, backup=backup if moved_old else None)


def _completion_record(*, pending: dict, pr_number: int, output_merge_sha: str, release_provenance: Path) -> dict:
    if pending.get("schema_version") != SCHEMA_VERSION:
        raise ReleaseWorkflowError("completed cleanup requires the versioned-gamedata release schema")
    return {
        "schema_version": COMPLETION_SCHEMA_VERSION,
        "gamever": pending["gamever"],
        "build_id": pending["build_id"],
        "pr_number": pr_number,
        "pr_head_sha": pending["pr_head_sha"],
        "output_merge_sha": require_sha(output_merge_sha, "OUTPUT_MERGE_SHA"),
        "candidate_sha256": pending["candidate_sha256"],
        "gamedata_manifest_sha256": pending["gamedata_manifest_sha256"],
        "bin_manifest_sha256": pending["bin_manifest_sha256"],
        "release_provenance_sha256": sha256_file(release_provenance),
    }


def _validate_completion_record(record: dict, gamever: str, build_id: str) -> dict:
    schema_version = record.get("schema_version")
    expected_fields = COMPLETION_FIELDS if schema_version == COMPLETION_SCHEMA_VERSION else LEGACY_COMPLETION_FIELDS
    if set(record) != expected_fields or schema_version not in {0, COMPLETION_SCHEMA_VERSION}:
        raise ReleaseWorkflowError("completion record has unexpected fields or schema")
    if (record.get("gamever"), record.get("build_id")) != (
        require_gamever(gamever),
        require_build_id(build_id),
    ):
        raise ReleaseWorkflowError("completion record identity mismatch")
    require_sha(record.get("pr_head_sha", ""), "completion PR head SHA")
    require_sha(record.get("output_merge_sha", ""), "completion output merge SHA")
    if schema_version == COMPLETION_SCHEMA_VERSION and (
        not isinstance(record.get("pr_number"), int) or record["pr_number"] <= 0
    ):
        raise ReleaseWorkflowError("completion record has an invalid PR number")
    hash_fields = [
        "candidate_sha256",
        "bin_manifest_sha256",
        "release_provenance_sha256",
    ]
    hash_fields.append("gamedata_manifest_sha256" if schema_version == 1 else "tracked_output_manifest_sha256")
    for field in hash_fields:
        value = record.get(field, "")
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ReleaseWorkflowError(f"completion record has an invalid {field}")
    return record


def _recovery_paths(persisted_root: Path, gamever: str, build_id: str) -> tuple[Path, Path]:
    accepted_root = contained_path(persisted_root, "bin")
    return (
        contained_path(accepted_root, f".{gamever}.{build_id}.incoming"),
        contained_path(accepted_root, f".{gamever}.{build_id}.backup"),
    )


def finalize_promotion(
    *,
    staging_root: Path,
    pr_number: int,
    event_head_sha: str,
    output_merge_sha: str,
    release_provenance: Path,
) -> dict:
    staging_root = Path(staging_root)
    _index, pending, stage_dir = load_indexed_pending(staging_root, pr_number, event_head_sha)
    state = load_json_object(stage_dir / "PROMOTED.json")
    accepted = Path(state["accepted"])
    if verify_inventory(accepted, pending["bin_files"]) != pending["bin_manifest_sha256"]:
        raise ReleaseWorkflowError("accepted bin changed before promotion completion")
    release_provenance = Path(release_provenance)
    if not release_provenance.is_file():
        raise ReleaseWorkflowError("release provenance is missing before promotion completion")
    record = _completion_record(
        pending=pending,
        pr_number=pr_number,
        output_merge_sha=output_merge_sha,
        release_provenance=release_provenance,
    )
    write_canonical_json(stage_dir / "PROMOTION_COMPLETE", record)
    backup = state.get("backup")
    if backup and Path(backup).exists():
        reject_reparse_points(Path(backup))
        remove_tree(Path(backup))
    persisted_root = accepted.parent.parent
    incoming_path, backup_path = _recovery_paths(persisted_root, pending["gamever"], pending["build_id"])
    if incoming_path.exists() or backup_path.exists():
        raise ReleaseWorkflowError("promotion recovery paths remain after backup finalization")
    completed_path = contained_path(staging_root, "completed", pending["gamever"], f"{pending['build_id']}.json")
    write_canonical_json(completed_path, record)
    index_path = contained_path(staging_root, "pr-index", f"{pr_number}.json")
    index_path.unlink()
    return record


def _matching_pr_indexes(staging_root: Path, gamever: str, build_id: str) -> list[Path]:
    index_root = contained_path(staging_root, "pr-index")
    if not index_root.exists():
        return []
    reject_reparse_points(index_root)
    matches = []
    for path in index_root.glob("*.json"):
        index = load_json_object(path)
        if (index.get("gamever"), index.get("build_id")) == (gamever, build_id):
            matches.append(path)
    return matches


def _validate_completed_stage(stage_dir: Path, record: dict, persisted_root: Path) -> None:
    complete = load_json_object(stage_dir / "PROMOTION_COMPLETE")
    if record["schema_version"] == COMPLETION_SCHEMA_VERSION:
        if complete != record:
            raise ReleaseWorkflowError("stage completion marker does not match durable completion record")
    elif complete.get("output_merge_sha") != record["output_merge_sha"]:
        raise ReleaseWorkflowError("legacy completion marker does not match durable completion record")
    pending = load_json_object(stage_dir / "manifest.json")
    expected_pending = {
        "gamever": record["gamever"],
        "build_id": record["build_id"],
        "pr_head_sha": record["pr_head_sha"],
        "candidate_sha256": record["candidate_sha256"],
        "bin_manifest_sha256": record["bin_manifest_sha256"],
    }
    if record["schema_version"] == COMPLETION_SCHEMA_VERSION:
        expected_pending["gamedata_manifest_sha256"] = record["gamedata_manifest_sha256"]
    else:
        expected_pending["tracked_output_manifest_sha256"] = record["tracked_output_manifest_sha256"]
    if {key: pending.get(key) for key in expected_pending} != expected_pending:
        raise ReleaseWorkflowError("private manifest does not match durable completion record")
    promoted = load_json_object(stage_dir / "PROMOTED.json")
    expected_accepted = contained_path(persisted_root, "bin", record["gamever"])
    if Path(promoted.get("accepted", "")) != expected_accepted:
        raise ReleaseWorkflowError("promoted state does not match completed accepted-bin identity")
    expected_backup = _recovery_paths(persisted_root, record["gamever"], record["build_id"])[1]
    if promoted.get("backup") is not None and Path(promoted["backup"]) != expected_backup:
        raise ReleaseWorkflowError("promoted state backup path does not match completed build identity")


def cleanup_completed(*, staging_root: Path, persisted_root: Path, gamever: str, build_id: str) -> dict:
    staging_root = Path(staging_root)
    persisted_root = Path(persisted_root)
    if (persisted_root / "release-staging").resolve() != staging_root.resolve():
        raise ReleaseWorkflowError("staging_root must be persisted_root/release-staging")
    # Match the normalized root recorded by promote_bin in PROMOTED.json.
    persisted_root = persisted_root.resolve()
    completion_path = contained_path(staging_root, "completed", gamever, f"{build_id}.json")
    reject_reparse_components(staging_root, completion_path)
    record = _validate_completion_record(load_json_object(completion_path), gamever, build_id)
    if _matching_pr_indexes(staging_root, gamever, build_id):
        raise ReleaseWorkflowError("completed stage still has a matching PR index")
    incoming_path, backup_path = _recovery_paths(persisted_root, gamever, build_id)
    if incoming_path.exists() or backup_path.exists():
        raise ReleaseWorkflowError("completed stage still has promotion recovery paths")
    stage_dir = contained_path(staging_root, gamever, build_id)
    trash_dir = contained_path(staging_root, "cleanup-trash", gamever, build_id)
    lock_path = contained_path(staging_root, "locks", f"{gamever}.lock")
    resumed = False
    with _version_lock(lock_path):
        if stage_dir.exists() and trash_dir.exists():
            raise ReleaseWorkflowError("both completed stage and cleanup trash exist")
        if stage_dir.exists():
            reject_reparse_points(stage_dir)
            _validate_completed_stage(stage_dir, record, persisted_root)
            trash_dir.parent.mkdir(parents=True, exist_ok=True)
            os.replace(stage_dir, trash_dir)
        elif trash_dir.exists():
            reject_reparse_points(trash_dir)
            resumed = True
        else:
            return {"status": "already-absent", "gamever": gamever, "build_id": build_id}
    remove_tree(trash_dir)
    return {"status": "resumed" if resumed else "removed", "gamever": gamever, "build_id": build_id}


def list_completed(staging_root: Path) -> list[dict]:
    completed_root = contained_path(Path(staging_root), "completed")
    if not completed_root.exists():
        return []
    reject_reparse_points(completed_root)
    records = []
    for path in sorted(completed_root.glob("*/*.json")):
        record = load_json_object(path)
        records.append(_validate_completion_record(record, path.parent.name, path.stem))
    return records

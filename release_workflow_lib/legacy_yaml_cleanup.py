"""Recoverably remove legacy YAML truth from the persisted accepted-bin cache."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from release_workflow_lib.binary_cache import (
    BINARY_CACHE_LOCK_ROOT,
    configured_binary_paths,
    require_gamever,
    validate_binary_cache_tree,
    version_lock,
)
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.filesystem import remove_tree
from release_workflow_lib.hashing import (
    contained_path,
    inventory_sha256,
    load_json_object,
    normalized_relative_path,
    reject_reparse_components,
    reject_reparse_points,
    sha256_file,
    verify_inventory,
    write_canonical_json,
)


SCHEMA_VERSION = 1


def _yaml_inventory(root: Path) -> list[dict]:
    reject_reparse_points(root)
    inventory = []
    if not root.exists():
        return inventory
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        relative = normalized_relative_path(path.relative_to(root).as_posix())
        inventory.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    return inventory


def _backup_manifest(gamever: str, files: list[dict]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "gamever": gamever,
        "file_count": len(files),
        "inventory_sha256": inventory_sha256(files),
        "files": files,
    }


def _validate_backup(*, persisted_root: Path, gamever: str, backup_root: Path, files: list[dict]) -> dict:
    manifest = _backup_manifest(gamever, files)
    expected_backup = contained_path(
        persisted_root,
        "accepted-bin-legacy-yaml",
        gamever,
        manifest["inventory_sha256"].removeprefix("sha256:"),
    )
    if backup_root.resolve() != expected_backup.resolve():
        raise ReleaseWorkflowError("legacy YAML cleanup backup path is not canonical")
    reject_reparse_components(persisted_root, backup_root)
    if load_json_object(backup_root / "manifest.json") != manifest:
        raise ReleaseWorkflowError("legacy YAML cleanup backup manifest is invalid")
    try:
        backup_digest = verify_inventory(backup_root / "payload", files)
    except ReleaseWorkflowError as exc:
        raise ReleaseWorkflowError("legacy YAML cleanup backup payload is damaged") from exc
    if backup_digest != manifest["inventory_sha256"]:
        raise ReleaseWorkflowError("legacy YAML cleanup backup payload is damaged")
    return manifest


def _prepare_backup(*, persisted_root: Path, accepted: Path, gamever: str, files: list[dict]) -> tuple[Path, dict]:
    manifest = _backup_manifest(gamever, files)
    digest = manifest["inventory_sha256"]
    digest_component = digest.removeprefix("sha256:")
    backup_root = contained_path(persisted_root, "accepted-bin-legacy-yaml", gamever, digest_component)
    incoming = contained_path(persisted_root, "accepted-bin-legacy-yaml", gamever, f".{digest_component}.incoming")
    if backup_root.exists():
        return backup_root, _validate_backup(
            persisted_root=persisted_root,
            gamever=gamever,
            backup_root=backup_root,
            files=files,
        )
    if incoming.exists():
        reject_reparse_points(incoming)
        remove_tree(incoming)
    payload = incoming / "payload"
    try:
        payload.mkdir(parents=True, exist_ok=True)
        for item in files:
            source = contained_path(accepted, *Path(item["path"]).parts)
            reject_reparse_components(accepted, source)
            if not source.is_file() or source.stat().st_size != item["size"] or sha256_file(source) != item["sha256"]:
                raise ReleaseWorkflowError(f"legacy accepted-bin YAML changed before backup: {item['path']}")
            target = contained_path(payload, *Path(item["path"]).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        if verify_inventory(payload, files) != digest:
            raise ReleaseWorkflowError("legacy YAML incoming backup failed exact verification")
        write_canonical_json(incoming / "manifest.json", manifest)
        backup_root.parent.mkdir(parents=True, exist_ok=True)
        os.replace(incoming, backup_root)
    except Exception:
        if incoming.exists():
            remove_tree(incoming)
        raise
    return backup_root, manifest


def _delete_yaml_path(path: Path) -> None:
    path.unlink()


def _resume_deletion(*, accepted: Path, files: list[dict], allowed_paths: frozenset[str]) -> None:
    reject_reparse_points(accepted)
    for item in files:
        path = contained_path(accepted, *Path(item["path"]).parts)
        reject_reparse_components(accepted, path)
        if not path.exists():
            continue
        if not path.is_file() or path.stat().st_size != item["size"] or sha256_file(path) != item["sha256"]:
            raise ReleaseWorkflowError(f"legacy accepted-bin YAML drifted during cleanup: {item['path']}")
        _delete_yaml_path(path)
    validate_binary_cache_tree(accepted, allowed_paths, allow_excluded=False)


def cleanup_legacy_accepted_yaml(*, repo_root: str | Path, persisted_root: str | Path, gamever: str) -> dict:
    gamever = require_gamever(gamever)
    repo_root = Path(repo_root).resolve()
    persisted_root = Path(persisted_root).resolve()
    allowed_paths = configured_binary_paths(repo_root, gamever)
    reject_reparse_components(persisted_root, persisted_root)
    accepted = contained_path(persisted_root, "bin", gamever)
    reject_reparse_components(persisted_root, accepted)
    if not accepted.is_dir():
        raise ReleaseWorkflowError(f"accepted-bin GAMEVER does not exist: {accepted}")
    state_path = contained_path(persisted_root, "binary-cache", "legacy-yaml-cleanup", f"{gamever}.json")
    receipt_path = contained_path(persisted_root, "binary-cache", "legacy-yaml-receipts", f"{gamever}.json")
    lock_path = contained_path(persisted_root, *BINARY_CACHE_LOCK_ROOT, f"{gamever}.lock")
    with version_lock(lock_path):
        if receipt_path.is_file():
            receipt = load_json_object(receipt_path)
            backup_value = receipt.get("backup_root")
            if not isinstance(backup_value, str) or not backup_value:
                raise ReleaseWorkflowError("legacy YAML cleanup receipt identity is invalid")
            backup_root = Path(backup_value)
            reject_reparse_components(persisted_root, backup_root)
            manifest = load_json_object(backup_root / "manifest.json")
            files = manifest.get("files")
            if not isinstance(files, list):
                raise ReleaseWorkflowError("legacy YAML cleanup backup inventory is invalid")
            manifest = _validate_backup(
                persisted_root=persisted_root,
                gamever=gamever,
                backup_root=backup_root,
                files=files,
            )
            expected_receipt = {
                "schema_version": SCHEMA_VERSION,
                "gamever": gamever,
                "file_count": len(files),
                "inventory_sha256": manifest["inventory_sha256"],
                "backup_root": str(backup_root),
                "backup_manifest_sha256": sha256_file(backup_root / "manifest.json"),
            }
            if receipt != expected_receipt:
                raise ReleaseWorkflowError("legacy YAML cleanup receipt identity is invalid")
            if _yaml_inventory(accepted):
                raise ReleaseWorkflowError("legacy YAML reappeared after completed cleanup")
            _resume_deletion(accepted=accepted, files=[], allowed_paths=allowed_paths)
            return {**receipt, "status": "already-clean"}

        if state_path.is_file():
            state = load_json_object(state_path)
            if state.get("schema_version") != SCHEMA_VERSION or state.get("gamever") != gamever:
                raise ReleaseWorkflowError("legacy YAML cleanup state identity is invalid")
            files = state.get("files")
            backup_value = state.get("backup_root")
            if not isinstance(files, list) or not isinstance(backup_value, str) or not backup_value:
                raise ReleaseWorkflowError("legacy YAML cleanup state does not match its backup")
            backup_root = Path(backup_value)
            manifest = _validate_backup(
                persisted_root=persisted_root,
                gamever=gamever,
                backup_root=backup_root,
                files=files,
            )
            expected_state = {
                **manifest,
                "backup_root": str(backup_root),
                "backup_manifest_sha256": sha256_file(backup_root / "manifest.json"),
            }
            if state != expected_state:
                raise ReleaseWorkflowError("legacy YAML cleanup state does not match its backup")
        else:
            files = _yaml_inventory(accepted)
            backup_root, manifest = _prepare_backup(
                persisted_root=persisted_root,
                accepted=accepted,
                gamever=gamever,
                files=files,
            )
            state = {
                **manifest,
                "backup_root": str(backup_root),
                "backup_manifest_sha256": sha256_file(backup_root / "manifest.json"),
            }
            write_canonical_json(state_path, state)

        _resume_deletion(accepted=accepted, files=files, allowed_paths=allowed_paths)
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "gamever": gamever,
            "file_count": len(files),
            "inventory_sha256": state["inventory_sha256"],
            "backup_root": state["backup_root"],
            "backup_manifest_sha256": state["backup_manifest_sha256"],
        }
        write_canonical_json(receipt_path, receipt)
        state_path.unlink()
        return {**receipt, "status": "cleaned"}

"""Restore only configured binaries from the disposable accepted-bin cache."""

from __future__ import annotations

import shutil
from pathlib import Path, PurePosixPath

from binary_lock import BinaryLockError, verify_binary_root
from release_workflow_lib.binary_cache import (
    BINARY_CACHE_LOCK_ROOT,
    configured_binary_paths,
    load_source_binary_lock,
    require_gamever,
    validate_binary_cache_tree,
    version_lock,
)
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    contained_path,
    inventory_sha256,
    normalized_relative_path,
    reject_reparse_components,
    reject_reparse_points,
    sha256_file,
)


def _allowed_directories(allowed_paths: frozenset[str]) -> frozenset[str]:
    return frozenset(
        parent.as_posix()
        for path in allowed_paths
        for parent in PurePosixPath(path).parents
        if parent != PurePosixPath(".")
    )


def _validate_target_subset(root: Path, allowed_paths: frozenset[str]) -> None:
    reject_reparse_points(root)
    directories = _allowed_directories(allowed_paths)
    for path in root.rglob("*"):
        relative = normalized_relative_path(path.relative_to(root).as_posix())
        if path.is_file() and relative not in allowed_paths:
            raise ReleaseWorkflowError(f"workspace binary restore target contains an unexpected file: {relative}")
        if path.is_dir() and relative not in directories:
            raise ReleaseWorkflowError(f"workspace binary restore target contains an unexpected directory: {relative}")


def _inventory(root: Path, allowed_paths: frozenset[str]) -> tuple[list[dict], str]:
    files = []
    for relative in sorted(allowed_paths):
        path = root / PurePosixPath(relative)
        files.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    return files, inventory_sha256(files)


def restore_accepted_bin(
    *,
    repo_root: Path,
    persisted_root: Path,
    gamever: str,
    required: bool = False,
) -> dict:
    """Copy the exact configured binary set into ``repo_root/bin/<GAMEVER>``."""
    gamever = require_gamever(gamever)
    repo_root = Path(repo_root).resolve()
    persisted_root = Path(persisted_root).resolve()
    reject_reparse_components(persisted_root, persisted_root)
    allowed_paths = configured_binary_paths(repo_root, gamever)
    source_root = contained_path(persisted_root, "bin", gamever)
    lock_path = contained_path(persisted_root, *BINARY_CACHE_LOCK_ROOT, f"{gamever}.lock")
    target_root = contained_path(repo_root / "bin", gamever)
    reject_reparse_components(repo_root, target_root)
    binary_lock = load_source_binary_lock(repo_root, gamever)

    with version_lock(lock_path):
        if not source_root.is_dir():
            if required:
                raise ReleaseWorkflowError(f"accepted binary cache is missing: {source_root}")
            return {
                "restored": False,
                "reason": "cache-missing",
                "gamever": gamever,
                "hash": None,
                "file_count": 0,
                "binary_lock_sha256": binary_lock.sha256,
            }
        validate_binary_cache_tree(source_root, allowed_paths, allow_excluded=False)
        try:
            verify_binary_root(binary_lock.document, source_root)
        except BinaryLockError as exc:
            if required:
                raise ReleaseWorkflowError(
                    f"accepted binary cache does not match source lock for {gamever}: {exc}"
                ) from exc
            return {
                "restored": False,
                "reason": "binary-lock-mismatch",
                "gamever": gamever,
                "hash": None,
                "file_count": 0,
                "binary_lock_sha256": binary_lock.sha256,
            }
        target_root.mkdir(parents=True, exist_ok=True)
        _validate_target_subset(target_root, allowed_paths)
        for relative in sorted(allowed_paths):
            source = source_root / PurePosixPath(relative)
            target = target_root / PurePosixPath(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            reject_reparse_components(target_root, target.parent)
            shutil.copy2(source, target)
        validate_binary_cache_tree(target_root, allowed_paths, allow_excluded=False)
        try:
            verify_binary_root(binary_lock.document, target_root)
        except BinaryLockError as exc:
            raise ReleaseWorkflowError(f"restored workspace does not match source lock for {gamever}: {exc}") from exc
        files, digest = _inventory(target_root, allowed_paths)
        return {
            "restored": True,
            "reason": None,
            "gamever": gamever,
            "hash": digest,
            "file_count": len(files),
            "binary_lock_sha256": binary_lock.sha256,
        }

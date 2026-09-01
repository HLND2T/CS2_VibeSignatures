"""Idempotently mirror a source gamebin tree into the persisted accepted bin tree.

The warm IDB cache producer prepares configured binaries and warms IDA databases
from them; PR and release consumers then restore that cache and analyze the exact
same binaries. This module makes the accepted-bin lifecycle follow the warmup
lifecycle: after a successful warmup run (whether the cache hit or was freshly
warmed), the actual binaries the run consumed are transactionally, idempotently
mirrored into ``PERSISTED_WORKSPACE/bin/<GAMEVER>`` so the accepted tree always
reflects the warmup input.

The accepted tree is binary-only: YAML, IDA databases, and BinSync state are
excluded. A dedicated per-version binary-cache lock makes direct invocations safe.

When the source and accepted trees already agree by path and size - the common
cache-hit case - the comparison takes a no-hash skeleton fast path and the
returned ``hash`` is ``None`` because no content hash was computed.
"""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.binary_cache import (
    BINARY_CACHE_LOCK_ROOT,
    ignore_binary_cache_state,
    is_binary_cache_excluded_path,
    require_gamever,
    version_lock,
)
from release_workflow_lib.filesystem import remove_tree
from release_workflow_lib.hashing import (
    contained_path,
    inventory_sha256,
    normalized_relative_path,
    reject_reparse_components,
    reject_reparse_points,
    sha256_file,
)


def _filtered_files(root: Path) -> list[Path]:
    """Sorted durable files under ``root``, rejecting reparse points."""
    reject_reparse_points(root)
    return [
        path
        for path in sorted(item for item in root.rglob("*") if item.is_file())
        if not is_binary_cache_excluded_path(path.relative_to(root))
    ]


def _filtered_inventory(root: Path) -> tuple[list[dict], str]:
    """Inventory one gamebin tree excluding recoverable analysis state."""
    filtered = []
    for path in _filtered_files(root):
        relative = normalized_relative_path(path.relative_to(root).as_posix())
        filtered.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    return filtered, inventory_sha256(filtered)


def _filtered_skeleton(root: Path) -> list[tuple[str, int]]:
    """Sorted ``(relative path, size)`` pairs excluding recoverable state.

    A no-hash identity used for the fast path: equal skeletons imply equal bytes
    because the source tree is a robocopy restore of the same persisted tree and
    nothing rewrites files in place between restore and sync (prepare only adds
    missing binaries; IDA warmup writes only excluded side files).
    """
    return [
        (normalized_relative_path(path.relative_to(root).as_posix()), path.stat().st_size)
        for path in _filtered_files(root)
    ]


def _contains_recoverable_analysis_state(root: Path) -> bool:
    """Return whether a verified tree contains any excluded analysis state."""
    return any(is_binary_cache_excluded_path(path.relative_to(root)) for path in root.rglob("*"))


def _swap_verified_bin(
    *,
    source: Path,
    target: Path,
    incoming: Path,
    backup: Path,
    expected_files: list[dict],
    expected_hash: str,
) -> bool:
    """Replace ``target`` with a verified filtered copy of ``source``.

    Mirrors the promote_bin swap: copy to ``incoming``, verify the filtered
    inventory, then atomically move the old target to ``backup`` and ``incoming``
    to target. Returns whether an existing target was moved aside.

    Unlike promote_bin (whose staged source is already clean), the warmup source
    tree can contain IDA and BinSync recovery state, so verification here must be
    against the filtered inventory, not the full tree.
    """
    if backup.exists():
        raise ReleaseWorkflowError(f"sync backup already exists while accepted bin differs: {backup}")
    if incoming.exists():
        reject_reparse_points(incoming)
        remove_tree(incoming)
    incoming.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copytree(source, incoming, copy_function=shutil.copy2, ignore=ignore_binary_cache_state)
    except OSError as exc:
        raise ReleaseWorkflowError(f"unable to copy source tree {source}: {exc}") from exc
    if _filtered_inventory(incoming) != (expected_files, expected_hash):
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


def sync_accepted_bin(*, repo_root: Path, persisted_root: Path, gamever: str) -> dict:
    """Mirror ``repo_root/bin/<GAMEVER>`` into accepted bin for ``gamever``.

    The source is the gamever directory the caller actually consumed. Recoverable
    IDA and BinSync state is excluded so mutable analysis state never leaks into
    the accepted tree. Returns a summary with ``synced`` true when the accepted
    tree changed; ``hash`` is the source content hash, or ``None`` when the no-hash
    skeleton fast path proved the trees already identical.
    """
    gamever = require_gamever(gamever)
    repo_root = Path(repo_root).resolve()
    persisted_root = Path(persisted_root).resolve()
    reject_reparse_components(persisted_root, persisted_root)
    source_root = contained_path(repo_root / "bin", gamever)
    if not source_root.is_dir():
        raise ReleaseWorkflowError(f"sync source tree does not exist: {source_root}")
    reject_reparse_points(source_root)

    accepted_root = contained_path(persisted_root, "bin")
    reject_reparse_components(persisted_root, accepted_root)
    accepted_root.mkdir(parents=True, exist_ok=True)
    target = contained_path(accepted_root, gamever)
    incoming = contained_path(accepted_root, f".{gamever}.{uuid.uuid4().hex}.incoming")
    backup = contained_path(accepted_root, f".{gamever}.{uuid.uuid4().hex}.backup")
    lock_path = contained_path(persisted_root, *BINARY_CACHE_LOCK_ROOT, f"{gamever}.lock")

    source_skeleton = _filtered_skeleton(source_root)

    with version_lock(lock_path):
        if (
            target.is_dir()
            and _filtered_skeleton(target) == source_skeleton
            and not _contains_recoverable_analysis_state(target)
        ):
            return {"synced": False, "gamever": gamever, "hash": None}
        expected_files, expected_hash = _filtered_inventory(source_root)
        moved_old = _swap_verified_bin(
            source=source_root,
            target=target,
            incoming=incoming,
            backup=backup,
            expected_files=expected_files,
            expected_hash=expected_hash,
        )
        return {
            "synced": True,
            "gamever": gamever,
            "hash": expected_hash,
            "replaced": moved_old,
            "backup": str(backup) if moved_old else None,
        }

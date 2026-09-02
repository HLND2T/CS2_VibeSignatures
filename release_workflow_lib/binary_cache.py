"""Shared validation, exclusion, and locking rules for disposable binary caches."""

from __future__ import annotations

import os
import re
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotConfigError
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import normalized_relative_path, reject_reparse_points


GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")
IDA_DATABASE_SUFFIXES = (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til")
BINSYNC_REPO_SUFFIX = ".bsproj"
BINSYNC_SIDECAR_SUFFIX = ".binsync.json"
DISPOSABLE_ANALYSIS_SUFFIXES = (*IDA_DATABASE_SUFFIXES, BINSYNC_REPO_SUFFIX, BINSYNC_SIDECAR_SUFFIX)
BINARY_CACHE_LOCK_ROOT = ("binary-cache", "locks")


def require_gamever(value: str) -> str:
    value = str(value)
    if not GAMEVER_RE.fullmatch(value):
        raise ReleaseWorkflowError(f"invalid GAMEVER: {value!r}")
    return value


def is_binary_cache_excluded_path(path: Path) -> bool:
    """Return whether a path is analysis state or forbidden YAML truth."""
    path = Path(path)
    return path.suffix.lower() in {".yaml", ".yml"} or any(
        part.lower().endswith(DISPOSABLE_ANALYSIS_SUFFIXES) for part in path.parts
    )


def ignore_binary_cache_state(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if is_binary_cache_excluded_path(Path(name))}


def configured_binary_paths(repo_root: str | Path, gamever: str) -> frozenset[str]:
    """Return the exact accepted-cache paths declared by one analysis config."""
    repo_root = Path(repo_root).resolve()
    gamever = require_gamever(gamever)
    try:
        contract = load_contract(
            repo_root / "configs" / f"{gamever}.yaml",
            gamever,
            repo_root / "bin",
            artifactdir=repo_root / "bin_artifacts",
        )
    except SnapshotConfigError as exc:
        raise ReleaseWorkflowError(f"unable to load configured binary allowlist for {gamever}: {exc}") from exc
    paths = {
        normalized_relative_path(f"{target.module_name}/{PurePosixPath(target.source_path).name}")
        for target in contract.binary_targets.values()
    }
    if not paths:
        raise ReleaseWorkflowError(f"configured binary allowlist is empty for {gamever}")
    return frozenset(paths)


def validate_binary_cache_tree(root: str | Path, allowed_paths: frozenset[str], *, allow_excluded: bool) -> None:
    """Require an exact configured binary file set and optionally tolerated cache state."""
    root = Path(root)
    reject_reparse_points(root)
    durable = set()
    excluded = []
    allowed_directories = {
        parent.as_posix()
        for path in allowed_paths
        for parent in PurePosixPath(path).parents
        if parent != PurePosixPath(".")
    }
    unexpected_directories = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if is_binary_cache_excluded_path(relative):
            excluded.append(relative.as_posix())
        elif path.is_file():
            durable.add(normalized_relative_path(relative.as_posix()))
        elif path.is_dir() and normalized_relative_path(relative.as_posix()) not in allowed_directories:
            unexpected_directories.append(relative.as_posix())
    if excluded and not allow_excluded:
        raise ReleaseWorkflowError("excluded analysis state remains in accepted bin: " + ", ".join(sorted(excluded)))
    if unexpected_directories:
        raise ReleaseWorkflowError(
            "binary cache contains unexpected directories: " + ", ".join(sorted(unexpected_directories))
        )
    if durable != set(allowed_paths):
        missing = sorted(set(allowed_paths) - durable)
        unexpected = sorted(durable - set(allowed_paths))
        raise ReleaseWorkflowError(f"binary cache allowlist mismatch: missing={missing!r}; unexpected={unexpected!r}")


@contextmanager
def version_lock(lock_path: Path):
    """Acquire one non-blocking cross-platform lock for a GAMEVER cache writer."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ReleaseWorkflowError(f"unable to acquire per-version binary cache lock: {lock_path}") from exc
        try:
            yield
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
    finally:
        handle.close()

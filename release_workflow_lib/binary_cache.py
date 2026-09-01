"""Shared validation, exclusion, and locking rules for disposable binary caches."""

from __future__ import annotations

import os
import re
from contextlib import contextmanager
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError


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

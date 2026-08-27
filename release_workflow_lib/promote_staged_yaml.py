"""Promote the latest staged analyzed YAML for a merged PR into accepted bin.

Merge-time PR finalization copies the analyzed ``*.yaml`` files a successful
full-validation run staged under ``PERSISTED_WORKSPACE/pr-yaml-staging/<PR>``
into ``PERSISTED_WORKSPACE/bin/<GAMEVER>``. This is a YAML overlay on the
accepted tree, not a full bin replacement, and it must be mutually excluded
from the other accepted-bin writers, so it shares the same per-GAMEVER lock as
``sync_accepted_bin`` and ``promote_bin``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import contained_path, reject_reparse_components, reject_reparse_points
from release_workflow_lib.manifests import require_gamever
from release_workflow_lib.promotion import _version_lock

# Same lock space as promote_bin and sync_accepted_bin so merge-time YAML
# promotion and warmup mirroring of one GAMEVER are mutually excluded.
_LOCK_RELATIVE = ("release-staging", "locks")
_GAMEVER_MARKER = "gamever.txt"


def _latest_staged_run(pr_staging: Path) -> tuple[Path, str]:
    runs = [path for path in pr_staging.iterdir() if path.is_dir()]
    if not runs:
        raise ReleaseWorkflowError(f"staged YAML directory has no run subdirectories: {pr_staging}")

    def sort_key(path: Path) -> tuple[int, int]:
        parts = path.name.split("-")
        if len(parts) < 2:
            raise ReleaseWorkflowError(f"staged run has an unexpected directory name: {path.name}")
        try:
            return int(parts[0]), int(parts[1])
        except ValueError as exc:
            raise ReleaseWorkflowError(f"staged run has an unexpected directory name: {path.name}") from exc

    latest = max(runs, key=sort_key)
    marker = latest / _GAMEVER_MARKER
    if not marker.is_file():
        raise ReleaseWorkflowError(f"staged run is missing {_GAMEVER_MARKER}: {latest}")
    gamever = require_gamever(marker.read_text(encoding="utf-8").strip())
    return latest, gamever


def _copy_yaml_overlay(source: Path, target: Path) -> int:
    promoted = 0
    for path in sorted(source.rglob("*.yaml")):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        destination = contained_path(target, *relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        promoted += 1
    return promoted


def promote_staged_yaml(*, persisted_root: Path, pr_number: int) -> dict:
    if not isinstance(pr_number, int) or pr_number <= 0:
        raise ReleaseWorkflowError(f"invalid PR number: {pr_number}")
    persisted_root = Path(persisted_root).resolve()
    reject_reparse_components(persisted_root, persisted_root)

    pr_staging = contained_path(persisted_root, "pr-yaml-staging", str(pr_number))
    reject_reparse_components(persisted_root, pr_staging)
    if not pr_staging.is_dir():
        raise ReleaseWorkflowError(f"staged YAML directory does not exist: {pr_staging}")

    latest_run, gamever = _latest_staged_run(pr_staging)

    target = contained_path(persisted_root, "bin", gamever)
    reject_reparse_components(persisted_root, target)

    lock_path = contained_path(persisted_root, *_LOCK_RELATIVE, f"{gamever}.lock")

    with _version_lock(lock_path):
        reject_reparse_points(latest_run)
        target.mkdir(parents=True, exist_ok=True)
        promoted = _copy_yaml_overlay(latest_run, target)

    return {
        "pr_number": pr_number,
        "gamever": gamever,
        "staged_run": str(latest_run),
        "promoted_files": promoted,
    }

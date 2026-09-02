"""Fail-closed validation for ``7z l -slt -ba`` member inventories."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import normalized_relative_path


def _normalized_member_path(value: str) -> str:
    candidate = value.replace("\\", "/")
    if ":" in candidate:
        raise ReleaseWorkflowError("archive paths must not contain drive or stream separators")
    return normalized_relative_path(candidate)


def _is_link_entry(fields: dict[str, str]) -> bool:
    if "Symbolic Link" in fields or "Hard Link" in fields:
        return True
    attributes = fields.get("Attributes", "").strip().split()
    return any(token.lower().startswith("l") for token in attributes)


def listed_archive_files(output: str) -> list[dict]:
    """Return a canonical file inventory after validating every listed member."""
    entries: list[tuple[str, str, int]] = []
    for block in re.split(r"\n\s*\n", output.replace("\r\n", "\n")):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, separator, value = line.partition(" = ")
            if separator:
                if key in fields:
                    raise ReleaseWorkflowError(f"7z archive entry repeats field {key!r}")
                fields[key] = value
        if "Path" not in fields:
            continue
        raw_path = fields["Path"]
        try:
            path = _normalized_member_path(raw_path)
            if "Size" not in fields:
                raise ReleaseWorkflowError("archive entry has no declared size")
            size = int(fields["Size"])
        except (TypeError, ValueError, ReleaseWorkflowError) as exc:
            raise ReleaseWorkflowError(f"7z archive contains an unsafe entry: {raw_path}") from exc
        if size < 0:
            raise ReleaseWorkflowError(f"7z archive entry has a negative size: {path}")
        if _is_link_entry(fields):
            raise ReleaseWorkflowError(f"7z archive contains a link or unsupported entry: {path}")
        folder = fields.get("Folder")
        if folder == "+":
            if size != 0:
                raise ReleaseWorkflowError(f"7z archive directory has non-zero size: {path}")
            kind = "directory"
        elif folder in (None, "-"):
            kind = "file"
        else:
            raise ReleaseWorkflowError(f"7z archive contains a link or unsupported entry: {path}")
        entries.append((path, kind, size))

    folded = [path.casefold() for path, _kind, _size in entries]
    if not entries or len(set(folded)) != len(folded):
        raise ReleaseWorkflowError("7z archive inventory is empty or contains duplicate paths")
    files = [{"path": path, "size": size} for path, kind, size in entries if kind == "file"]
    if not files:
        raise ReleaseWorkflowError("7z archive file inventory is empty")
    allowed_directories = {
        parent.as_posix()
        for item in files
        for parent in PurePosixPath(item["path"]).parents
        if parent != PurePosixPath(".")
    }
    unexpected_directories = sorted(
        path for path, kind, _size in entries if kind == "directory" and path not in allowed_directories
    )
    if unexpected_directories:
        raise ReleaseWorkflowError(
            "7z archive contains unexpected empty or unrelated directories: " + ", ".join(unexpected_directories)
        )
    return sorted(files, key=lambda item: item["path"])

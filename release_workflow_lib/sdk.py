"""Resolve the SDK gitlink from an immutable source tree, including legacy releases."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


SDK_PATH = "s2sdk"
LEGACY_SDK_PATH = "hl2sdk_cs2"
SDK_PATHS = (SDK_PATH, LEGACY_SDK_PATH)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class SourceSdkError(ValueError):
    """The source tree does not bind exactly one SDK gitlink."""


@dataclass(frozen=True)
class SourceSdk:
    path: str
    sha: str


def source_sdk(repo_root: Path, source_sha: str) -> SourceSdk:
    if not SHA_RE.fullmatch(source_sha):
        raise SourceSdkError("SDK source must be an immutable source SHA")
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-tree", source_sha, "--", *SDK_PATHS],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise SourceSdkError(result.stderr.strip() or "Unable to read the SDK source tree")
    records = result.stdout.splitlines()
    if len(records) != 1:
        raise SourceSdkError("source must bind exactly one SDK gitlink (s2sdk or legacy hl2sdk_cs2)")
    fields = records[0].split()
    if (
        len(fields) != 4
        or fields[:2] != ["160000", "commit"]
        or not SHA_RE.fullmatch(fields[2])
        or fields[3] not in SDK_PATHS
    ):
        raise SourceSdkError("source SDK path must be a Git gitlink")
    return SourceSdk(path=fields[3], sha=fields[2])

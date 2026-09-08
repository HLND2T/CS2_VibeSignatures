"""Bounded, best-effort byte diagnostics shared by artifact verifiers."""

from __future__ import annotations

import difflib
import hashlib
from itertools import islice
from pathlib import Path

from gamesymbol_snapshot_lib.paths import is_reparse_point


MAX_DIFF_LINES = 40
MAX_DIFF_CHARACTERS = 16000
MAX_TEXT_BYTES = 1024 * 1024
MAX_LOG_CHARACTERS = 64000


def read_artifact_bytes(path: Path) -> tuple[bytes | None, str | None]:
    """Never follow links, and preserve read errors as diagnostic facts."""
    try:
        for component in (path, *path.parents):
            if is_reparse_point(component):
                return None, f"unreadable: link/reparse point: {component}"
        return path.read_bytes(), None
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, f"unreadable: {exc}"


def content_diff(
    label: str,
    expected: bytes | None,
    actual: bytes | None,
    *,
    expected_error: str | None = None,
    actual_error: str | None = None,
    max_diff_lines: int = MAX_DIFF_LINES,
) -> str:
    def describe(raw: bytes | None, error: str | None) -> str:
        if error:
            return error
        if raw is None:
            return "missing"
        return f"size={len(raw)} sha256=sha256:{hashlib.sha256(raw).hexdigest()}"

    facts = (
        f"\n  artifact: {label}"
        f"\n  expected: {describe(expected, expected_error)}"
        f"\n  actual:   {describe(actual, actual_error)}"
    )
    if expected_error or actual_error:
        return facts[:MAX_DIFF_CHARACTERS]
    if max(len(expected or b""), len(actual or b"")) > MAX_TEXT_BYTES:
        return facts + "\n  content diff omitted: text size limit exceeded"
    if b"\0" in (expected or b"") or b"\0" in (actual or b""):
        return facts + "\n  content diff unavailable: binary data"
    try:
        expected_lines = (expected or b"").decode("utf-8").splitlines()
        actual_lines = (actual or b"").decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return facts + "\n  content diff unavailable: not UTF-8"
    if expected_lines == actual_lines:
        if expected != actual:
            return facts + "\n  bytes differ only in line endings/final newline or file presence"
        return facts
    lines = list(
        islice(
            difflib.unified_diff(expected_lines, actual_lines, fromfile="expected", tofile="actual", lineterm=""),
            max_diff_lines + 1,
        )
    )
    rendered = facts + "\n  content diff (expected -> actual):\n    " + "\n    ".join(lines[:max_diff_lines])
    truncated = len(lines) > max_diff_lines or len(rendered) > MAX_DIFF_CHARACTERS
    return rendered[:MAX_DIFF_CHARACTERS] + ("\n  ... (content diff truncated)" if truncated else "")

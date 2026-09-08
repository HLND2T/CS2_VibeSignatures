"""Bounded, best-effort byte diagnostics shared by artifact verifiers."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path

from gamesymbol_snapshot_lib.paths import is_reparse_point


MAX_DIFF_LINES = 40
MAX_DIFF_CHARACTERS = 16000
MAX_TEXT_BYTES = 1024 * 1024
MAX_LOG_CHARACTERS = 64000
MAX_CHANGED_ARTIFACTS = 5
PATH_LIST_BUDGET_DIVISOR = 16


@dataclass
class DiagnosticContext:
    """Caller-bound sources; absent expected bytes mean unavailable, not an empty inventory."""

    actual_root: Path | None = None
    game_versions: tuple[str, ...] = ()
    expected: dict[str, bytes] | None = None
    evidence: dict[str, Path | bytes] = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def safe_component(value: str) -> str:
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+", value)
        or value in (".", "..")
        or value.endswith((".", " "))
        or value.split(".")[0].upper()
        in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}
    ):
        raise ValueError(f"unsafe diagnostic path component: {value!r}")
    return value


def require_real_path(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    for component in (path, *path.parents):
        if is_reparse_point(component):
            raise ValueError(f"skipped link/reparse point: {component}")
    return path


def external_staging(repo_root: Path, staging: Path) -> Path:
    repo_root = require_real_path(repo_root)
    staging = require_real_path(staging)
    if staging == repo_root or repo_root in staging.parents or staging in repo_root.parents:
        raise ValueError("diagnostic staging must be disjoint from the source checkout")
    return staging


def read_flat_artifacts(context: DiagnosticContext) -> tuple[dict[str, bytes], dict[str, str]]:
    """Read only flat GAMEVER/module/*.yaml, rejecting collisions before opening files."""
    actual = {}
    unreadable = {}

    def unavailable(prefix: str, error: str) -> None:
        for key in context.expected or {}:
            if key.startswith(prefix):
                unreadable[key] = error

    if context.actual_root is None:
        return actual, unreadable
    try:
        root = require_real_path(context.actual_root)
        candidates: dict[str, list[tuple[str, Path]]] = {}
        for gamever in context.game_versions:
            game_root = require_real_path(root / safe_component(gamever))
            if not game_root.is_dir():
                context.errors.append(f"{game_root}: missing artifact root")
                continue
            for module in sorted(game_root.iterdir()):
                try:
                    require_real_path(module)
                    safe_component(module.name)
                    if not module.is_dir():
                        raise ValueError(f"non-flat artifact path: {module}")
                    for path in sorted(module.iterdir()):
                        key = f"bin_artifacts/{gamever}/{module.name}/{path.name}"
                        try:
                            require_real_path(path)
                            if path.is_dir():
                                raise ValueError(f"non-flat artifact path: {path}")
                            if path.suffix.lower() != ".yaml":
                                continue
                            safe_component(path.name)
                            candidates.setdefault(key.casefold(), []).append((key, path))
                        except (OSError, ValueError) as exc:
                            context.errors.append(str(exc))
                            if path.suffix.lower() == ".yaml":
                                unreadable[key] = str(exc)
                except (OSError, ValueError) as exc:
                    context.errors.append(str(exc))
                    unavailable(f"bin_artifacts/{gamever}/{module.name}/", str(exc))
        for entries in candidates.values():
            if len(entries) != 1:
                error = f"case-insensitive artifact collision: {[key for key, _ in entries]!r}"
                context.errors.append(error)
                unreadable.update({key: error for key, _ in entries})
                continue
            key, path = entries[0]
            raw, error = read_artifact_bytes(path)
            if raw is None:
                unreadable[key] = error or "missing during diagnostic read"
                context.errors.append(f"{key}: {unreadable[key]}")
            else:
                actual[key] = raw
    except (OSError, ValueError) as exc:
        context.errors.append(str(exc))
        unavailable("bin_artifacts/", str(exc))
    return actual, unreadable


def render_inventory_diagnostics(context: DiagnosticContext, *, max_characters: int = MAX_LOG_CHARACTERS) -> str:
    actual, unreadable = read_flat_artifacts(context)
    pieces = []
    remaining = max_characters
    truncated = False

    def append(text: str, omitted: str) -> None:
        nonlocal remaining, truncated
        if truncated:
            return
        if len(text) > remaining:
            marker = f"\n  ... (diagnostics truncated; {omitted})"
            rendered = "".join(pieces) + text
            pieces[:] = [rendered[: max(0, max_characters - len(marker))] + marker[:max_characters]]
            remaining = 0
            truncated = True
            return
        pieces.append(text)
        remaining -= len(text)

    if context.expected is None:
        append("\n  expected artifact diagnostics unavailable", "expected unavailable")
    else:
        expected = context.expected
        missing = sorted(expected.keys() - actual.keys() - unreadable.keys())
        extra = sorted((actual.keys() | unreadable.keys()) - expected.keys())
        changed = sorted(key for key in expected.keys() & actual.keys() if expected[key] != actual[key])
        groups = (("missing", missing), ("extra", extra), ("changed", changed), ("unreadable", sorted(unreadable)))
        # Reserve most of the budget for byte facts/diffs; each path list has its own bound.
        for label, keys in groups:
            limit = max_characters // PATH_LIST_BUDGET_DIVISOR
            shown = []
            used = 0
            for key in keys:
                cost = len(repr(key)) + 2
                if used + cost > limit:
                    break
                shown.append(key)
                used += cost
            suffix = f"; {len(keys) - len(shown)} paths omitted" if len(shown) != len(keys) else ""
            append(f"\n  {label}={shown!r} (total={len(keys)}){suffix}", f"{len(keys)} {label} paths omitted")
        details = sorted(set(changed + missing + extra + list(unreadable)))
        source = str(context.metadata.get("expected_source", "Git blob"))
        sha = str(context.metadata.get("source_sha", "unknown"))
        append(f"\n  expected source: {source} ({sha})", "source details omitted")
        for index, key in enumerate(details[:MAX_CHANGED_ARTIFACTS]):
            detail = content_diff(key, expected.get(key), actual.get(key), actual_error=unreadable.get(key))
            if len(detail) > remaining:
                append(detail, f"{len(details) - index} file details omitted or incomplete")
                break
            append(detail, "file details omitted")
        else:
            if len(details) > MAX_CHANGED_ARTIFACTS:
                append(f"\n  ... {len(details) - MAX_CHANGED_ARTIFACTS} file details omitted", "file details omitted")
    for index, error in enumerate(context.errors):
        if remaining <= 0:
            break
        append(
            f"\n  collection error: {error}", f"{len(context.errors) - index} collection errors omitted or incomplete"
        )
    return "".join(pieces)


def append_failure_diagnostics(
    message: str, load_context: Callable[[], DiagnosticContext], *, max_characters: int = MAX_LOG_CHARACTERS
) -> str:
    try:
        return message + render_inventory_diagnostics(load_context(), max_characters=max_characters)
    except Exception as exc:
        return message + f"\n  artifact diagnostics unavailable: {exc}"[:max_characters]


def collect_failure_bundle(
    *,
    repo_root: Path,
    staging: Path,
    destination: Path,
    error: str,
    load_context: Callable[[], DiagnosticContext],
    phase: str,
) -> None:
    """Copy an allowlisted snapshot into a new external directory; never use evidence as validation."""
    staging = external_staging(repo_root, staging)
    destination = external_staging(repo_root, destination)
    if destination == staging or staging in destination.parents or destination in staging.parents:
        raise ValueError("diagnostic destination must be disjoint from the rebuild staging tree")
    destination.mkdir(parents=True, exist_ok=False)

    def write(relative: str, raw: bytes) -> None:
        parts = relative.split("/")
        for part in parts:
            safe_component(part)
        target = destination.joinpath(*parts)
        require_real_path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        # A fresh exclusive file also prevents overwriting a substituted leaf link.
        with target.open("xb") as stream:
            stream.write(raw)

    write("verification-error.txt", (error + "\n").encode("utf-8"))
    try:
        context = load_context()
    except Exception as exc:
        context = DiagnosticContext(errors=[str(exc)])
    metadata = {
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        **context.metadata,
        "expected_available": context.expected is not None,
        "phase": phase,
        "collection_errors": context.errors,
    }

    def save(relative: str, source: Path | bytes) -> None:
        try:
            if isinstance(source, bytes):
                raw, read_error = source, None
            else:
                raw, read_error = read_artifact_bytes(source)
            if raw is None:
                context.errors.append(f"{source}: {read_error or 'missing'}")
            else:
                write(relative, raw)
        except Exception as exc:
            context.errors.append(f"{relative}: {exc}")

    for relative, source in context.evidence.items():
        save(relative, source)
    if (
        context.actual_root is not None
        and Path(os.path.abspath(context.actual_root)) != staging / "actual-bin-artifacts"
    ):
        context.errors.append("diagnostic actual root is not staging-local")
    else:
        actual, _unreadable = read_flat_artifacts(context)
        for relative, raw in actual.items():
            save(f"actual/{relative}", raw)
    for relative, raw in (context.expected or {}).items():
        if not relative.startswith("bin_artifacts/") or len(relative.split("/")) != 4 or not relative.endswith(".yaml"):
            context.errors.append(f"invalid diagnostic Git path: {relative}")
            continue
        save(f"expected/{relative}", raw)
    write("diagnostics.json", (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


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
    marker = "\n  ... (content diff truncated)" if truncated else ""
    return rendered[: MAX_DIFF_CHARACTERS - len(marker)] + marker

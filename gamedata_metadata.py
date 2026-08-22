#!/usr/bin/env python3
"""Generate per-entry change metadata for versioned gamedata outputs.

For every generated gamedata file we emit a sibling ``<file>.metadata.json``
recording, per entry (symbol), whether our snapshot covers it and whether we
changed its value relative to the upstream file. This feeds the web diff view.

The diff baseline is always ``upstream -> ours``: the upstream payload
(downloaded or statically seeded) is the "before", the final generated file is
the "after". A change is a leaf-level value difference between the two; line
numbers refer to the final (after) file.

Entry classification (three states):
- ``covered=False``: we have no snapshot symbol for the entry; it stays upstream.
- ``covered=True, updated=False``: we have a symbol, but our value equals upstream.
- ``covered=True, updated=True``: we have a symbol and changed the value.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from gamedata_utils import (
    _build_jsonc_value_spans,
    normalize_func_name_colons_to_underscore,
    strip_jsonc_comments,
)

try:
    import vdf
except ImportError:  # pragma: no cover - only required for the cs2kz VDF generator
    vdf = None

SCHEMA_VERSION = 1

# Section keys whose values are symbol-entry records (as opposed to scalar
# fields). Case-sensitive on purpose: CounterStrikeSharp nests entry fields
# under lowercase "signatures"/"offsets", which must NOT be treated as sections.
_SECTION_KEYS = frozenset(
    {"Signatures", "Offsets", "Patches", "Signature", "Offset", "Addresses", "VFuncs", "Games", "csgo"}
)

_VDF_TOKEN_RE = re.compile(r'"[^"]*"|\{|\}')
_FLAT_ASSIGN_RE = re.compile(r"^(?P<key>[a-z0-9_]+)[ \t]*=[ \t]*(?P<value>[+-]?\d+)")


def _normalize_text(text):
    """Strip a UTF-8 BOM and normalize CRLF/CR to LF, if text is not None."""
    if text is None:
        return None
    return text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")


def _leaves(value, path=()):
    """Yield every scalar leaf as ``(path_tuple, scalar_value)``."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _leaves(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _leaves(child, path + (index,))
    else:
        yield path, value


def _scalar_equal(left, right):
    if type(left) is not type(right):
        return False
    return left == right


def _entry_and_covered(segments, yaml_data, alias_map):
    """Return ``(entry_name, covered)`` for a leaf path.

    Covered means the first path segment whose normalized name maps to a
    snapshot symbol (the same predicate generators use for name matching).
    Uncovered entries fall back to the key immediately after the deepest
    section key so they still group under a readable name.
    """
    for segment in segments:
        if isinstance(segment, str):
            normalized = normalize_func_name_colons_to_underscore(segment, alias_map)
            if normalized in yaml_data:
                return segment, True
    for index in range(len(segments) - 1, -1, -1):
        segment = segments[index]
        if isinstance(segment, str) and segment in _SECTION_KEYS:
            following = segments[index + 1] if index + 1 < len(segments) else None
            if isinstance(following, str):
                return following, False
    for segment in segments:
        if isinstance(segment, str):
            return segment, False
    return "<entry>", False


def _group_leaves(old_leaves, new_leaves, yaml_data, alias_map, line_of):
    entries = {}
    for path in set(old_leaves) | set(new_leaves):
        name, covered = _entry_and_covered(path, yaml_data, alias_map)
        record = entries.setdefault(name, {"covered": covered, "changes": []})
        in_old = path in old_leaves
        in_new = path in new_leaves
        if in_old and in_new:
            old_value = old_leaves[path]
            new_value = new_leaves[path]
            if _scalar_equal(old_value, new_value):
                continue
            before, after = old_value, new_value
            line = line_of(path)
        elif in_new:
            before, after = None, new_leaves[path]
            line = line_of(path)
        else:
            before, after = old_leaves[path], None
            line = None
        record["changes"].append({"path": list(path), "before": before, "after": after, "line": line})
    return entries


def _finalize_entries(entries):
    result = []
    for name in sorted(entries, key=str.lower):
        record = entries[name]
        changes = sorted(
            record["changes"],
            key=lambda change: (
                change["line"] is None,
                change["line"] if change["line"] is not None else -1,
                json.dumps(change["path"], sort_keys=True),
            ),
        )
        entry = {"name": name, "covered": record["covered"], "updated": bool(changes)}
        if changes:
            entry["changes"] = changes
        result.append(entry)
    return result


def _jsonc_line_of(after_text):
    try:
        spans = _build_jsonc_value_spans(after_text)
    except Exception:
        return lambda _path: None

    def line_of(path):
        span = spans.get(path)
        if span is None:
            return None
        return after_text.count("\n", 0, span.start) + 1

    return line_of


def _diff_json(before_text, after_text, yaml_data, alias_map):
    before_data = json.loads(strip_jsonc_comments(before_text)) if before_text is not None else None
    after_data = json.loads(strip_jsonc_comments(after_text))
    old_leaves = dict(_leaves(before_data)) if before_data is not None else {}
    new_leaves = dict(_leaves(after_data))
    return _group_leaves(old_leaves, new_leaves, yaml_data, alias_map, _jsonc_line_of(after_text))


def _vdf_leaf_lines(text):
    """Map every scalar leaf path to its line number in pretty-printed VDF text."""
    tokens = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for match in _VDF_TOKEN_RE.finditer(line):
            tokens.append((match.group(0), lineno))
    result = {}
    position = 0

    def unquote(token):
        return token[1:-1]

    def parse_object(path):
        nonlocal position
        position += 1  # consume '{'
        while tokens[position][0] != "}":
            parse_pair(path)
        position += 1  # consume '}'

    def parse_pair(path):
        nonlocal position
        key_token, key_line = tokens[position]
        position += 1
        if tokens[position][0] == "{":
            parse_object(path + (unquote(key_token),))
        else:
            position += 1  # consume the scalar value token
            result[path + (unquote(key_token),)] = key_line

    parse_pair(())
    return result


def _diff_vdf(before_text, after_text, yaml_data, alias_map):
    before_data = vdf.loads(before_text) if before_text is not None else None
    after_data = vdf.loads(after_text)
    old_leaves = dict(_leaves(before_data)) if before_data is not None else {}
    new_leaves = dict(_leaves(after_data))
    leaf_lines = _vdf_leaf_lines(after_text)
    return _group_leaves(old_leaves, new_leaves, yaml_data, alias_map, lambda path: leaf_lines.get(path))


def _parse_flat_assignments(text):
    entries = {}
    if text is None:
        return entries
    for lineno, line in enumerate(text.splitlines(), 1):
        match = _FLAT_ASSIGN_RE.match(line)
        if match:
            entries[match.group("key")] = (match.group("value"), lineno)
    return entries


def _diff_flat(before_text, after_text, yaml_data, alias_map):
    # Flat key=value templates (CS2FOW) re-substitute every value from the
    # snapshot, so every entry is covered by construction.
    del yaml_data, alias_map
    old_entries = _parse_flat_assignments(before_text)
    new_entries = _parse_flat_assignments(after_text)
    entries = {}
    for key in set(old_entries) | set(new_entries):
        record = entries.setdefault(key, {"covered": True, "changes": []})
        in_old = key in old_entries
        in_new = key in new_entries
        if in_old and in_new:
            old_value = old_entries[key][0]
            new_value = new_entries[key][0]
            if old_value == new_value:
                continue
            before, after = old_value, new_value
            line = new_entries[key][1]
        elif in_new:
            before, after = None, new_entries[key][0]
            line = new_entries[key][1]
        else:
            before, after = old_entries[key][0], None
            line = None
        record["changes"].append({"path": [key], "before": before, "after": after, "line": line})
    return entries


def compute_file_metadata(*, before_text, after_text, rel_path, gamever, yaml_data, alias_to_name_map):
    """Compute the metadata document for one gamedata output file."""
    before = _normalize_text(before_text)
    after = _normalize_text(after_text)
    suffix = Path(rel_path).suffix.lower()
    if suffix in {".json", ".jsonc"}:
        entries = _diff_json(before, after, yaml_data, alias_to_name_map)
    elif suffix == ".txt":
        if vdf is not None and (after or "").lstrip().startswith(('"', "{")):
            entries = _diff_vdf(before, after, yaml_data, alias_to_name_map)
        else:
            entries = _diff_flat(before, after, yaml_data, alias_to_name_map)
    else:
        raise ValueError(f"unsupported gamedata output suffix: {rel_path}")

    finalized = _finalize_entries(entries)
    covered = sum(1 for entry in finalized if entry["covered"])
    updated = sum(1 for entry in finalized if entry.get("updated"))
    return {
        "schema_version": SCHEMA_VERSION,
        "gamever": str(gamever),
        "file": rel_path,
        "summary": {"total": len(finalized), "covered": covered, "updated": updated},
        "entries": finalized,
    }


def _atomic_write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(text.encode("utf-8"))
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def write_file_metadata(
    *,
    before_text,
    after_text,
    rel_path,
    gamever,
    yaml_data,
    alias_to_name_map,
    metadata_path,
):
    """Compute and atomically write ``<file>.metadata.json`` for one output."""
    metadata = compute_file_metadata(
        before_text=before_text,
        after_text=after_text,
        rel_path=rel_path,
        gamever=gamever,
        yaml_data=yaml_data,
        alias_to_name_map=alias_to_name_map,
    )
    _atomic_write_json(Path(metadata_path), metadata)
    return metadata

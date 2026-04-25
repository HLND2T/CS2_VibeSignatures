#!/usr/bin/env python3
"""
Gamedata Utilities for CS2_VibeSignatures

Shared utility functions for gamedata update modules.
"""

import json
import os
import tempfile
from dataclasses import dataclass


# =============================================================================
# Signature Format Converters
# =============================================================================

def convert_sig_to_css(sig):
    """
    Convert YAML signature to CounterStrikeSharp format.

    YAML: "48 89 5C 24 ?? 48 8B D9"
    CSS:  "48 89 5C 24 ? 48 8B D9"

    Args:
        sig: Signature string from YAML

    Returns:
        Converted signature string
    """
    return sig.replace("??", "?")


def convert_sig_to_cs2fixes(sig):
    """
    Convert YAML signature to CS2Fixes VDF format.

    YAML: "48 89 5C 24 ?? 48 8B D9"
    VDF:  "\\x48\\x89\\x5C\\x24\\x2A\\x48\\x8B\\xD9"

    Args:
        sig: Signature string from YAML

    Returns:
        Converted signature string with \\xHH format
    """
    parts = sig.split()
    result = []
    for part in parts:
        if part == "??":
            result.append("\\x2A")
        else:
            result.append(f"\\x{part}")
    return "".join(result)


def convert_sig_to_swiftly(sig):
    """
    Convert YAML signature to Swiftly format.

    YAML: "48 89 5C 24 ?? 48 8B D9"
    Swiftly: "48 89 5C 24 ? 48 8B D9"

    Args:
        sig: Signature string from YAML

    Returns:
        Converted signature string
    """
    return sig.replace("??", "?")


# =============================================================================
# Name Normalization
# =============================================================================

def normalize_func_name_colons_to_underscore(name, alias_to_name_map=None):
    """
    Convert function name from double-colon format to underscore format.

    First looks up the name in the alias_to_name_map from config.yaml.
    If not found, falls back to simple :: to _ replacement.

    Example: CCSPlayerController::ChangeTeam -> CCSPlayerController_ChangeTeam

    Args:
        name: Function name with double colons
        alias_to_name_map: Optional mapping from aliases to names (from config.yaml)

    Returns:
        Function name with underscores
    """
    # First try to find in config.yaml aliases
    if alias_to_name_map and name in alias_to_name_map:
        return alias_to_name_map[name]

    # Fallback: simple replacement
    return name.replace("::", "_")


# =============================================================================
# JSONC File Handling
# =============================================================================

@dataclass(frozen=True)
class _JsoncValueSpan:
    start: int
    end: int


def _skip_jsonc_ws_and_comments(content, index):
    while index < len(content):
        char = content[index]
        if char in " \t\r\n":
            index += 1
            continue
        if content.startswith("//", index):
            index += 2
            while index < len(content) and content[index] != "\n":
                index += 1
            continue
        if content.startswith("/*", index):
            end_index = content.find("*/", index + 2)
            if end_index == -1:
                raise ValueError("unterminated JSONC block comment")
            index = end_index + 2
            continue
        return index
    return index


def _scan_json_string(content, index):
    if index >= len(content) or content[index] != "\"":
        raise ValueError("expected JSON string")
    index += 1
    escape_next = False
    while index < len(content):
        char = content[index]
        if escape_next:
            escape_next = False
        elif char == "\\":
            escape_next = True
        elif char == "\"":
            return index + 1
        index += 1
    raise ValueError("unterminated JSON string")


def _scan_json_number(content, index):
    start = index
    while index < len(content) and content[index] in "-+0123456789.eE":
        index += 1
    if start == index:
        raise ValueError("expected JSON number")
    json.loads(content[start:index])
    return index


def _scan_json_literal(content, index, literal):
    if not content.startswith(literal, index):
        raise ValueError(f"expected JSON literal {literal}")
    return index + len(literal)


def _scan_jsonc_value_spans(content, index, path, spans):
    value_start = _skip_jsonc_ws_and_comments(content, index)
    if value_start >= len(content):
        raise ValueError("expected JSON value")

    char = content[value_start]
    if char == "{":
        value_end = _scan_jsonc_object(content, value_start, path, spans)
    elif char == "[":
        value_end = _scan_jsonc_array(content, value_start, path, spans)
    elif char == "\"":
        value_end = _scan_json_string(content, value_start)
    elif char in "-0123456789":
        value_end = _scan_json_number(content, value_start)
    elif content.startswith("true", value_start):
        value_end = _scan_json_literal(content, value_start, "true")
    elif content.startswith("false", value_start):
        value_end = _scan_json_literal(content, value_start, "false")
    elif content.startswith("null", value_start):
        value_end = _scan_json_literal(content, value_start, "null")
    else:
        raise ValueError(f"unexpected JSONC value at offset {value_start}")

    spans[path] = _JsoncValueSpan(value_start, value_end)
    return value_end


def _scan_jsonc_object(content, index, path, spans):
    index += 1
    index = _skip_jsonc_ws_and_comments(content, index)
    if index < len(content) and content[index] == "}":
        return index + 1

    while True:
        key_start = _skip_jsonc_ws_and_comments(content, index)
        key_end = _scan_json_string(content, key_start)
        key = json.loads(content[key_start:key_end])
        colon_index = _skip_jsonc_ws_and_comments(content, key_end)
        if colon_index >= len(content) or content[colon_index] != ":":
            raise ValueError("expected ':' after JSON object key")
        index = _scan_jsonc_value_spans(
            content, colon_index + 1, path + (key,), spans
        )
        index = _skip_jsonc_ws_and_comments(content, index)
        if index < len(content) and content[index] == ",":
            index += 1
            continue
        if index < len(content) and content[index] == "}":
            return index + 1
        raise ValueError("expected ',' or '}' in JSON object")


def _scan_jsonc_array(content, index, path, spans):
    index += 1
    item_index = 0
    index = _skip_jsonc_ws_and_comments(content, index)
    if index < len(content) and content[index] == "]":
        return index + 1

    while True:
        index = _scan_jsonc_value_spans(content, index, path + (item_index,), spans)
        item_index += 1
        index = _skip_jsonc_ws_and_comments(content, index)
        if index < len(content) and content[index] == ",":
            index += 1
            continue
        if index < len(content) and content[index] == "]":
            return index + 1
        raise ValueError("expected ',' or ']' in JSON array")


def _jsonc_values_equal(left, right):
    if isinstance(left, dict) and isinstance(right, dict):
        if left.keys() != right.keys():
            return False
        return all(_jsonc_values_equal(left[key], right[key]) for key in left)
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return False
        return all(
            _jsonc_values_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return type(left) is type(right) and left == right


def _collect_jsonc_leaf_changes(old_value, new_value, path=()):
    if isinstance(old_value, dict) and isinstance(new_value, dict):
        if old_value.keys() != new_value.keys():
            return None
        changes = []
        for key in old_value:
            child_changes = _collect_jsonc_leaf_changes(
                old_value[key], new_value[key], path + (key,)
            )
            if child_changes is None:
                return None
            changes.extend(child_changes)
        return changes

    if isinstance(old_value, list) and isinstance(new_value, list):
        if len(old_value) != len(new_value):
            return None
        changes = []
        for index, old_item in enumerate(old_value):
            child_changes = _collect_jsonc_leaf_changes(
                old_item, new_value[index], path + (index,)
            )
            if child_changes is None:
                return None
            changes.extend(child_changes)
        return changes

    if isinstance(old_value, (dict, list)) or isinstance(new_value, (dict, list)):
        return None
    if _jsonc_values_equal(old_value, new_value):
        return []
    return [(path, new_value)]


def _format_jsonc_replacement_value(value):
    return json.dumps(value, ensure_ascii=False)


def _apply_jsonc_replacements(content, replacements):
    updated = content
    previous_start = len(content) + 1
    for start, end, value_text in sorted(replacements, reverse=True):
        if end > previous_start:
            raise ValueError("overlapping JSONC replacement spans")
        updated = updated[:start] + value_text + updated[end:]
        previous_start = start
    return updated


def _build_jsonc_value_spans(content):
    spans = {}
    end_index = _scan_jsonc_value_spans(content, 0, (), spans)
    end_index = _skip_jsonc_ws_and_comments(content, end_index)
    if end_index != len(content):
        raise ValueError("unexpected content after root JSONC value")
    return spans


def _dump_jsonc_preserving_values(original_content, data):
    original_data = json.loads(strip_jsonc_comments(original_content))
    changes = _collect_jsonc_leaf_changes(original_data, data)
    if changes is None:
        raise ValueError("JSONC structural changes cannot be preserved safely")
    if not changes:
        return original_content

    spans = _build_jsonc_value_spans(original_content)
    replacements = []
    for path, value in changes:
        span = spans.get(path)
        if span is None:
            raise ValueError(f"missing JSONC value span for path {path}")
        replacements.append(
            (span.start, span.end, _format_jsonc_replacement_value(value))
        )

    updated = _apply_jsonc_replacements(original_content, replacements)
    if not _jsonc_values_equal(json.loads(strip_jsonc_comments(updated)), data):
        raise ValueError("JSONC preservation changed parsed data unexpectedly")
    return updated


def strip_jsonc_comments(content):
    """
    Strip comments from JSONC content.

    Removes both single-line (//) and multi-line (/* */) comments,
    while preserving strings that might contain comment-like patterns.

    Args:
        content: JSONC content string

    Returns:
        JSON content string without comments
    """
    result = []
    i = 0
    in_string = False
    escape_next = False

    while i < len(content):
        char = content[i]

        if escape_next:
            result.append(char)
            escape_next = False
            i += 1
            continue

        if char == '\\' and in_string:
            result.append(char)
            escape_next = True
            i += 1
            continue

        if char == '"' and not escape_next:
            in_string = not in_string
            result.append(char)
            i += 1
            continue

        if not in_string:
            # Check for single-line comment
            if char == '/' and i + 1 < len(content) and content[i + 1] == '/':
                # Skip until end of line
                while i < len(content) and content[i] != '\n':
                    i += 1
                continue

            # Check for multi-line comment
            if char == '/' and i + 1 < len(content) and content[i + 1] == '*':
                i += 2
                # Skip until */
                while i + 1 < len(content):
                    if content[i] == '*' and content[i + 1] == '/':
                        i += 2
                        break
                    i += 1
                continue

        result.append(char)
        i += 1

    return ''.join(result)


def load_jsonc(file_path):
    """
    Load and parse a JSONC file (JSON with comments).

    Args:
        file_path: Path to the JSONC file

    Returns:
        Parsed JSON data as dictionary
    """
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    content = strip_jsonc_comments(content)
    return json.loads(content)


def _write_text_atomic(file_path, content):
    path = os.fspath(file_path)
    directory = os.path.dirname(os.path.abspath(path))
    fd, temp_path = tempfile.mkstemp(
        dir=directory,
        prefix=f".{os.path.basename(path)}.",
        suffix=".tmp",
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        os.replace(temp_path, path)
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def _save_jsonc_plain(file_path, data):
    content = json.dumps(data, indent=4) + "\n"
    _write_text_atomic(file_path, content)


def save_jsonc(file_path, data, original_content=None):
    """
    Save data to a JSONC file, preserving comments when possible.

    Args:
        file_path: Path to the JSONC file
        data: Data to save
        original_content: Optional original file content
    """
    if original_content is None:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                original_content = f.read()
        except OSError:
            original_content = None

    if original_content is not None:
        try:
            preserved = _dump_jsonc_preserving_values(original_content, data)
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"  Warning: Falling back to plain JSON for {file_path}: {exc}")
        else:
            _write_text_atomic(file_path, preserved)
            return

    _save_jsonc_plain(file_path, data)

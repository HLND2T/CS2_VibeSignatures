# JSONC Comment Preservation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve existing JSONC comments, blank lines, indentation, and key order when `update_gamedata.py` updates existing gamedata values.

**Architecture:** Keep all behavior centralized in `gamedata_utils.py` so existing `dist/*/gamedata.py` modules keep calling `load_jsonc()` and `save_jsonc()`. Add a small JSONC scanner that maps JSON paths to original value spans, compare old data with new data, and replace only changed leaf value slices in the original text. Fall back to the current plain JSON writer when a change cannot be represented as safe leaf-value replacement.

**Tech Stack:** Python 3.10+, builtin `json`, `dataclasses`, `unittest`, existing `uv run python -m unittest` workflow.

---

## Scope Check

This plan covers one subsystem: JSONC read/write preservation for gamedata files. It does not change YAML loading, signature conversion, VDF output, download behavior, or module discovery.

## File Structure

- Modify: `gamedata_utils.py`
  - Add JSONC value span scanning helpers.
  - Add leaf-diff and replacement helpers.
  - Update `save_jsonc()` to try preserving original JSONC text first.
- Create: `tests/test_gamedata_utils.py`
  - Add focused unit tests for comment preservation, nested path replacement, comment-like strings, and structural fallback.

## Repository Constraints

- Do not run broad test/build commands unless the user explicitly asks.
- Use only targeted `unittest` commands from this plan when validation is authorized.
- Do not create a git commit unless the user explicitly asks.

---

### Task 1: Add Failing JSONC Preservation Tests

**Files:**
- Create: `tests/test_gamedata_utils.py`

- [ ] **Step 1: Create focused tests**

Create `tests/test_gamedata_utils.py` with this complete content:

```python
import json
import tempfile
import unittest
from pathlib import Path

import gamedata_utils


class TestJsoncPreservingSave(unittest.TestCase):
    def _write_temp_jsonc(self, content: str) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "gamedata.jsonc"
        path.write_text(content, encoding="utf-8")
        return path

    def _load_clean_json(self, content: str) -> object:
        return json.loads(gamedata_utils.strip_jsonc_comments(content))

    def test_save_jsonc_preserves_comments_and_replaces_only_changed_string(self) -> None:
        original = (
            "{\n"
            "    // keep file comment\n"
            "    \"CEntityInstance::AcceptInput\": {\n"
            "        // keep platform comment\n"
            "        \"windows\": \"old sig\", // keep trailing comment\n"
            "        \"linux\": \"same sig\"\n"
            "    }\n"
            "}\n"
        )
        path = self._write_temp_jsonc(original)

        data = gamedata_utils.load_jsonc(path)
        data["CEntityInstance::AcceptInput"]["windows"] = "new sig"

        gamedata_utils.save_jsonc(path, data)

        updated = path.read_text(encoding="utf-8")
        expected = original.replace("\"old sig\"", "\"new sig\"")
        self.assertEqual(expected, updated)
        self.assertEqual(data, self._load_clean_json(updated))

    def test_save_jsonc_preserves_block_comments_and_comment_like_string_content(self) -> None:
        original = (
            "{\n"
            "    \"url\": \"https://example.test/a//b/*not-comment*/\",\n"
            "    /* keep block comment */\n"
            "    \"value\": 1\n"
            "}\n"
        )
        path = self._write_temp_jsonc(original)

        data = gamedata_utils.load_jsonc(path)
        data["value"] = 2

        gamedata_utils.save_jsonc(path, data)

        updated = path.read_text(encoding="utf-8")
        expected = original.replace("\"value\": 1", "\"value\": 2")
        self.assertEqual(expected, updated)
        self.assertEqual(data, self._load_clean_json(updated))

    def test_save_jsonc_replaces_nested_integer_without_reformatting_siblings(self) -> None:
        original = (
            "{\n"
            "    \"$schema\": \"schema.json\",\n"
            "    \"csgo\": {\n"
            "        \"Offsets\": {\n"
            "            \"Foo\": {\n"
            "                \"win64\": 1,\n"
            "                \"linuxsteamrt64\": 2 // keep linux comment\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        path = self._write_temp_jsonc(original)

        data = gamedata_utils.load_jsonc(path)
        data["csgo"]["Offsets"]["Foo"]["win64"] = 3

        gamedata_utils.save_jsonc(path, data)

        updated = path.read_text(encoding="utf-8")
        expected = original.replace("\"win64\": 1", "\"win64\": 3")
        self.assertEqual(expected, updated)
        self.assertEqual(data, self._load_clean_json(updated))

    def test_save_jsonc_falls_back_to_plain_json_for_new_key(self) -> None:
        original = (
            "{\n"
            "    // this comment cannot be preserved when adding a key\n"
            "    \"existing\": 1\n"
            "}\n"
        )
        path = self._write_temp_jsonc(original)

        data = gamedata_utils.load_jsonc(path)
        data["added"] = True

        gamedata_utils.save_jsonc(path, data)

        updated = path.read_text(encoding="utf-8")
        self.assertNotIn("// this comment cannot be preserved", updated)
        self.assertEqual(data, json.loads(updated))
        self.assertTrue(updated.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify current failure**

Run only after user authorizes targeted test execution:

```bash
uv run python -m unittest tests.test_gamedata_utils -v
```

Expected: the first three tests fail because current `save_jsonc()` rewrites the whole file with `json.dump()`, removing comments and changing untouched text. The structural fallback test may pass with current behavior.

---

### Task 2: Add JSONC Span Scanner Helpers

**Files:**
- Modify: `gamedata_utils.py`
- Test: `tests/test_gamedata_utils.py`

- [ ] **Step 1: Add imports and span dataclass**

At the top of `gamedata_utils.py`, replace the import block:

```python
import json
```

with:

```python
import json
from dataclasses import dataclass
```

Add this dataclass immediately under the JSONC section header and before `strip_jsonc_comments()`:

```python
@dataclass(frozen=True)
class _JsoncValueSpan:
    start: int
    end: int
```

- [ ] **Step 2: Add whitespace and comment skipper**

Insert this helper after `_JsoncValueSpan`:

```python
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
```

- [ ] **Step 3: Add primitive scanners**

Insert these helpers after `_skip_jsonc_ws_and_comments()`:

```python
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
```

- [ ] **Step 4: Add recursive value span scanner**

Insert these helpers after `_scan_json_literal()`:

```python
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
```

- [ ] **Step 5: Run scanner tests and confirm still failing at save behavior**

Run only after user authorizes targeted test execution:

```bash
uv run python -m unittest tests.test_gamedata_utils -v
```

Expected: tests still fail because `save_jsonc()` has not used the new scanner yet. No syntax errors should appear.

---

### Task 3: Add Leaf Diff and Original Text Replacement

**Files:**
- Modify: `gamedata_utils.py`
- Test: `tests/test_gamedata_utils.py`

- [ ] **Step 1: Add leaf change collector**

Insert these helpers after `_scan_jsonc_array()`:

```python
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
    if old_value == new_value:
        return []
    return [(path, new_value)]
```

- [ ] **Step 2: Add replacement and validation helpers**

Insert these helpers after `_collect_jsonc_leaf_changes()`:

```python
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
    if json.loads(strip_jsonc_comments(updated)) != data:
        raise ValueError("JSONC preservation changed parsed data unexpectedly")
    return updated
```

- [ ] **Step 3: Add plain writer helper**

Insert this helper immediately before `save_jsonc()`:

```python
def _save_jsonc_plain(file_path, data):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
        f.write("\n")
```

- [ ] **Step 4: Update `save_jsonc()`**

Replace the current `save_jsonc()` body with:

```python
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
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(preserved)
            return

    _save_jsonc_plain(file_path, data)
```

- [ ] **Step 5: Run targeted tests**

Run only after user authorizes targeted test execution:

```bash
uv run python -m unittest tests.test_gamedata_utils -v
```

Expected: all four tests pass with `OK`.

---

### Task 4: Add Coverage for Existing `original_content` Parameter

**Files:**
- Modify: `tests/test_gamedata_utils.py`

- [ ] **Step 1: Add explicit `original_content` test**

Append this method inside `class TestJsoncPreservingSave(unittest.TestCase)`:

```python
    def test_save_jsonc_uses_supplied_original_content(self) -> None:
        original = (
            "{\n"
            "    // supplied source comment\n"
            "    \"value\": \"old\"\n"
            "}\n"
        )
        path = self._write_temp_jsonc("{\"value\":\"seed\"}\n")

        data = {"value": "new"}
        gamedata_utils.save_jsonc(path, data, original_content=original)

        updated = path.read_text(encoding="utf-8")
        expected = original.replace("\"old\"", "\"new\"")
        self.assertEqual(expected, updated)
        self.assertEqual(data, self._load_clean_json(updated))
```

- [ ] **Step 2: Run targeted tests**

Run only after user authorizes targeted test execution:

```bash
uv run python -m unittest tests.test_gamedata_utils -v
```

Expected: five tests pass with `OK`.

---

### Task 5: Validate Syntax and Integration Boundary

**Files:**
- Modify: `gamedata_utils.py`
- Test: `tests/test_gamedata_utils.py`

- [ ] **Step 1: Run syntax check**

Run only after user authorizes targeted validation:

```bash
uv run python -m py_compile gamedata_utils.py tests/test_gamedata_utils.py
```

Expected: command exits successfully with no output.

- [ ] **Step 2: Run final targeted unit test**

Run only after user authorizes targeted validation:

```bash
uv run python -m unittest tests.test_gamedata_utils -v
```

Expected: output ends with `OK`.

- [ ] **Step 3: Inspect changed files**

Run:

```bash
git diff -- gamedata_utils.py tests/test_gamedata_utils.py
```

Expected: diff shows only shared JSONC preservation helpers, updated `save_jsonc()`, and the new focused test file. No `dist/*/gamedata.py` modules are changed.

---

## Handoff Notes

- If targeted tests are not authorized, do not claim tests passed; report that the implementation was statically reviewed only.
- If `save_jsonc()` prints fallback warnings for normal signature/offset value updates, treat that as a bug because existing leaf-value replacements should preserve JSONC text.
- If a future gamedata module adds keys, fallback to plain JSON is expected by this plan and should be reported as a limitation rather than a preservation success.

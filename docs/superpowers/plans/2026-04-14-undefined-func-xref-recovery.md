# Undefined Function Xref Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover function starts for all `_collect_xref_func_*` paths when IDA leaves the matching code block outside any defined function but a unique valid `call`/`jmp`/`lea` entry reference exists.

**Architecture:** Add a shared normalization layer in `ida_analyze_util.py` that first uses existing `idaapi.get_func(...)`, then conservatively scans upward by `0x200` bytes for a unique entry candidate referenced from an existing valid IDA function. All string, direct-address, and signature xref collectors feed raw code addresses into this shared helper before returning function-start sets.

**Tech Stack:** Python async helpers, IDA MCP `py_eval`, IDA MCP `define_func`, `unittest.IsolatedAsyncioTestCase`, `unittest.mock.AsyncMock`.

**Commit Policy:** Do not commit during execution unless the user explicitly requests it; project instructions override the generic frequent-commit guidance.

---

## File Structure

- Modify: `ida_analyze_util.py`
  - Add a `0x200` recovery-window constant near the existing xref helper utilities.
  - Add parsing and normalization helpers near `_parse_func_start_set_from_py_eval`.
  - Change `_collect_xref_func_starts_for_string`, `_collect_xref_func_starts_for_ea`, and `_collect_xref_func_starts_for_signature` to collect raw code addresses and normalize them through the shared helper.
- Modify: `tests/test_ida_analyze_util.py`
  - Extend `TestFuncXrefsSignatureSupport` with helper-level tests and collector integration tests.

## Task 1: Add Shared Recovery Helpers

**Files:**
- Modify: `ida_analyze_util.py:4451`
- Test: `tests/test_ida_analyze_util.py:1078`

- [ ] **Step 1: Add failing tests for helper behavior**

Append these tests inside `class TestFuncXrefsSignatureSupport(unittest.IsolatedAsyncioTestCase):` in `tests/test_ida_analyze_util.py`:

```python
    async def test_normalize_func_start_returns_existing_function(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {"status": "resolved", "func_start": "0x180001000"}
        )

        result = await ida_analyze_util._normalize_func_start_for_code_addr(
            session=session,
            code_addr=0x180001020,
            debug=True,
        )

        self.assertEqual(0x180001000, result)
        session.call_tool.assert_awaited_once()
        self.assertEqual("py_eval", session.call_tool.await_args.kwargs["name"])

    async def test_normalize_func_start_defines_unique_entry_candidate(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _py_eval_payload(
                {"status": "needs_define", "entry": "0x180001000"}
            ),
            _FakeCallToolResult({"ok": True}),
            _py_eval_payload(
                {"status": "resolved", "func_start": "0x180001000"}
            ),
        ]

        result = await ida_analyze_util._normalize_func_start_for_code_addr(
            session=session,
            code_addr=0x180001050,
            debug=True,
        )

        self.assertEqual(0x180001000, result)
        self.assertEqual(3, session.call_tool.await_count)
        define_call = session.call_tool.await_args_list[1]
        self.assertEqual("define_func", define_call.kwargs["name"])
        self.assertEqual(
            {"items": {"addr": "0x180001000"}},
            define_call.kwargs["arguments"],
        )

    async def test_normalize_func_start_skips_multiple_entry_candidates(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "status": "multiple_entries",
                "entries": ["0x180001000", "0x180001020"],
            }
        )

        result = await ida_analyze_util._normalize_func_start_for_code_addr(
            session=session,
            code_addr=0x180001050,
            debug=True,
        )

        self.assertIsNone(result)
        session.call_tool.assert_awaited_once()

    async def test_normalize_func_start_skips_existing_function_collision(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "status": "blocked_existing_function",
                "func_start": "0x180000f00",
            }
        )

        result = await ida_analyze_util._normalize_func_start_for_code_addr(
            session=session,
            code_addr=0x180001050,
            debug=True,
        )

        self.assertIsNone(result)
        session.call_tool.assert_awaited_once()

    async def test_normalize_func_start_probe_uses_conservative_filters(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {"status": "no_entry"}
        )

        await ida_analyze_util._normalize_func_start_for_code_addr(
            session=session,
            code_addr=0x180001050,
            debug=True,
        )

        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn("backtrack_limit = 512", py_code)
        self.assertIn("('call', 'jmp', 'lea')", py_code)
        self.assertIn("ref_func = idaapi.get_func(xref.frm)", py_code)
        self.assertIn("if not ref_func:", py_code)
        self.assertIn("idautils.XrefsTo(probe_ea, 0)", py_code)
        self.assertNotIn("idaapi.add_func(code_addr)", py_code)
        self.assertNotIn("define_func", py_code)
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run:

```bash
python -m unittest tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport -v
```

Expected: FAIL with `AttributeError: module 'ida_analyze_util' has no attribute '_normalize_func_start_for_code_addr'`.

- [ ] **Step 3: Add helper constants and parser**

In `ida_analyze_util.py`, insert this code immediately after `_parse_int_value` and before `_parse_func_start_set_from_py_eval`:

```python
UNDEFINED_FUNC_RECOVERY_BACKTRACK_LIMIT = 0x200


def _parse_int_set_from_py_eval(eval_data, debug=False):
    """Parse a py_eval JSON list payload into a set of integers."""
    if not isinstance(eval_data, dict):
        return None

    stderr_text = eval_data.get("stderr", "")
    if stderr_text and debug:
        print("    Preprocess: py_eval stderr:")
        print(stderr_text.strip())

    result_str = eval_data.get("result", "")
    if not result_str:
        return None

    try:
        parsed = json.loads(result_str)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(parsed, list):
        return None

    values = set()
    for item in parsed:
        try:
            values.add(_parse_int_value(item))
        except Exception:
            continue
    return values
```

- [ ] **Step 4: Make the existing set parser delegate**

Replace the body of `_parse_func_start_set_from_py_eval` in `ida_analyze_util.py` with:

```python
def _parse_func_start_set_from_py_eval(eval_data, debug=False):
    """Parse py_eval JSON payload, or return None on invalid payload."""
    return _parse_int_set_from_py_eval(eval_data, debug=debug)
```

- [ ] **Step 5: Add recovery probe and verification helpers**

Insert this code after `_parse_func_start_set_from_py_eval`:

```python
def _parse_py_eval_json_object(eval_data, debug=False):
    """Parse a py_eval JSON object payload, or return None on invalid payload."""
    if not isinstance(eval_data, dict):
        return None

    stderr_text = eval_data.get("stderr", "")
    if stderr_text and debug:
        print("    Preprocess: py_eval stderr:")
        print(stderr_text.strip())

    result_str = eval_data.get("result", "")
    if not result_str:
        return None

    try:
        parsed = json.loads(result_str)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


async def _probe_func_start_or_entry_candidate(session, code_addr, debug=False):
    """Return existing func start or one conservative undefined-entry candidate."""
    py_code = (
        "import ida_bytes, idaapi, idautils, idc, json\n"
        f"code_addr = {_parse_int_value(code_addr)}\n"
        f"backtrack_limit = {UNDEFINED_FUNC_RECOVERY_BACKTRACK_LIMIT}\n"
        "result_obj = {'status': 'no_entry'}\n"
        "func = idaapi.get_func(code_addr)\n"
        "if func:\n"
        "    result_obj = {'status': 'resolved', 'func_start': hex(func.start_ea)}\n"
        "else:\n"
        "    candidates = set()\n"
        "    lower_bound = max(0, code_addr - backtrack_limit)\n"
        "    for probe_ea in range(code_addr, lower_bound - 1, -1):\n"
        "        other_func = idaapi.get_func(probe_ea)\n"
        "        if other_func:\n"
        "            result_obj = {\n"
        "                'status': 'blocked_existing_function',\n"
        "                'func_start': hex(other_func.start_ea),\n"
        "            }\n"
        "            break\n"
        "        flags = ida_bytes.get_full_flags(probe_ea)\n"
        "        if not ida_bytes.is_code(flags):\n"
        "            continue\n"
        "        for xref in idautils.XrefsTo(probe_ea, 0):\n"
        "            ref_func = idaapi.get_func(xref.frm)\n"
        "            if not ref_func:\n"
        "                continue\n"
        "            mnem = idc.print_insn_mnem(xref.frm).lower()\n"
        "            if mnem not in ('call', 'jmp', 'lea'):\n"
        "                continue\n"
        "            operand_targets = [idc.get_operand_value(xref.frm, idx) for idx in range(3)]\n"
        "            if probe_ea in operand_targets:\n"
        "                candidates.add(probe_ea)\n"
        "    if result_obj.get('status') == 'no_entry':\n"
        "        if len(candidates) == 1:\n"
        "            result_obj = {'status': 'needs_define', 'entry': hex(next(iter(candidates)))}\n"
        "        elif len(candidates) > 1:\n"
        "            result_obj = {\n"
        "                'status': 'multiple_entries',\n"
        "                'entries': [hex(ea) for ea in sorted(candidates)],\n"
        "            }\n"
        "result = json.dumps(result_obj)\n"
    )
    try:
        eval_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        eval_data = parse_mcp_result(eval_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: py_eval error while probing func start: {e}")
        return None
    return _parse_py_eval_json_object(eval_data, debug=debug)


async def _read_covering_func_start_via_mcp(session, code_addr, debug=False):
    """Read the function start covering code_addr, or return None."""
    py_code = (
        "import idaapi, json\n"
        f"code_addr = {_parse_int_value(code_addr)}\n"
        "func = idaapi.get_func(code_addr)\n"
        "if func:\n"
        "    result = json.dumps({'status': 'resolved', 'func_start': hex(func.start_ea)})\n"
        "else:\n"
        "    result = json.dumps({'status': 'no_function'})\n"
    )
    try:
        eval_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        eval_data = parse_mcp_result(eval_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: py_eval error while verifying func start: {e}")
        return None

    parsed = _parse_py_eval_json_object(eval_data, debug=debug)
    if not parsed or parsed.get("status") != "resolved":
        return None
    try:
        return _parse_int_value(parsed.get("func_start"))
    except Exception:
        return None
```

- [ ] **Step 6: Add the public normalization helper**

Insert this code after `_read_covering_func_start_via_mcp`:

```python
async def _normalize_func_start_for_code_addr(session, code_addr, debug=False):
    """Resolve the function start for a code address, recovering undefined funcs."""
    try:
        code_addr_int = _parse_int_value(code_addr)
    except Exception:
        return None

    probe = await _probe_func_start_or_entry_candidate(
        session=session,
        code_addr=code_addr_int,
        debug=debug,
    )
    if not probe:
        return None

    status = probe.get("status")
    if status == "resolved":
        try:
            return _parse_int_value(probe.get("func_start"))
        except Exception:
            return None

    if status != "needs_define":
        if debug:
            print(
                "    Preprocess: undefined func recovery skipped: "
                f"{status or 'unknown'}"
            )
        return None

    try:
        entry = _parse_int_value(probe.get("entry"))
    except Exception:
        return None

    try:
        await session.call_tool(
            name="define_func",
            arguments={"items": {"addr": hex(entry)}},
        )
    except Exception as e:
        if debug:
            print(f"    Preprocess: define_func failed for {hex(entry)}: {e}")
        return None

    func_start = await _read_covering_func_start_via_mcp(
        session=session,
        code_addr=code_addr_int,
        debug=debug,
    )
    if func_start is None and debug:
        print(
            "    Preprocess: recovered function does not cover "
            f"{hex(code_addr_int)}"
        )
    return func_start


async def _normalize_func_starts_for_code_addrs(session, code_addrs, debug=False):
    """Normalize raw code addresses into a set of covering function starts."""
    func_starts = set()
    for code_addr in sorted(code_addrs):
        func_start = await _normalize_func_start_for_code_addr(
            session=session,
            code_addr=code_addr,
            debug=debug,
        )
        if func_start is not None:
            func_starts.add(func_start)
    return func_starts
```

- [ ] **Step 7: Run helper tests**

Run:

```bash
python -m unittest tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport -v
```

Expected: the helper tests from Step 1 PASS; existing collector tests may still PASS or fail later once collector expectations are updated.

## Task 2: Wire Collectors Through Normalization

**Files:**
- Modify: `ida_analyze_util.py:4494`
- Test: `tests/test_ida_analyze_util.py:1078`

- [ ] **Step 1: Add failing collector integration tests**

Append these tests inside `TestFuncXrefsSignatureSupport`:

```python
    async def test_collect_string_xrefs_normalizes_raw_xref_addresses(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(["0x180001050"])

        with patch.object(
            ida_analyze_util,
            "_normalize_func_starts_for_code_addrs",
            AsyncMock(return_value={0x180001000}),
        ) as mock_normalize:
            result = await ida_analyze_util._collect_xref_func_starts_for_string(
                session=session,
                xref_string="Networking",
                debug=True,
            )

        self.assertEqual({0x180001000}, result)
        mock_normalize.assert_awaited_once_with(
            session=session,
            code_addrs={0x180001050},
            debug=True,
        )
        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn("xref_addrs.add(xref.frm)", py_code)

    async def test_collect_ea_xrefs_normalizes_raw_xref_addresses(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(["0x180001070"])

        with patch.object(
            ida_analyze_util,
            "_normalize_func_starts_for_code_addrs",
            AsyncMock(return_value={0x180001000}),
        ) as mock_normalize:
            result = await ida_analyze_util._collect_xref_func_starts_for_ea(
                session=session,
                target_ea=0x180100000,
                debug=True,
            )

        self.assertEqual({0x180001000}, result)
        mock_normalize.assert_awaited_once_with(
            session=session,
            code_addrs={0x180001070},
            debug=True,
        )
        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn("xref_addrs.add(xref.frm)", py_code)

    async def test_collect_signature_xrefs_normalizes_match_addresses(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _FakeCallToolResult(
            [{"matches": ["0x180001090"], "n": 1}]
        )

        with patch.object(
            ida_analyze_util,
            "_normalize_func_starts_for_code_addrs",
            AsyncMock(return_value={0x180001000}),
        ) as mock_normalize:
            result = await ida_analyze_util._collect_xref_func_starts_for_signature(
                session=session,
                xref_signature="48 89 5C 24 08",
                debug=True,
            )

        self.assertEqual({0x180001000}, result)
        mock_normalize.assert_awaited_once_with(
            session=session,
            code_addrs={0x180001090},
            debug=True,
        )
        session.call_tool.assert_awaited_once()
```

- [ ] **Step 2: Run collector tests to verify they fail**

Run:

```bash
python -m unittest tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport -v
```

Expected: new collector tests FAIL because collectors still return existing `get_func(...)` starts directly and do not call `_normalize_func_starts_for_code_addrs`.

- [ ] **Step 3: Update string xref collector**

In `_collect_xref_func_starts_for_string`, replace the `py_code` construction and final return with:

```python
    py_code = (
        "import idautils, json\n"
        f"search_str = {json.dumps(search_str)}\n"
        "xref_addrs = set()\n"
        "for s in idautils.Strings():\n"
        "    current_str = str(s)\n"
        f"    if {match_expr}:\n"
        "        for xref in idautils.XrefsTo(s.ea, 0):\n"
        "            xref_addrs.add(xref.frm)\n"
        "result = json.dumps([hex(ea) for ea in sorted(xref_addrs)])\n"
    )
```

Then replace the final line:

```python
    return _parse_func_start_set_from_py_eval(eval_data, debug=debug)
```

with:

```python
    code_addrs = _parse_int_set_from_py_eval(eval_data, debug=debug)
    if code_addrs is None:
        return None
    return await _normalize_func_starts_for_code_addrs(
        session=session,
        code_addrs=code_addrs,
        debug=debug,
    )
```

- [ ] **Step 4: Update direct-address xref collector**

In `_collect_xref_func_starts_for_ea`, replace the `py_code` construction and final return with:

```python
    py_code = (
        "import idautils, json\n"
        f"target_ea = {target_ea_int}\n"
        "xref_addrs = set()\n"
        "for xref in idautils.XrefsTo(target_ea, 0):\n"
        "    xref_addrs.add(xref.frm)\n"
        "result = json.dumps([hex(ea) for ea in sorted(xref_addrs)])\n"
    )
```

Then replace the final line:

```python
    return _parse_func_start_set_from_py_eval(eval_data, debug=debug)
```

with:

```python
    code_addrs = _parse_int_set_from_py_eval(eval_data, debug=debug)
    if code_addrs is None:
        return None
    return await _normalize_func_starts_for_code_addrs(
        session=session,
        code_addrs=code_addrs,
        debug=debug,
    )
```

- [ ] **Step 5: Update signature xref collector**

In `_collect_xref_func_starts_for_signature`, after:

```python
    if not match_addrs:
        return set()
```

delete the existing `py_eval`/`parse_mcp_result` block entirely and replace it with:

```python
    code_addrs = set(match_addrs)
    return await _normalize_func_starts_for_code_addrs(
        session=session,
        code_addrs=code_addrs,
        debug=debug,
    )
```

- [ ] **Step 6: Update existing collector expectation tests**

In the existing tests `test_collect_xref_func_starts_for_string_uses_substring_by_default` and `test_collect_xref_func_starts_for_string_supports_fullmatch_prefix`, wrap the collector call with a patched normalizer:

```python
        with patch.object(
            ida_analyze_util,
            "_normalize_func_starts_for_code_addrs",
            AsyncMock(return_value={0x180001000}),
        ):
            result = await ida_analyze_util._collect_xref_func_starts_for_string(
                session=session,
                xref_string="_projectile",
                debug=True,
            )
```

Use the same patch pattern in the `FULLMATCH` test. Keep the existing assertions for `search_str`, substring matching, and full-match matching.

- [ ] **Step 7: Run collector tests**

Run:

```bash
python -m unittest tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport -v
```

Expected: PASS for all tests in `TestFuncXrefsSignatureSupport`.

## Task 3: Run Targeted Regression

**Files:**
- Modify: none
- Test: `tests/test_ida_analyze_util.py`

- [ ] **Step 1: Run focused utility tests**

Run:

```bash
python -m unittest tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport -v
```

Expected: PASS.

- [ ] **Step 2: Run preprocessor-script forwarding tests**

Run:

```bash
python -m unittest tests.test_ida_preprocessor_scripts -v
```

Expected: PASS. These tests verify that existing `FUNC_XREFS` script contracts still forward correctly.

- [ ] **Step 3: Optional manual IDA validation**

Only run this when an IDA MCP environment and the target Linux `libclient.so` are available:

```bash
python ida_analyze_bin.py -gamever=14141b -modules=client -platform=linux -debug
```

Expected: `find-CSteamworksGameStats_OnReceivedSessionID` no longer reports `empty candidate set for string xref: Steamworks Stats: %s Received %s session id: %llu` when a unique `lea rax, loc_12B0AA0` entry reference exists from inside a valid function.

## Self-Review Checklist

- Spec coverage:
  - Common helper covers string, direct-address, and signature xref collectors.
  - `0x200` backtrack limit is represented by `UNDEFINED_FUNC_RECOVERY_BACKTRACK_LIMIT`.
  - `call`/`jmp`/`lea` filter is tested through generated `py_eval` source.
  - Referencing instruction must be inside an existing valid IDA function via `ref_func = idaapi.get_func(xref.frm)`.
  - Multiple entries and existing-function collisions skip `define_func`.
- Placeholder scan:
  - No `TBD`, `TODO`, or "fill in later" markers are intentionally present.
- Type consistency:
  - New helper names use `_normalize_func_start_for_code_addr` and `_normalize_func_starts_for_code_addrs` consistently.
  - Collector helpers continue returning `set[int]` or `None`.

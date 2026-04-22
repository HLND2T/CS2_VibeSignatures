# ProcessMovement Float Xrefs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `xref_floats` and `exclude_floats` as post-intersection `func_xrefs` filters so `CCSPlayer_MovementServices_ProcessMovement` can resolve to a unique candidate.

**Architecture:** Extend the existing `func_xrefs` normalization and fallback path in `ida_analyze_util.py`. Keep float filters as post-processing on `common_funcs`, implemented through one focused MCP `py_eval` helper that scans readonly scalar `xmm` memory constants.

**Tech Stack:** Python, `unittest`, `AsyncMock`, IDA `py_eval`, `ida_bytes`, `ida_funcs`, `ida_segment`, `idautils`, `idc`.

---

## File Structure

- Modify `ida_analyze_util.py:5` to import `math` for finite float validation.
- Modify `ida_analyze_util.py:5434` to add `_normalize_float_xref_values()` near existing scalar parsers.
- Add `_filter_func_addrs_by_float_xrefs_via_mcp()` near `_filter_func_addrs_by_signature_via_mcp()` and before `preprocess_func_xrefs_via_mcp()`.
- Modify `ida_analyze_util.py:6689` to accept, apply, and debug-log `xref_floats` / `exclude_floats`.
- Modify `ida_analyze_util.py:7133` to forward normalized float filters from `_try_preprocess_func_without_llm()`.
- Modify `ida_analyze_util.py:7217` documentation and `func_xrefs` schema normalization.
- Modify `tests/test_ida_analyze_util.py:2380` to add helper and integration tests.
- Modify `tests/test_ida_analyze_util.py:2996` to assert schema normalization forwards float filters and rejects invalid values.
- Modify `tests/test_ida_preprocessor_scripts.py:2256` to assert the `ProcessMovement` script forwards `xref_floats` and `exclude_floats`.

---

### Task 1: Extend Schema Contract

**Files:**
- Modify: `tests/test_ida_analyze_util.py:2996`
- Modify: `tests/test_ida_preprocessor_scripts.py:2256`
- Modify: `ida_analyze_util.py:5`
- Modify: `ida_analyze_util.py:5434`
- Modify: `ida_analyze_util.py:7217`
- Modify: `ida_analyze_util.py:7133`

- [ ] **Step 1: Write failing normalization and script tests**

In `tests/test_ida_analyze_util.py`, update the existing `func_xrefs` normalization test that currently begins near `tests/test_ida_analyze_util.py:2996`.

Add the new fields to the input spec:

```python
                        "xref_floats": ["64.0", "0.5"],
                        "exclude_floats": ["128.0"],
```

The updated `func_xrefs` input block should contain:

```python
                    {
                        "func_name": "LoggingChannel_Init",
                        "xref_strings": ["Networking"],
                        "xref_gvs": ["g_NetworkingState"],
                        "xref_signatures": ["C7 44 24 40 64 FF FF FF"],
                        "xref_funcs": ["LoggingChannel_Shutdown"],
                        "xref_floats": ["64.0", "0.5"],
                        "exclude_funcs": ["LoggingChannel_Rebuild"],
                        "exclude_strings": ["FULLMATCH:Networking"],
                        "exclude_gvs": ["g_ExcludeNetworkingState"],
                        "exclude_signatures": ["DE AD BE EF"],
                        "exclude_floats": ["128.0"],
                    }
```

Add these assertions after the existing `exclude_signatures` assertion:

```python
        self.assertEqual(
            ["64.0", "0.5"],
            mock_func_xrefs.call_args.kwargs["xref_floats"],
        )
        self.assertEqual(
            ["128.0"],
            mock_func_xrefs.call_args.kwargs["exclude_floats"],
        )
```

Add this new test after `test_preprocess_common_skill_rejects_empty_positive_xref_sources`:

```python
    async def test_preprocess_common_skill_rejects_invalid_float_xref_values(
        self,
    ) -> None:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/LoggingChannel_Init.windows.yaml"],
            old_yaml_map={},
            new_binary_dir="/tmp",
            platform="windows",
            image_base=0x180000000,
            func_names=["LoggingChannel_Init"],
            func_xrefs=[
                {
                    "func_name": "LoggingChannel_Init",
                    "xref_strings": ["Networking"],
                    "xref_gvs": [],
                    "xref_signatures": [],
                    "xref_funcs": [],
                    "xref_floats": ["not-a-float"],
                    "exclude_funcs": [],
                    "exclude_strings": [],
                    "exclude_gvs": [],
                    "exclude_signatures": [],
                    "exclude_floats": [],
                }
            ],
            generate_yaml_desired_fields=[
                (
                    "LoggingChannel_Init",
                    ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
                )
            ],
            debug=True,
        )

        self.assertFalse(result)
```

In `tests/test_ida_preprocessor_scripts.py`, update `expected_func_xrefs` in `TestFindCcsPlayerMovementServicesProcessMovement.test_script_forwards_gv_backed_func_xrefs` so it contains:

```python
                "xref_floats": ["64.0", "0.5"],
```

immediately after `"xref_funcs": [],`, and:

```python
                "exclude_floats": [],
```

immediately after `"exclude_signatures": [],`.

- [ ] **Step 2: Run targeted tests and confirm contract failure**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport \
  tests.test_ida_preprocessor_scripts.TestFindCcsPlayerMovementServicesProcessMovement
```

Expected result:

- `test_preprocess_common_skill_rejects_unknown_func_xrefs_key` behavior remains unchanged.
- The updated forwarding tests fail because `xref_floats` and `exclude_floats` are still unknown or not forwarded.

- [ ] **Step 3: Add float field validation and forwarding**

In `ida_analyze_util.py`, add the import:

```python
import math
```

near the existing imports:

```python
import json
import math
import os
```

Add this helper after `_parse_int_value()`:

```python
def _normalize_float_xref_values(field_name, field_values, func_name, debug=False):
    """Validate and strip func_xrefs float filter values."""
    normalized_values = []
    for item in field_values:
        raw = item.strip()
        try:
            parsed_value = float(raw)
        except (TypeError, ValueError):
            if debug:
                print(
                    f"    Preprocess: invalid {field_name} float value for "
                    f"{func_name}: {item}"
                )
            return None
        if not math.isfinite(parsed_value):
            if debug:
                print(
                    f"    Preprocess: non-finite {field_name} float value for "
                    f"{func_name}: {item}"
                )
            return None
        normalized_values.append(raw)
    return normalized_values
```

In `preprocess_common_skill()`, update `func_xrefs_allowed_keys`:

```python
        "xref_floats",
        "exclude_floats",
```

Update `func_xrefs_list_keys`:

```python
        "xref_floats",
        "exclude_floats",
```

After the existing string/list validation inside the loop over `func_xrefs_list_keys`, add:

```python
            if field_name in {"xref_floats", "exclude_floats"}:
                field_list = _normalize_float_xref_values(
                    field_name,
                    field_list,
                    func_name,
                    debug=debug,
                )
                if field_list is None:
                    return False
```

Update the `preprocess_common_skill()` docstring section for `func_xrefs` so it mentions:

```python
      ``xref_floats`` and ``exclude_floats`` are optional post-intersection
      scalar readonly float/double filters; they do not count as positive
      candidate sources.
```

In `_try_preprocess_func_without_llm()`, add these keyword arguments to the `preprocess_func_xrefs_via_mcp()` call:

```python
            xref_floats=xref_spec["xref_floats"],
            exclude_floats=xref_spec["exclude_floats"],
```

- [ ] **Step 4: Run contract tests and confirm pass**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport \
  tests.test_ida_preprocessor_scripts.TestFindCcsPlayerMovementServicesProcessMovement
```

Expected result:

- All tests in the two named classes pass.
- The `ProcessMovement` script forwarding test confirms `xref_floats=["64.0", "0.5"]` and `exclude_floats=[]`.

- [ ] **Step 5: Commit schema checkpoint**

Run only when committing is authorized:

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py tests/test_ida_preprocessor_scripts.py
git commit -m "feat(preprocess): 接入浮点 xref 字段契约"
```

---

### Task 2: Add Float Filter Helper

**Files:**
- Modify: `tests/test_ida_analyze_util.py:2380`
- Modify: `ida_analyze_util.py:6530`

- [ ] **Step 1: Write failing helper tests**

Add these tests near the existing `preprocess_func_xrefs` tests in `tests/test_ida_analyze_util.py`:

```python
    async def test_filter_func_addrs_by_float_xrefs_keeps_xref_matches_and_excludes_hits(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "0x180100000": {
                    "constants": [
                        {
                            "inst_ea": "0x180100010",
                            "const_ea": "0x181000000",
                            "kind": "float",
                            "value": 64.0,
                        }
                    ],
                    "xref_hit": True,
                    "exclude_hit": False,
                },
                "0x180200000": {
                    "constants": [
                        {
                            "inst_ea": "0x180200010",
                            "const_ea": "0x181000004",
                            "kind": "float",
                            "value": 1.0,
                        }
                    ],
                    "xref_hit": False,
                    "exclude_hit": False,
                },
                "0x180300000": {
                    "constants": [
                        {
                            "inst_ea": "0x180300010",
                            "const_ea": "0x181000008",
                            "kind": "float",
                            "value": 0.5,
                        }
                    ],
                    "xref_hit": True,
                    "exclude_hit": True,
                },
            }
        )

        result = await ida_analyze_util._filter_func_addrs_by_float_xrefs_via_mcp(
            session=session,
            func_addrs={0x180100000, 0x180200000, 0x180300000},
            xref_floats=["64.0", "0.5"],
            exclude_floats=["0.5"],
            debug=True,
        )

        self.assertEqual({0x180100000}, result)
        session.call_tool.assert_awaited_once()
        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn('struct.unpack("<f"', py_code)
        self.assertIn('struct.unpack("<d"', py_code)
        self.assertIn('seg_name == ".rdata"', py_code)
        self.assertIn('seg_name.startswith(".rodata")', py_code)
        self.assertIn('"mulss"', py_code)
        self.assertIn('"mulsd"', py_code)

    async def test_filter_func_addrs_by_float_xrefs_fails_closed_on_invalid_payload(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(["not-a-dict"])

        result = await ida_analyze_util._filter_func_addrs_by_float_xrefs_via_mcp(
            session=session,
            func_addrs={0x180100000},
            xref_floats=["64.0"],
            exclude_floats=[],
            debug=True,
        )

        self.assertIsNone(result)
        session.call_tool.assert_awaited_once()
```

- [ ] **Step 2: Run helper tests and confirm failure**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_filter_func_addrs_by_float_xrefs_keeps_xref_matches_and_excludes_hits \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_filter_func_addrs_by_float_xrefs_fails_closed_on_invalid_payload
```

Expected result:

- Both tests fail with `AttributeError` because `_filter_func_addrs_by_float_xrefs_via_mcp` does not exist.

- [ ] **Step 3: Implement helper**

Add this function before `preprocess_func_xrefs_via_mcp()` in `ida_analyze_util.py`:

```python
async def _filter_func_addrs_by_float_xrefs_via_mcp(
    session,
    func_addrs,
    xref_floats,
    exclude_floats,
    debug=False,
):
    """Filter function addresses by readonly scalar float/double xrefs."""
    func_addr_set = set(func_addrs or [])
    if not func_addr_set:
        return set()
    if not xref_floats and not exclude_floats:
        return func_addr_set

    try:
        xref_values = [float(value) for value in (xref_floats or [])]
        exclude_values = [float(value) for value in (exclude_floats or [])]
    except (TypeError, ValueError):
        if debug:
            print("    Preprocess: invalid float xref filter values")
        return None

    py_code = (
        "import ida_bytes, ida_funcs, ida_segment, idautils, idc, json, struct\n"
        f"func_addrs = {[int(addr) for addr in sorted(func_addr_set)]}\n"
        f"xref_values = {xref_values!r}\n"
        f"exclude_values = {exclude_values!r}\n"
        "FLOAT_EPSILON = 1e-6\n"
        "DOUBLE_EPSILON = 1e-12\n"
        "SINGLE_MNEMS = {\n"
        "    \"addss\", \"subss\", \"mulss\", \"divss\", \"minss\", \"maxss\",\n"
        "    \"sqrtss\", \"movss\", \"comiss\", \"ucomiss\",\n"
        "}\n"
        "DOUBLE_MNEMS = {\n"
        "    \"addsd\", \"subsd\", \"mulsd\", \"divsd\", \"minsd\", \"maxsd\",\n"
        "    \"sqrtsd\", \"movsd\", \"comisd\", \"ucomisd\",\n"
        "}\n"
        "MEM_OP_TYPES = {idc.o_mem, idc.o_displ, idc.o_phrase}\n"
        "\n"
        "def _scalar_kind(mnem):\n"
        "    lower = (mnem or \"\").lower()\n"
        "    if lower in SINGLE_MNEMS and lower.endswith(\"ss\"):\n"
        "        return \"float\"\n"
        "    if lower in DOUBLE_MNEMS and lower.endswith(\"sd\"):\n"
        "        return \"double\"\n"
        "    return None\n"
        "\n"
        "def _has_xmm_operand(ea):\n"
        "    for op_idx in range(8):\n"
        "        text = (idc.print_operand(ea, op_idx) or \"\").lower()\n"
        "        if \"xmm\" in text:\n"
        "            return True\n"
        "    return False\n"
        "\n"
        "def _is_readonly_float_segment(ea):\n"
        "    seg = ida_segment.getseg(ea)\n"
        "    if not seg:\n"
        "        return False\n"
        "    seg_name = ida_segment.get_segm_name(seg) or \"\"\n"
        "    return seg_name == \".rdata\" or seg_name.startswith(\".rodata\")\n"
        "\n"
        "def _matches(value, expected_values, kind):\n"
        "    epsilon = FLOAT_EPSILON if kind == \"float\" else DOUBLE_EPSILON\n"
        "    for expected in expected_values:\n"
        "        if abs(value - expected) < epsilon:\n"
        "            return True\n"
        "    return False\n"
        "\n"
        "def _read_scalar_value(target_ea, kind):\n"
        "    if kind == \"float\":\n"
        "        raw = ida_bytes.get_bytes(target_ea, 4)\n"
        "        if not raw or len(raw) != 4:\n"
        "            return None\n"
        "        return struct.unpack(\"<f\", raw)[0]\n"
        "    raw = ida_bytes.get_bytes(target_ea, 8)\n"
        "    if not raw or len(raw) != 8:\n"
        "        return None\n"
        "    return struct.unpack(\"<d\", raw)[0]\n"
        "\n"
        "out = {}\n"
        "for func_ea in func_addrs:\n"
        "    func = ida_funcs.get_func(func_ea)\n"
        "    constants = []\n"
        "    xref_hit = False\n"
        "    exclude_hit = False\n"
        "    if func:\n"
        "        for insn_ea in idautils.FuncItems(func.start_ea):\n"
        "            mnem = idc.print_insn_mnem(insn_ea)\n"
        "            kind = _scalar_kind(mnem)\n"
        "            if not kind or not _has_xmm_operand(insn_ea):\n"
        "                continue\n"
        "            for op_idx in range(8):\n"
        "                if idc.get_operand_type(insn_ea, op_idx) not in MEM_OP_TYPES:\n"
        "                    continue\n"
        "                target_ea = idc.get_operand_value(insn_ea, op_idx)\n"
        "                if not _is_readonly_float_segment(target_ea):\n"
        "                    continue\n"
        "                value = _read_scalar_value(target_ea, kind)\n"
        "                if value is None:\n"
        "                    continue\n"
        "                constants.append({\n"
        "                    \"inst_ea\": hex(insn_ea),\n"
        "                    \"const_ea\": hex(target_ea),\n"
        "                    \"kind\": kind,\n"
        "                    \"value\": value,\n"
        "                })\n"
        "                if _matches(value, xref_values, kind):\n"
        "                    xref_hit = True\n"
        "                if _matches(value, exclude_values, kind):\n"
        "                    exclude_hit = True\n"
        "    out[hex(func_ea)] = {\n"
        "        \"constants\": constants,\n"
        "        \"xref_hit\": xref_hit,\n"
        "        \"exclude_hit\": exclude_hit,\n"
        "    }\n"
        "result = json.dumps(out)\n"
    )

    try:
        eval_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        eval_data = parse_mcp_result(eval_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: py_eval error for float xref filter: {e}")
        return None

    parsed = _parse_py_eval_json_object(eval_data, debug=debug)
    if not isinstance(parsed, dict):
        return None

    filtered_funcs = set()
    missing_xref_funcs = set()
    excluded_funcs = set()
    for func_addr in sorted(func_addr_set):
        entry = parsed.get(hex(func_addr))
        if not isinstance(entry, dict):
            return None
        if debug:
            constants = entry.get("constants", [])
            print(
                "    Preprocess: float constants for "
                f"{hex(func_addr)} = {constants}"
            )
        if exclude_values and entry.get("exclude_hit"):
            excluded_funcs.add(func_addr)
            continue
        if xref_values and not entry.get("xref_hit"):
            missing_xref_funcs.add(func_addr)
            continue
        filtered_funcs.add(func_addr)

    if debug and missing_xref_funcs:
        print(
            "    Preprocess: float xref missing funcs = "
            f"{[hex(a) for a in sorted(missing_xref_funcs)]}"
        )
    if debug and excluded_funcs:
        print(
            "    Preprocess: float exclude funcs = "
            f"{[hex(a) for a in sorted(excluded_funcs)]}"
        )

    return filtered_funcs
```

- [ ] **Step 4: Run helper tests and confirm pass**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_filter_func_addrs_by_float_xrefs_keeps_xref_matches_and_excludes_hits \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_filter_func_addrs_by_float_xrefs_fails_closed_on_invalid_payload
```

Expected result:

- Both helper tests pass.
- The generated `py_eval` string contains scalar single and scalar double handling.

- [ ] **Step 5: Commit helper checkpoint**

Run only when committing is authorized:

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "feat(preprocess): 添加浮点 xref 过滤辅助函数"
```

---

### Task 3: Integrate Float Filters Into Func Xrefs

**Files:**
- Modify: `tests/test_ida_analyze_util.py:2380`
- Modify: `ida_analyze_util.py:6689`

- [ ] **Step 1: Write failing integration tests**

Add these tests near the existing `preprocess_func_xrefs` tests:

```python
    async def test_preprocess_func_xrefs_applies_float_filters_after_excludes(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180100000, 0x180200000}),
        ) as mock_collect_string, patch.object(
            ida_analyze_util,
            "_filter_func_addrs_by_float_xrefs_via_mcp",
            AsyncMock(return_value={0x180200000}),
        ) as mock_float_filter, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=["Networking"],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                xref_floats=["64.0"],
                exclude_floats=[],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertEqual("0x180200000", result["func_va"])
        mock_collect_string.assert_awaited_once_with(
            session="session",
            xref_string="Networking",
            debug=True,
        )
        mock_float_filter.assert_awaited_once_with(
            session="session",
            func_addrs={0x180100000, 0x180200000},
            xref_floats=["64.0"],
            exclude_floats=[],
            debug=True,
        )
        mock_gen_sig.assert_awaited_once()

    async def test_preprocess_func_xrefs_fails_closed_on_float_filter_failure(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180100000, 0x180200000}),
        ), patch.object(
            ida_analyze_util,
            "_filter_func_addrs_by_float_xrefs_via_mcp",
            AsyncMock(return_value=None),
        ) as mock_float_filter, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(return_value=None),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=["Networking"],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                xref_floats=["64.0"],
                exclude_floats=[],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertIsNone(result)
        mock_float_filter.assert_awaited_once()
        mock_gen_sig.assert_not_called()
```

- [ ] **Step 2: Run integration tests and confirm failure**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_func_xrefs_applies_float_filters_after_excludes \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_func_xrefs_fails_closed_on_float_filter_failure
```

Expected result:

- Tests fail because `preprocess_func_xrefs_via_mcp()` does not accept `xref_floats` / `exclude_floats` or does not call the helper.

- [ ] **Step 3: Add float filter parameters and call helper**

Update `preprocess_func_xrefs_via_mcp()` signature:

```python
    exclude_signatures,
    xref_floats=None,
    exclude_floats=None,
    new_binary_dir=None,
```

At the top of the function, after the docstring and before `has_explicit_positive_source`, add:

```python
    xref_floats = xref_floats or []
    exclude_floats = exclude_floats or []
```

After the existing `common_funcs after excludes` debug block and before the `len(common_funcs) != 1` check, add:

```python
    if xref_floats or exclude_floats:
        if debug:
            print(
                "    Preprocess: common_funcs before float filters = "
                f"{[hex(a) for a in sorted(common_funcs)]}"
            )
        filtered_funcs = await _filter_func_addrs_by_float_xrefs_via_mcp(
            session=session,
            func_addrs=common_funcs,
            xref_floats=xref_floats,
            exclude_floats=exclude_floats,
            debug=debug,
        )
        if filtered_funcs is None:
            if debug:
                print("    Preprocess: failed to apply float xref filters")
            return None
        common_funcs = filtered_funcs
        if debug:
            print(
                "    Preprocess: common_funcs after float filters = "
                f"{[hex(a) for a in sorted(common_funcs)]}"
            )
```

- [ ] **Step 4: Run integration tests and confirm pass**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_func_xrefs_applies_float_filters_after_excludes \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_func_xrefs_fails_closed_on_float_filter_failure
```

Expected result:

- Both integration tests pass.
- The helper receives `func_addrs` after normal xref intersection and existing excludes.

- [ ] **Step 5: Commit integration checkpoint**

Run only when committing is authorized:

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "feat(preprocess): 应用浮点 xref 候选过滤"
```

---

### Task 4: Final Targeted Verification

**Files:**
- Verify: `ida_analyze_util.py`
- Verify: `ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement.py`
- Verify: `tests/test_ida_analyze_util.py`
- Verify: `tests/test_ida_preprocessor_scripts.py`

- [ ] **Step 1: Run focused unittest classes**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport \
  tests.test_ida_preprocessor_scripts.TestFindCcsPlayerMovementServicesProcessMovement
```

Expected result:

- All tests in these classes pass.
- Existing `func_xrefs` behavior remains compatible because `xref_floats` and `exclude_floats` default to empty lists.

- [ ] **Step 2: Run broader affected test files**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util \
  tests.test_ida_preprocessor_scripts
```

Expected result:

- Both test modules pass.
- No unrelated preprocessor script test regresses because all float fields are optional.

- [ ] **Step 3: Inspect for placeholder text in plan and spec**

Run:

```bash
python - <<'PY'
from pathlib import Path

paths = [
    Path("docs/superpowers/specs/2026-04-22-processmovement-float-xrefs-design.md"),
    Path("docs/superpowers/plans/2026-04-22-processmovement-float-xrefs.md"),
]
needles = ["TO" "DO", "TB" "D", "<place" "holder>", "待" "补", "未" "定"]

for path in paths:
    text = path.read_text(encoding="utf-8")
    for needle in needles:
        if needle in text:
            print(f"{path}: found {needle}")
            raise SystemExit(1)
print("no placeholders found")
PY
```

Expected result:

- Prints `no placeholders found`.

- [ ] **Step 4: Review final diff**

Run:

```bash
git diff -- \
  ida_analyze_util.py \
  ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement.py \
  tests/test_ida_analyze_util.py \
  tests/test_ida_preprocessor_scripts.py \
  docs/superpowers/specs/2026-04-22-processmovement-float-xrefs-design.md \
  docs/superpowers/plans/2026-04-22-processmovement-float-xrefs.md
```

Expected result:

- `ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement.py` still declares `xref_floats=["64.0", "0.5"]` and `exclude_floats=[]`.
- `ida_analyze_util.py` contains no behavior change for callers that omit float filters.
- Tests cover schema forwarding, invalid float config, helper semantics, integration behavior, and script forwarding.

- [ ] **Step 5: Commit final checkpoint**

Run only when committing is authorized:

```bash
git add \
  ida_analyze_util.py \
  ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement.py \
  tests/test_ida_analyze_util.py \
  tests/test_ida_preprocessor_scripts.py \
  docs/superpowers/specs/2026-04-22-processmovement-float-xrefs-design.md \
  docs/superpowers/plans/2026-04-22-processmovement-float-xrefs.md
git commit -m "feat(preprocess): 支持 ProcessMovement 浮点 xref 过滤"
```

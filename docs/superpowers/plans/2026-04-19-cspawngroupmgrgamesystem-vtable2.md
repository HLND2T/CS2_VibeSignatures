# CSpawnGroupMgrGameSystem Vtable2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate `CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml` from the secondary vtable and bind `CSpawnGroupMgrGameSystem_DoesGameSystemReallocate` to that artifact.

**Architecture:** Add a reusable ordinal-vtable helper under `ida_preprocessor_scripts/` that locates a validated vtable address point by explicit Windows aliases or Linux `offset-to-top` filtering. Keep the existing primary-vtable path unchanged, and add artifact-stem path resolution so `vtable_name: CSpawnGroupMgrGameSystem_vtable2` reads `CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml` instead of appending another `_vtable`.

**Tech Stack:** Python 3, PyYAML, `unittest`, `AsyncMock`, IDA MCP `py_eval`, existing `ida_analyze_util.py` preprocess helpers.

**Repository Constraint:** Do not run broad tests, build commands, or `git commit` unless the user explicitly authorizes them.

---

## File Structure

- Create: `ida_preprocessor_scripts/_ordinal_vtable_common.py`
  - Owns ordinal vtable discovery and py_eval result normalization.
  - Does not write YAML files.
- Create: `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_vtable2.py`
  - Thin wrapper that calls the ordinal helper and writes `CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml`.
- Modify: `ida_analyze_util.py`
  - Adds vtable artifact-stem path helpers.
  - Updates shared vtable path consumers to understand names ending with `_vtable` or `_vtable<number>`.
  - Updates `func_vtable_relations` slot enrichment to read artifact-stem vtable YAML directly.
- Modify: `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py`
  - Changes the vtable relation from `CSpawnGroupMgrGameSystem` to `CSpawnGroupMgrGameSystem_vtable2`.
- Modify: `config.yaml`
  - Adds the new vtable2 preprocessing skill.
  - Makes `DoesGameSystemReallocate` depend on `CSpawnGroupMgrGameSystem_vtable2`.
  - Adds `CSpawnGroupMgrGameSystem_vtable2` as a vtable symbol.
- Modify: `tests/test_ida_analyze_util.py`
  - Covers artifact-stem path resolution and slot enrichment from `*_vtable2`.
- Modify: `tests/test_ida_preprocessor_scripts.py`
  - Covers the ordinal helper and both new/changed preprocessor scripts.

## Task 1: Add vtable artifact-stem path helpers

**Files:**
- Modify: `ida_analyze_util.py:405`
- Modify: `ida_analyze_util.py:2507`
- Modify: `ida_analyze_util.py:4860`
- Modify: `ida_analyze_util.py:6274`
- Modify: `ida_analyze_util.py:7560`
- Test: `tests/test_ida_analyze_util.py`

- [ ] **Step 1: Write failing tests for artifact-stem helpers and relation enrichment**

Add this test class after `TestVtableAliasSupport` in `tests/test_ida_analyze_util.py`:

```python
class TestVtableArtifactStemSupport(unittest.IsolatedAsyncioTestCase):
    def test_normalizes_plain_class_name_to_primary_vtable_artifact(self) -> None:
        self.assertEqual(
            "CSpawnGroupMgrGameSystem_vtable",
            ida_analyze_util._normalize_vtable_artifact_stem(
                "CSpawnGroupMgrGameSystem"
            ),
        )

    def test_preserves_primary_vtable_artifact_stem(self) -> None:
        self.assertEqual(
            "CSpawnGroupMgrGameSystem_vtable",
            ida_analyze_util._normalize_vtable_artifact_stem(
                "CSpawnGroupMgrGameSystem_vtable"
            ),
        )

    def test_preserves_numbered_vtable_artifact_stem(self) -> None:
        self.assertEqual(
            "CSpawnGroupMgrGameSystem_vtable2",
            ida_analyze_util._normalize_vtable_artifact_stem(
                "CSpawnGroupMgrGameSystem_vtable2"
            ),
        )

    def test_builds_vtable_yaml_path_without_double_suffix(self) -> None:
        self.assertEqual(
            "/tmp/bin/server/CSpawnGroupMgrGameSystem_vtable2.windows.yaml",
            ida_analyze_util._build_vtable_yaml_path(
                "/tmp/bin/server",
                "CSpawnGroupMgrGameSystem_vtable2",
                "windows",
            ),
        )

    async def test_func_vtable_relation_reads_numbered_vtable_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"
            module_dir.mkdir(parents=True, exist_ok=True)
            _write_yaml(
                module_dir / "CSpawnGroupMgrGameSystem_vtable2.windows.yaml",
                {
                    "vtable_class": "CSpawnGroupMgrGameSystem",
                    "vtable_symbol": "??_7CSpawnGroupMgrGameSystem@@6B@_0",
                    "vtable_va": "0x1819682b0",
                    "vtable_rva": "0x19682b0",
                    "vtable_size": "0x1f0",
                    "vtable_numvfunc": 62,
                    "vtable_entries": {
                        56: "0x1803a75c0",
                    },
                },
            )

            with patch.object(
                ida_analyze_util,
                "preprocess_func_sig_via_mcp",
                AsyncMock(
                    return_value={
                        "func_name": "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
                        "func_va": "0x1803a75c0",
                        "func_rva": "0x3a75c0",
                        "func_size": "0x10",
                        "func_sig": "48 8B ??",
                    }
                ),
            ), patch.object(
                ida_analyze_util,
                "preprocess_vtable_via_mcp",
                AsyncMock(return_value=None),
            ) as mock_preprocess_vtable, patch.object(
                ida_analyze_util,
                "write_func_yaml",
            ) as mock_write_func_yaml, patch.object(
                ida_analyze_util,
                "_rename_func_in_ida",
                AsyncMock(return_value=None),
            ):
                result = await ida_analyze_util.preprocess_common_skill(
                    session="session",
                    expected_outputs=[
                        str(
                            module_dir
                            / "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.windows.yaml"
                        )
                    ],
                    old_yaml_map={},
                    new_binary_dir=str(module_dir),
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[
                        "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate"
                    ],
                    func_vtable_relations=[
                        (
                            "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
                            "CSpawnGroupMgrGameSystem_vtable2",
                        )
                    ],
                    generate_yaml_desired_fields=[
                        (
                            "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
                            [
                                "func_name",
                                "vtable_name",
                                "vfunc_offset",
                                "vfunc_index",
                            ],
                        )
                    ],
                    debug=True,
                )

        self.assertTrue(result)
        mock_preprocess_vtable.assert_not_awaited()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(
            "CSpawnGroupMgrGameSystem_vtable2",
            written_payload["vtable_name"],
        )
        self.assertEqual(56, written_payload["vfunc_index"])
        self.assertEqual("0x1c0", written_payload["vfunc_offset"])
```

- [ ] **Step 2: Run the targeted failing tests**

Run only these tests if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_analyze_util.TestVtableArtifactStemSupport -v
```

Expected before implementation: failures for missing `_normalize_vtable_artifact_stem` and `_build_vtable_yaml_path`.

- [ ] **Step 3: Add artifact-stem helpers to `ida_analyze_util.py`**

Insert this code immediately after `_get_mangled_class_aliases(...)` in `ida_analyze_util.py`:

```python
_VTABLE_ARTIFACT_STEM_RE = re.compile(r"_vtable(?:\d+)?$")


def _is_vtable_artifact_stem(vtable_name):
    normalized = str(vtable_name or "").strip()
    return bool(normalized and _VTABLE_ARTIFACT_STEM_RE.search(normalized))


def _normalize_vtable_artifact_stem(vtable_name):
    normalized = str(vtable_name or "").strip()
    if not normalized:
        return ""
    if _is_vtable_artifact_stem(normalized):
        return normalized
    return f"{normalized}_vtable"


def _build_vtable_yaml_path(binary_dir, vtable_name, platform):
    return os.path.join(
        os.fspath(binary_dir),
        f"{_normalize_vtable_artifact_stem(vtable_name)}.{platform}.yaml",
    )
```

- [ ] **Step 4: Update `preprocess_func_sig_via_mcp(...)` vtable loading**

In the nested `_load_vtable_data(vtable_name)` function in `ida_analyze_util.py`, replace the path construction and missing-file generation block with:

```python
        vtable_yaml_path = _build_vtable_yaml_path(
            new_binary_dir,
            vtable_name,
            platform,
        )

        if not os.path.exists(vtable_yaml_path):
            if _is_vtable_artifact_stem(vtable_name):
                if debug:
                    print(
                        "    Preprocess: vtable artifact YAML not found: "
                        f"{os.path.basename(vtable_yaml_path)}"
                    )
                return None

            vtable_gen_data = await preprocess_vtable_via_mcp(
                session,
                vtable_name,
                image_base,
                platform,
                debug,
                _get_mangled_class_aliases(
                    normalized_mangled_class_names,
                    vtable_name,
                ),
            )
            if vtable_gen_data is None:
                if debug:
                    print(
                        "    Preprocess: vtable YAML not found and generation failed: "
                        f"{os.path.basename(vtable_yaml_path)}"
                    )
                return None
            write_vtable_yaml(vtable_yaml_path, vtable_gen_data)
            if debug:
                print(
                    "    Preprocess: generated vtable YAML: "
                    f"{os.path.basename(vtable_yaml_path)}"
                )
```

- [ ] **Step 5: Update `preprocess_index_based_vfunc_via_mcp(...)` vtable path resolution**

Replace the target vtable path block in `preprocess_index_based_vfunc_via_mcp(...)` with:

```python
    vtable_artifact_stem = _normalize_vtable_artifact_stem(inherit_vtable_class)
    try:
        vtable_path = _resolve_related_yaml_path(
            new_binary_dir,
            vtable_artifact_stem,
            platform,
        )
    except ValueError:
        if debug:
            print(
                "    Preprocess: invalid vtable artifact path: "
                f"{vtable_artifact_stem}"
            )
        return None
```

Also replace debug messages that currently print `f"{inherit_vtable_class}_vtable"` for the target vtable YAML with `vtable_artifact_stem`.

- [ ] **Step 6: Update direct xref vtable filtering path**

In the helper that builds `vtable_addr_set` for xref filtering, replace:

```python
        vtable_yaml_path = os.path.join(
            new_binary_dir, f"{vtable_class}_vtable.{platform}.yaml"
        )
```

with:

```python
        vtable_yaml_path = _build_vtable_yaml_path(
            new_binary_dir,
            vtable_class,
            platform,
        )
```

- [ ] **Step 7: Update `func_vtable_relations` slot enrichment**

In `preprocess_common_skill(...)`, replace the direct `preprocess_vtable_via_mcp(...)` call used for slot enrichment with this branch:

```python
            if _is_vtable_artifact_stem(vtable_class):
                if not new_binary_dir:
                    if debug:
                        print(
                            f"    Preprocess: new_binary_dir is required for "
                            f"artifact vtable {vtable_class}"
                        )
                    return False
                vtable_yaml_path = _build_vtable_yaml_path(
                    new_binary_dir,
                    vtable_class,
                    platform,
                )
                vtable_data = _read_yaml_file(vtable_yaml_path)
                if not isinstance(vtable_data, dict):
                    if debug:
                        print(
                            "    Preprocess: vtable artifact YAML missing or invalid: "
                            f"{os.path.basename(vtable_yaml_path)}"
                        )
                    return False
            else:
                vtable_data = await preprocess_vtable_via_mcp(
                    session=session,
                    class_name=vtable_class,
                    image_base=image_base,
                    platform=platform,
                    debug=debug,
                    symbol_aliases=_get_mangled_class_aliases(
                        normalized_mangled_class_names,
                        vtable_class,
                    ),
                )
                if vtable_data is None:
                    if debug:
                        print(
                            f"    Preprocess: failed to look up {vtable_class} "
                            f"vtable for {func_name}"
                        )
                    return False
```

- [ ] **Step 8: Run the targeted tests**

Run only these tests if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_analyze_util.TestVtableArtifactStemSupport -v
```

Expected after implementation: all tests in `TestVtableArtifactStemSupport` pass.

## Task 2: Add reusable ordinal vtable helper

**Files:**
- Create: `ida_preprocessor_scripts/_ordinal_vtable_common.py`
- Modify: `tests/test_ida_preprocessor_scripts.py`

- [ ] **Step 1: Add helper test scaffolding**

In `tests/test_ida_preprocessor_scripts.py`, add `import json` at the top with the existing imports.

Add this path constant after `REALLOCATING_FACTORY_DEALLOCATE_SCRIPT_PATH`:

```python
ORDINAL_VTABLE_COMMON_PATH = Path(
    "ida_preprocessor_scripts/_ordinal_vtable_common.py"
)
```

Add these fake MCP payload helpers after `_load_module(...)`:

```python
class _FakeTextContent:
    def __init__(self, text: str) -> None:
        self.text = text


class _FakeCallToolResult:
    def __init__(self, payload: dict[str, object]) -> None:
        self.content = [_FakeTextContent(json.dumps(payload))]


def _py_eval_payload(payload: object) -> _FakeCallToolResult:
    return _FakeCallToolResult(
        {
            "result": json.dumps(payload),
            "stdout": "",
            "stderr": "",
        }
    )
```

- [ ] **Step 2: Write failing ordinal helper tests**

Add this test class in `tests/test_ida_preprocessor_scripts.py` after the helper scaffolding:

```python
class TestOrdinalVtableCommon(unittest.IsolatedAsyncioTestCase):
    def test_build_ordinal_vtable_py_eval_embeds_constraints(self) -> None:
        module = _load_module(
            ORDINAL_VTABLE_COMMON_PATH,
            "ordinal_vtable_common",
        )

        py_code = module._build_ordinal_vtable_py_eval(
            class_name="CSpawnGroupMgrGameSystem",
            ordinal=0,
            symbol_aliases=["??_7CSpawnGroupMgrGameSystem@@6B@_0"],
            expected_offset_to_top=-8,
        )

        self.assertIn('"CSpawnGroupMgrGameSystem"', py_code)
        self.assertIn("??_7CSpawnGroupMgrGameSystem@@6B@_0", py_code)
        self.assertIn("ordinal = 0", py_code)
        self.assertIn("expected_offset_to_top = -8", py_code)

    async def test_preprocess_ordinal_vtable_normalizes_result(self) -> None:
        module = _load_module(
            ORDINAL_VTABLE_COMMON_PATH,
            "ordinal_vtable_common_preprocess",
        )
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "vtable_class": "CSpawnGroupMgrGameSystem",
                "vtable_symbol": "??_7CSpawnGroupMgrGameSystem@@6B@_0",
                "vtable_va": "0x1819682b0",
                "vtable_size": "0x10",
                "vtable_numvfunc": 2,
                "vtable_entries": {
                    "0": "0x18014c840",
                    "1": "0x18014c850",
                },
            }
        )

        result = await module.preprocess_ordinal_vtable_via_mcp(
            session=session,
            class_name="CSpawnGroupMgrGameSystem",
            ordinal=0,
            image_base=0x180000000,
            platform="windows",
            debug=True,
            symbol_aliases=["??_7CSpawnGroupMgrGameSystem@@6B@_0"],
            expected_offset_to_top=None,
        )

        self.assertEqual("CSpawnGroupMgrGameSystem", result["vtable_class"])
        self.assertEqual("0x19682b0", result["vtable_rva"])
        self.assertEqual(
            {
                0: "0x18014c840",
                1: "0x18014c850",
            },
            result["vtable_entries"],
        )
        session.call_tool.assert_awaited_once()

    async def test_preprocess_ordinal_vtable_returns_none_for_empty_result(self) -> None:
        module = _load_module(
            ORDINAL_VTABLE_COMMON_PATH,
            "ordinal_vtable_common_none",
        )
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(None)

        result = await module.preprocess_ordinal_vtable_via_mcp(
            session=session,
            class_name="CSpawnGroupMgrGameSystem",
            ordinal=0,
            image_base=0x180000000,
            platform="linux",
            debug=False,
            expected_offset_to_top=-8,
        )

        self.assertIsNone(result)
```

- [ ] **Step 3: Run the targeted failing tests**

Run only these tests if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_preprocessor_scripts.TestOrdinalVtableCommon -v
```

Expected before implementation: import failure for missing `ida_preprocessor_scripts/_ordinal_vtable_common.py`.

- [ ] **Step 4: Create `ida_preprocessor_scripts/_ordinal_vtable_common.py`**

Create the file with this content:

```python
#!/usr/bin/env python3
"""Shared helpers for locating ordinal vtable address points via IDA MCP."""

import json

from ida_analyze_util import parse_mcp_result


_ORDINAL_VTABLE_PY_EVAL_TEMPLATE = r'''
import ida_bytes, ida_name, idaapi, idautils, ida_segment, json

class_name = CLASS_NAME_PLACEHOLDER
candidate_symbols = CANDIDATE_SYMBOLS_PLACEHOLDER
ordinal = ORDINAL_PLACEHOLDER
expected_offset_to_top = EXPECTED_OFFSET_TO_TOP_PLACEHOLDER
ptr_size = 8 if idaapi.inf_is_64bit() else 4

candidates = []

def _read_ptr(ea):
    if ptr_size == 8:
        return ida_bytes.get_qword(ea)
    return ida_bytes.get_dword(ea)

def _to_signed_ptr(value):
    if ptr_size == 8:
        sign_bit = 1 << 63
        mask = 1 << 64
    else:
        sign_bit = 1 << 31
        mask = 1 << 32
    if value & sign_bit:
        return value - mask
    return value

def _read_vtable_entries(address_point):
    vtable_seg = ida_segment.getseg(address_point)
    entries = {}
    count = 0
    for i in range(1000):
        ea = address_point + i * ptr_size
        ptr_value = _read_ptr(ea)
        if ptr_value == 0 or ptr_value == 0xFFFFFFFFFFFFFFFF:
            break
        target_seg = ida_segment.getseg(ptr_value)
        if not target_seg:
            break
        if vtable_seg and vtable_seg.start_ea <= ptr_value < vtable_seg.end_ea:
            break
        if not (target_seg.perm & ida_segment.SEGPERM_EXEC):
            break
        func = idaapi.get_func(ptr_value)
        if func is not None:
            entries[count] = hex(ptr_value)
            count += 1
            continue
        flags = ida_bytes.get_full_flags(ptr_value)
        if ida_bytes.is_code(flags):
            entries[count] = hex(ptr_value)
            count += 1
            continue
        break
    return entries

def _append_candidate(symbol, address_point, source, offset_to_top=None):
    if address_point == idaapi.BADADDR:
        return False
    entries = _read_vtable_entries(address_point)
    if not entries:
        return False
    candidates.append({
        "vtable_class": class_name,
        "vtable_symbol": symbol,
        "vtable_va": hex(address_point),
        "vtable_size": hex(len(entries) * ptr_size),
        "vtable_numvfunc": len(entries),
        "vtable_entries": entries,
        "offset_to_top": offset_to_top,
        "source": source,
    })
    return True

def _try_direct_symbol(symbol_name):
    if not symbol_name:
        return False
    addr = ida_name.get_name_ea(idaapi.BADADDR, symbol_name)
    if addr == idaapi.BADADDR:
        return False
    if symbol_name.startswith("_ZTV"):
        return _append_candidate(
            symbol_name + " + 0x10",
            addr + 0x10,
            "alias",
            0,
        )
    return _append_candidate(symbol_name, addr, "alias")

alias_hit = False
for symbol_name in candidate_symbols:
    if _try_direct_symbol(symbol_name):
        alias_hit = True

if candidate_symbols and not alias_hit:
    result = json.dumps(None)
else:
    if not candidates:
        win_col_prefix = "??_R4" + class_name + "@@6B@"
        for col_addr, col_name in idautils.Names():
            if col_name == win_col_prefix or col_name.startswith(win_col_prefix + "_"):
                for ref in idautils.DataRefsTo(col_addr):
                    symbol = ida_name.get_name(ref + ptr_size)
                    if not symbol:
                        symbol = "vftable@" + hex(ref + ptr_size)
                    _append_candidate(symbol, ref + ptr_size, "windows-rtti")

    if not candidates:
        typeinfo_name = "_ZTI" + str(len(class_name)) + class_name
        typeinfo_addr = ida_name.get_name_ea(idaapi.BADADDR, typeinfo_name)
        if typeinfo_addr != idaapi.BADADDR:
            for ref in idautils.DataRefsTo(typeinfo_addr):
                offset_to_top = _to_signed_ptr(_read_ptr(ref - ptr_size))
                address_point = ref + ptr_size
                symbol = ida_name.get_name(address_point)
                if not symbol:
                    symbol = (
                        typeinfo_name
                        + " ref "
                        + hex(ref)
                        + " offset_to_top "
                        + str(offset_to_top)
                    )
                _append_candidate(
                    symbol,
                    address_point,
                    "linux-typeinfo",
                    offset_to_top,
                )

    filtered = candidates
    if expected_offset_to_top is not None:
        filtered = [
            candidate
            for candidate in filtered
            if candidate.get("offset_to_top") == expected_offset_to_top
        ]

    filtered = sorted(filtered, key=lambda candidate: int(candidate["vtable_va"], 16))
    if ordinal < 0 or ordinal >= len(filtered):
        result = json.dumps(None)
    else:
        selected = dict(filtered[ordinal])
        selected.pop("source", None)
        result = json.dumps(selected)
'''


def _build_ordinal_vtable_py_eval(
    *,
    class_name,
    ordinal,
    symbol_aliases=None,
    expected_offset_to_top=None,
):
    return (
        _ORDINAL_VTABLE_PY_EVAL_TEMPLATE
        .replace("CLASS_NAME_PLACEHOLDER", json.dumps(str(class_name)))
        .replace(
            "CANDIDATE_SYMBOLS_PLACEHOLDER",
            json.dumps(list(symbol_aliases or [])),
        )
        .replace("ORDINAL_PLACEHOLDER", str(int(ordinal)))
        .replace(
            "EXPECTED_OFFSET_TO_TOP_PLACEHOLDER",
            "None" if expected_offset_to_top is None else str(int(expected_offset_to_top)),
        )
    )


async def preprocess_ordinal_vtable_via_mcp(
    session,
    class_name,
    ordinal,
    image_base,
    platform,
    debug=False,
    symbol_aliases=None,
    expected_offset_to_top=None,
):
    _ = platform
    py_code = _build_ordinal_vtable_py_eval(
        class_name=class_name,
        ordinal=ordinal,
        symbol_aliases=symbol_aliases,
        expected_offset_to_top=expected_offset_to_top,
    )

    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        result_data = parse_mcp_result(result)
    except Exception as exc:
        if debug:
            print(
                f"    Preprocess ordinal vtable: py_eval error for "
                f"{class_name}[{ordinal}]: {exc}"
            )
        return None

    vtable_info = None
    if isinstance(result_data, dict):
        result_str = result_data.get("result", "")
        if result_str:
            try:
                vtable_info = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                vtable_info = None

    if not isinstance(vtable_info, dict):
        if debug:
            print(
                f"    Preprocess ordinal vtable: no result for "
                f"{class_name}[{ordinal}]"
            )
        return None

    try:
        vtable_va_int = int(vtable_info["vtable_va"], 16)
        raw_entries = vtable_info.get("vtable_entries", {})
        entries = {int(index): value for index, value in raw_entries.items()}
    except (KeyError, TypeError, ValueError):
        if debug:
            print(
                f"    Preprocess ordinal vtable: invalid result for "
                f"{class_name}[{ordinal}]"
            )
        return None

    return {
        "vtable_class": vtable_info["vtable_class"],
        "vtable_symbol": vtable_info["vtable_symbol"],
        "vtable_va": vtable_info["vtable_va"],
        "vtable_rva": hex(vtable_va_int - image_base),
        "vtable_size": vtable_info["vtable_size"],
        "vtable_numvfunc": vtable_info["vtable_numvfunc"],
        "vtable_entries": entries,
    }
```

- [ ] **Step 5: Run the targeted tests**

Run only these tests if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_preprocessor_scripts.TestOrdinalVtableCommon -v
```

Expected after implementation: all tests in `TestOrdinalVtableCommon` pass.

## Task 3: Add `find-CSpawnGroupMgrGameSystem_vtable2` script

**Files:**
- Create: `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_vtable2.py`
- Modify: `tests/test_ida_preprocessor_scripts.py`

- [ ] **Step 1: Add script path constant**

Add this constant near the other script path constants in `tests/test_ida_preprocessor_scripts.py`:

```python
CSPAWNGROUP_VTABLE2_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_vtable2.py"
)
```

- [ ] **Step 2: Write failing wrapper tests**

Add this test class in `tests/test_ida_preprocessor_scripts.py`:

```python
class TestFindCSpawnGroupMgrGameSystemVtable2(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_uses_windows_secondary_vtable_alias(self) -> None:
        module = _load_module(
            CSPAWNGROUP_VTABLE2_SCRIPT_PATH,
            "find_CSpawnGroupMgrGameSystem_vtable2_windows",
        )
        fake_vtable_data = {
            "vtable_class": "CSpawnGroupMgrGameSystem",
            "vtable_symbol": "??_7CSpawnGroupMgrGameSystem@@6B@_0",
            "vtable_va": "0x1819682b0",
            "vtable_rva": "0x19682b0",
            "vtable_size": "0x10",
            "vtable_numvfunc": 2,
            "vtable_entries": {
                0: "0x18014c840",
                1: "0x18014c850",
            },
        }
        mock_preprocess = AsyncMock(return_value=fake_vtable_data)

        with patch.object(
            module,
            "preprocess_ordinal_vtable_via_mcp",
            mock_preprocess,
        ), patch.object(module, "write_vtable_yaml") as mock_write_vtable_yaml:
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=[
                    "/tmp/CSpawnGroupMgrGameSystem_vtable2.windows.yaml"
                ],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess.assert_awaited_once_with(
            session="session",
            class_name="CSpawnGroupMgrGameSystem",
            ordinal=0,
            image_base=0x180000000,
            platform="windows",
            debug=True,
            symbol_aliases=["??_7CSpawnGroupMgrGameSystem@@6B@_0"],
            expected_offset_to_top=None,
        )
        mock_write_vtable_yaml.assert_called_once_with(
            "/tmp/CSpawnGroupMgrGameSystem_vtable2.windows.yaml",
            fake_vtable_data,
        )

    async def test_preprocess_skill_uses_linux_offset_to_top_filter(self) -> None:
        module = _load_module(
            CSPAWNGROUP_VTABLE2_SCRIPT_PATH,
            "find_CSpawnGroupMgrGameSystem_vtable2_linux",
        )
        fake_vtable_data = {
            "vtable_class": "CSpawnGroupMgrGameSystem",
            "vtable_symbol": "_ZTI24CSpawnGroupMgrGameSystem ref 0x40f1728 offset_to_top -8",
            "vtable_va": "0x40f1730",
            "vtable_rva": "0xf1730",
            "vtable_size": "0x10",
            "vtable_numvfunc": 2,
            "vtable_entries": {
                0: "0xc2efc0",
                1: "0xc2efd0",
            },
        }
        mock_preprocess = AsyncMock(return_value=fake_vtable_data)

        with patch.object(
            module,
            "preprocess_ordinal_vtable_via_mcp",
            mock_preprocess,
        ), patch.object(module, "write_vtable_yaml") as mock_write_vtable_yaml:
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=[
                    "/tmp/CSpawnGroupMgrGameSystem_vtable2.linux.yaml"
                ],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="linux",
                image_base=0x400000,
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess.assert_awaited_once_with(
            session="session",
            class_name="CSpawnGroupMgrGameSystem",
            ordinal=0,
            image_base=0x400000,
            platform="linux",
            debug=True,
            symbol_aliases=None,
            expected_offset_to_top=-8,
        )
        mock_write_vtable_yaml.assert_called_once_with(
            "/tmp/CSpawnGroupMgrGameSystem_vtable2.linux.yaml",
            fake_vtable_data,
        )
```

- [ ] **Step 3: Run the targeted failing tests**

Run only these tests if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_preprocessor_scripts.TestFindCSpawnGroupMgrGameSystemVtable2 -v
```

Expected before implementation: import failure for missing `find-CSpawnGroupMgrGameSystem_vtable2.py`.

- [ ] **Step 4: Create the vtable2 wrapper script**

Create `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_vtable2.py` with this content:

```python
#!/usr/bin/env python3
"""Preprocess script for find-CSpawnGroupMgrGameSystem_vtable2 skill."""

import os

from ida_analyze_util import write_vtable_yaml
from _ordinal_vtable_common import preprocess_ordinal_vtable_via_mcp


TARGET_CLASS_NAME = "CSpawnGroupMgrGameSystem"
TARGET_OUTPUT_STEM = "CSpawnGroupMgrGameSystem_vtable2"
WINDOWS_SYMBOL_ALIASES = ["??_7CSpawnGroupMgrGameSystem@@6B@_0"]
LINUX_EXPECTED_OFFSET_TO_TOP = -8


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    _ = skill_name
    _ = old_yaml_map
    _ = new_binary_dir

    target_filename = f"{TARGET_OUTPUT_STEM}.{platform}.yaml"
    target_outputs = [
        path for path in expected_outputs
        if os.path.basename(path) == target_filename
    ]
    if len(target_outputs) != 1:
        if debug:
            print(
                f"    Preprocess: expected exactly one output named "
                f"{target_filename}, got {len(target_outputs)}"
            )
        return False

    if platform == "windows":
        symbol_aliases = WINDOWS_SYMBOL_ALIASES
        expected_offset_to_top = None
    elif platform == "linux":
        symbol_aliases = None
        expected_offset_to_top = LINUX_EXPECTED_OFFSET_TO_TOP
    else:
        if debug:
            print(f"    Preprocess: unsupported platform for vtable2: {platform}")
        return False

    vtable_data = await preprocess_ordinal_vtable_via_mcp(
        session=session,
        class_name=TARGET_CLASS_NAME,
        ordinal=0,
        image_base=image_base,
        platform=platform,
        debug=debug,
        symbol_aliases=symbol_aliases,
        expected_offset_to_top=expected_offset_to_top,
    )
    if vtable_data is None:
        return False

    write_vtable_yaml(target_outputs[0], vtable_data)
    if debug:
        print(f"    Preprocess: generated {target_filename}")
    return True
```

- [ ] **Step 5: Run the targeted tests**

Run only these tests if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_preprocessor_scripts.TestFindCSpawnGroupMgrGameSystemVtable2 -v
```

Expected after implementation: both wrapper tests pass.

## Task 4: Bind `DoesGameSystemReallocate` to `vtable2`

**Files:**
- Modify: `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py`
- Modify: `tests/test_ida_preprocessor_scripts.py`

- [ ] **Step 1: Add script path constant**

Add this constant near the other script path constants in `tests/test_ida_preprocessor_scripts.py`:

```python
CSPAWNGROUP_DOES_REALLOCATE_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py"
)
```

- [ ] **Step 2: Write failing script contract test**

Add this test class in `tests/test_ida_preprocessor_scripts.py`:

```python
class TestFindCSpawnGroupMgrGameSystemDoesGameSystemReallocate(
    unittest.IsolatedAsyncioTestCase
):
    async def test_preprocess_skill_binds_to_secondary_vtable_artifact(self) -> None:
        module = _load_module(
            CSPAWNGROUP_DOES_REALLOCATE_SCRIPT_PATH,
            "find_CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)

        with patch.object(
            module,
            "preprocess_common_skill",
            mock_preprocess_common_skill,
        ), patch.object(
            module,
            "_read_vfunc_offset",
            return_value=0x18,
        ):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="/tmp/bin/server",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        call_kwargs = mock_preprocess_common_skill.await_args.kwargs
        self.assertEqual(
            [
                (
                    "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
                    "CSpawnGroupMgrGameSystem_vtable2",
                )
            ],
            call_kwargs["func_vtable_relations"],
        )
        self.assertEqual(
            [
                {
                    "func_name": "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
                    "xref_strings": [],
                    "xref_gvs": [],
                    "xref_signatures": [
                        "48 8B 0D ?? ?? ?? ?? 48 8B 01 48 FF 60 18"
                    ],
                    "xref_funcs": [],
                    "exclude_funcs": [],
                    "exclude_strings": [],
                    "exclude_gvs": [],
                    "exclude_signatures": [],
                }
            ],
            call_kwargs["func_xrefs"],
        )
```

- [ ] **Step 3: Run the targeted failing test**

Run only this test if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_preprocessor_scripts.TestFindCSpawnGroupMgrGameSystemDoesGameSystemReallocate -v
```

Expected before implementation: assertion failure because `func_vtable_relations` still points at `CSpawnGroupMgrGameSystem`.

- [ ] **Step 4: Update the script relation**

In `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py`, replace `FUNC_VTABLE_RELATIONS` with:

```python
FUNC_VTABLE_RELATIONS = [
    (
        "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
        "CSpawnGroupMgrGameSystem_vtable2",
    ),
]
```

- [ ] **Step 5: Run the targeted test**

Run only this test if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_preprocessor_scripts.TestFindCSpawnGroupMgrGameSystemDoesGameSystemReallocate -v
```

Expected after implementation: the script contract test passes.

## Task 5: Update `config.yaml`

**Files:**
- Modify: `config.yaml:1011`
- Modify: `config.yaml:2730`

- [ ] **Step 1: Add the new preprocessing skill**

In the server skill list near `find-CSpawnGroupMgrGameSystem_vtable`, update the block to:

```yaml
      - name: find-CSpawnGroupMgrGameSystem_vtable
        expected_output:
          - CSpawnGroupMgrGameSystem_vtable.{platform}.yaml

      - name: find-CSpawnGroupMgrGameSystem_vtable2
        expected_output:
          - CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml

      - name: find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate
        expected_output:
          - CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.{platform}.yaml
        expected_input:
          - IGameSystemFactory_DoesGameSystemReallocate.{platform}.yaml
          - CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml
```

- [ ] **Step 2: Add the vtable2 symbol entry**

In the symbol list near `CSpawnGroupMgrGameSystem_vtable`, update the block to:

```yaml
      - name: CSpawnGroupMgrGameSystem_vtable
        category: vtable

      - name: CSpawnGroupMgrGameSystem_vtable2
        category: vtable

      - name: CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_vtable
        category: vtable
```

- [ ] **Step 3: Validate YAML parsing**

Run this command if the user authorizes validation:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml

data = yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8"))
assert data is not None
print("config.yaml parsed")
PY
```

Expected output:

```text
config.yaml parsed
```

## Task 6: Run focused verification

**Files:**
- Test: `tests/test_ida_analyze_util.py`
- Test: `tests/test_ida_preprocessor_scripts.py`
- Verify: `config.yaml`

- [ ] **Step 1: Run artifact-stem tests**

Run if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_analyze_util.TestVtableArtifactStemSupport -v
```

Expected: all tests pass.

- [ ] **Step 2: Run ordinal helper tests**

Run if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_preprocessor_scripts.TestOrdinalVtableCommon -v
```

Expected: all tests pass.

- [ ] **Step 3: Run vtable2 wrapper tests**

Run if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_preprocessor_scripts.TestFindCSpawnGroupMgrGameSystemVtable2 -v
```

Expected: all tests pass.

- [ ] **Step 4: Run DoesGameSystemReallocate script contract test**

Run if the user authorizes test execution:

```bash
python3 -m unittest tests.test_ida_preprocessor_scripts.TestFindCSpawnGroupMgrGameSystemDoesGameSystemReallocate -v
```

Expected: all tests pass.

- [ ] **Step 5: Run a narrow regression set for touched shared paths**

Run if the user authorizes test execution:

```bash
python3 -m unittest \
  tests.test_ida_analyze_util.TestVtableAliasSupport \
  tests.test_ida_analyze_util.TestPreprocessIndexBasedVfuncViaMcp \
  tests.test_ida_preprocessor_scripts.TestFindCGameSystemReallocatingFactoryCSpawnGroupMgrGameSystemVtable \
  -v
```

Expected: all tests pass.

## Task 7: Final review checklist

**Files:**
- Review: `ida_analyze_util.py`
- Review: `ida_preprocessor_scripts/_ordinal_vtable_common.py`
- Review: `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_vtable2.py`
- Review: `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py`
- Review: `config.yaml`
- Review: `tests/test_ida_analyze_util.py`
- Review: `tests/test_ida_preprocessor_scripts.py`

- [ ] **Step 1: Confirm no double `_vtable` suffix path exists**

Run:

```bash
rg -n "_vtable2_vtable|_vtable_vtable" .
```

Expected: no matches in source or generated YAML paths.

- [ ] **Step 2: Confirm no primary-vtable fallback in DoesGameSystemReallocate**

Run:

```bash
rg -n "CSpawnGroupMgrGameSystem_vtable2|CSpawnGroupMgrGameSystem\"\\)" \
  ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py \
  config.yaml
```

Expected:

- `find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py` contains `CSpawnGroupMgrGameSystem_vtable2`
- `config.yaml` contains `CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml`
- No relation in the script points to plain `CSpawnGroupMgrGameSystem`

- [ ] **Step 3: Review git diff**

Run:

```bash
git diff -- \
  ida_analyze_util.py \
  ida_preprocessor_scripts/_ordinal_vtable_common.py \
  ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_vtable2.py \
  ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py \
  config.yaml \
  tests/test_ida_analyze_util.py \
  tests/test_ida_preprocessor_scripts.py
```

Expected: diff contains only the ordinal-vtable, vtable2 binding, config, and focused tests described in this plan.

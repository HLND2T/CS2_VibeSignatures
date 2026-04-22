# CSource2Client Vtable Undefined Entry Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `preprocess_vtable_via_mcp` 在 Linux vtable 遇到指向 `.text` 但尚未定义为函数的 entry 时，先恢复函数定义并把归一化后的真实函数起点写入 `vtable_entries`，而不是提前停表。

**Architecture:** 仅修改 `ida_analyze_util.py` 中的 `_VTABLE_PY_EVAL_TEMPLATE`、`_build_vtable_py_eval`、以及 `preprocess_vtable_via_mcp` 的 builder 调用。模板内新增一个“可执行段 entry 恢复为函数起点”的局部 helper：先复用已有函数，缺失时在 IDA 内创建指令和函数，再用覆盖该地址的 `func.start_ea` 作为最终 entry 值。测试集中放在 `tests/test_ida_analyze_util.py`，通过检查生成的 `py_eval` 脚本文本与 builder 调用参数来锁定行为，不依赖真实 IDA 会话。

**Tech Stack:** Python 3、仓库现有 `unittest.IsolatedAsyncioTestCase`、`unittest.mock.AsyncMock`、IDA `py_eval` 模板字符串、IDA Python API (`idaapi`, `ida_bytes`, `ida_auto`, `idc`)。

**Commit Policy:** Do not commit during execution unless the user explicitly requests it; project instructions override the generic frequent-commit guidance.

---

## File Structure

- Modify: `ida_analyze_util.py`
  - 在 `_VTABLE_PY_EVAL_TEMPLATE` 中加入 `debug_enabled` 占位符。
  - 在模板内加入 `_debug(...)` 与 `_resolve_vtable_func_start(...)` helper。
  - 把可执行段 entry 的写入值从 `hex(ptr_value)` 改为 `hex(func_start)`。
  - 让 `_build_vtable_py_eval(...)` 接收 `debug` 并替换 `DEBUG_PLACEHOLDER`。
  - 让 `preprocess_vtable_via_mcp(...)` 把 `debug` 透传给 `_build_vtable_py_eval(...)`。
- Modify: `tests/test_ida_analyze_util.py`
  - 新增 `TestVtableEntryRecoverySupport`，覆盖 builder debug 占位符、builder 调用透传、模板内 exec-entry 恢复 helper、以及归一化写入逻辑。

### Task 1: 接通 builder 的 debug 透传

**Files:**
- Modify: `ida_analyze_util.py:34`
- Modify: `ida_analyze_util.py:493`
- Modify: `ida_analyze_util.py:2539`
- Test: `tests/test_ida_analyze_util.py:359`

- [ ] **Step 1: 在 `tests/test_ida_analyze_util.py` 新增 builder/debug 失败测试**

在 `class TestVtableAliasSupport(unittest.IsolatedAsyncioTestCase):` 之后插入这个新测试类：

```python
class TestVtableEntryRecoverySupport(unittest.IsolatedAsyncioTestCase):
    def test_build_vtable_py_eval_embeds_debug_flag(self) -> None:
        py_code = ida_analyze_util._build_vtable_py_eval(
            "CSource2Client",
            debug=True,
        )

        self.assertIn('"CSource2Client"', py_code)
        self.assertIn("debug_enabled = True", py_code)
        self.assertNotIn("DEBUG_PLACEHOLDER", py_code)

    async def test_preprocess_vtable_via_mcp_forwards_debug_to_builder(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "vtable_class": "CSource2Client",
                "vtable_symbol": "_ZTV14CSource2Client + 0x10",
                "vtable_va": "0x424f6c0",
                "vtable_size": "0x18",
                "vtable_numvfunc": 3,
                "vtable_entries": {
                    "0": "0x174e400",
                    "1": "0x174dcd0",
                    "2": "0x17481f0",
                },
            }
        )

        with patch.object(
            ida_analyze_util,
            "_build_vtable_py_eval",
            return_value="py-code",
        ) as mock_build:
            result = await ida_analyze_util.preprocess_vtable_via_mcp(
                session=session,
                class_name="CSource2Client",
                image_base=0x400000,
                platform="linux",
                debug=True,
            )

        self.assertEqual(
            {
                "vtable_class": "CSource2Client",
                "vtable_symbol": "_ZTV14CSource2Client + 0x10",
                "vtable_va": "0x424f6c0",
                "vtable_rva": hex(0x424F6C0 - 0x400000),
                "vtable_size": "0x18",
                "vtable_numvfunc": 3,
                "vtable_entries": {
                    0: "0x174e400",
                    1: "0x174dcd0",
                    2: "0x17481f0",
                },
            },
            result,
        )
        mock_build.assert_called_once_with(
            "CSource2Client",
            symbol_aliases=None,
            debug=True,
        )
        session.call_tool.assert_awaited_once_with(
            name="py_eval",
            arguments={"code": "py-code"},
        )
```

- [ ] **Step 2: 运行定向单测，确认当前实现还不支持 `debug` 透传**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestVtableEntryRecoverySupport.test_build_vtable_py_eval_embeds_debug_flag \
  tests.test_ida_analyze_util.TestVtableEntryRecoverySupport.test_preprocess_vtable_via_mcp_forwards_debug_to_builder \
  -v
```

Expected: FAIL，`_build_vtable_py_eval()` 报 `unexpected keyword argument 'debug'`，或 `mock_build.assert_called_once_with(..., debug=True)` 不成立。

- [ ] **Step 3: 修改模板头部、builder 签名、以及 `preprocess_vtable_via_mcp(...)` 的 builder 调用**

先把 `_VTABLE_PY_EVAL_TEMPLATE` 开头四行替换为：

```python
_VTABLE_PY_EVAL_TEMPLATE = r'''
import ida_bytes, ida_name, idaapi, idautils, ida_segment, json

class_name = CLASS_NAME_PLACEHOLDER
candidate_symbols = CANDIDATE_SYMBOLS_PLACEHOLDER
debug_enabled = DEBUG_PLACEHOLDER
ptr_size = 8 if idaapi.inf_is_64bit() else 4
```

再把 `_build_vtable_py_eval(...)` 整个函数替换为：

```python
def _build_vtable_py_eval(class_name, symbol_aliases=None, debug=False):
    """Build the vtable py_eval script for the given class name."""
    return (
        _VTABLE_PY_EVAL_TEMPLATE
        .replace("CLASS_NAME_PLACEHOLDER", json.dumps(class_name))
        .replace(
            "CANDIDATE_SYMBOLS_PLACEHOLDER",
            json.dumps(list(symbol_aliases or [])),
        )
        .replace("DEBUG_PLACEHOLDER", "True" if debug else "False")
    )
```

最后把 `preprocess_vtable_via_mcp(...)` 中构造脚本的那一行替换为：

```python
    py_code = _build_vtable_py_eval(
        class_name,
        symbol_aliases=symbol_aliases,
        debug=debug,
    )
```

- [ ] **Step 4: 重跑这两个单测，确认 builder/debug 通路打通**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestVtableEntryRecoverySupport.test_build_vtable_py_eval_embeds_debug_flag \
  tests.test_ida_analyze_util.TestVtableEntryRecoverySupport.test_preprocess_vtable_via_mcp_forwards_debug_to_builder \
  -v
```

Expected: PASS

### Task 2: 在 vtable 模板内恢复未定义的可执行段 entry

**Files:**
- Modify: `ida_analyze_util.py:35`
- Modify: `ida_analyze_util.py:45`
- Modify: `ida_analyze_util.py:137`
- Test: `tests/test_ida_analyze_util.py:359`

- [ ] **Step 1: 在同一个测试类里继续补充 exec-entry 恢复失败测试**

把下面两个测试方法追加到 `TestVtableEntryRecoverySupport`：

```python
    def test_build_vtable_py_eval_recovers_exec_entries_to_func_start(self) -> None:
        py_code = ida_analyze_util._build_vtable_py_eval(
            "CSource2Client",
            debug=True,
        )

        self.assertIn(
            "import ida_auto, ida_bytes, ida_name, idaapi, ida_segment, idautils, idc, json",
            py_code,
        )
        self.assertIn("def _debug(message):", py_code)
        self.assertIn("def _resolve_vtable_func_start(ptr_value):", py_code)
        self.assertIn(
            "ida_bytes.del_items(ptr_value, ida_bytes.DELIT_SIMPLE, ptr_size)",
            py_code,
        )
        self.assertIn("idc.create_insn(ptr_value)", py_code)
        self.assertIn("idaapi.add_func(ptr_value)", py_code)
        self.assertIn("ida_auto.auto_wait()", py_code)
        self.assertIn("func_start = _resolve_vtable_func_start(ptr_value)", py_code)
        self.assertIn("entries[count] = hex(func_start)", py_code)

    def test_build_vtable_py_eval_rejects_uncovered_recovery_result(self) -> None:
        py_code = ida_analyze_util._build_vtable_py_eval(
            "CSource2Client",
            debug=True,
        )

        self.assertIn("if func is None:", py_code)
        self.assertIn(
            'f"    Preprocess vtable: no function covers {hex(ptr_value)} after recovery"',
            py_code,
        )
        self.assertIn(
            "if not (func.start_ea <= ptr_value < func.end_ea):",
            py_code,
        )
        self.assertIn(
            'f"{hex(func.start_ea)} does not cover {hex(ptr_value)}"',
            py_code,
        )
```

- [ ] **Step 2: 运行新增的两个测试，确认当前模板还没有恢复 helper**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestVtableEntryRecoverySupport.test_build_vtable_py_eval_recovers_exec_entries_to_func_start \
  tests.test_ida_analyze_util.TestVtableEntryRecoverySupport.test_build_vtable_py_eval_rejects_uncovered_recovery_result \
  -v
```

Expected: FAIL，缺少 `ida_auto` / `idc` 导入、缺少 `_resolve_vtable_func_start(...)`、或仍然把 entry 直接写成 `hex(ptr_value)`。

- [ ] **Step 3: 扩展模板导入并加入本地恢复 helper**

把模板最顶部导入行替换为：

```python
import ida_auto, ida_bytes, ida_name, idaapi, ida_segment, idautils, idc, json
```

然后在 `_try_direct_symbol(...)` 之后、`for symbol_name in candidate_symbols:` 之前插入：

```python
def _debug(message):
    if debug_enabled:
        print(message)


def _resolve_vtable_func_start(ptr_value):
    func = idaapi.get_func(ptr_value)
    if func is not None and func.start_ea <= ptr_value < func.end_ea:
        return func.start_ea

    flags = ida_bytes.get_full_flags(ptr_value)
    if not ida_bytes.is_code(flags):
        try:
            ida_bytes.del_items(ptr_value, ida_bytes.DELIT_SIMPLE, ptr_size)
        except Exception as exc:
            _debug(
                f"    Preprocess vtable: del_items failed for {hex(ptr_value)}: {exc}"
            )
        try:
            idc.create_insn(ptr_value)
        except Exception as exc:
            _debug(
                f"    Preprocess vtable: create_insn failed for {hex(ptr_value)}: {exc}"
            )

    try:
        idaapi.add_func(ptr_value)
    except Exception as exc:
        _debug(f"    Preprocess vtable: add_func failed for {hex(ptr_value)}: {exc}")

    try:
        ida_auto.auto_wait()
    except Exception:
        pass

    func = idaapi.get_func(ptr_value)
    if func is None:
        _debug(
            f"    Preprocess vtable: no function covers {hex(ptr_value)} after recovery"
        )
        return None
    if not (func.start_ea <= ptr_value < func.end_ea):
        _debug(
            "    Preprocess vtable: recovered function "
            f"{hex(func.start_ea)} does not cover {hex(ptr_value)}"
        )
        return None
    return func.start_ea
```

- [ ] **Step 4: 用恢复 helper 替换现有 exec-entry 写入分支**

把 vtable 扫描循环里下面这段旧逻辑：

```python
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
```

替换为：

```python
        func_start = _resolve_vtable_func_start(ptr_value)
        if func_start is None:
            break
        entries[count] = hex(func_start)
        count += 1
        continue
```

注意不要改动上面的 Linux `ptr_value == 0` 分支；它仍然应该保持：

```python
        if ptr_value == 0:
            if is_linux:
                entries[count] = hex(ptr_value)
                count += 1
                continue
            else:
                break
```

- [ ] **Step 5: 重新运行四个 recovery/debug 相关测试**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestVtableEntryRecoverySupport.test_build_vtable_py_eval_embeds_debug_flag \
  tests.test_ida_analyze_util.TestVtableEntryRecoverySupport.test_preprocess_vtable_via_mcp_forwards_debug_to_builder \
  tests.test_ida_analyze_util.TestVtableEntryRecoverySupport.test_build_vtable_py_eval_recovers_exec_entries_to_func_start \
  tests.test_ida_analyze_util.TestVtableEntryRecoverySupport.test_build_vtable_py_eval_rejects_uncovered_recovery_result \
  -v
```

Expected: PASS

### Task 3: 做 focused regression，确认旧 builder 行为未回退

**Files:**
- Test: `tests/test_ida_analyze_util.py`

- [ ] **Step 1: 运行旧 builder 测试加上新 recovery 测试类**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestVtableAliasSupport.test_build_vtable_py_eval_embeds_candidate_symbols \
  tests.test_ida_analyze_util.TestVtableEntryRecoverySupport \
  -v
```

Expected: PASS

- [ ] **Step 2: 记录本次验证结论**

把执行结论写入工作记录时，使用下面这段摘要：

```text
Focused unittest coverage passed:
- TestVtableAliasSupport.test_build_vtable_py_eval_embeds_candidate_symbols
- TestVtableEntryRecoverySupport (all tests)

This confirms:
1. candidate symbol embedding still works;
2. debug flag is forwarded into the builder;
3. exec-segment entries now go through local function recovery;
4. recovered entries are normalized to func.start_ea before writing.
```

## Self-Review Checklist

- Spec coverage:
  - `debug` 透传：Task 1
  - 模板内恢复未定义函数：Task 2
  - 归一化写入 `func.start_ea`：Task 2
  - focused regression：Task 3
- Placeholder scan:
  - 无 `TBD` / `TODO` / “later” / “appropriate handling” 之类占位描述
- Type consistency:
  - 统一使用 `_build_vtable_py_eval(..., debug=False)`
  - 统一使用 `_resolve_vtable_func_start(ptr_value)`
  - 统一把恢复结果命名为 `func_start`

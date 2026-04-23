# String Enumeration Min Length Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 统一仓库内所有 IDA 字符串枚举的最小长度配置，默认支持 4 字节字符串，并在同一次 `py_eval` 中复用单个 `idautils.Strings` 实例完成多目标精确匹配扫描。

**Architecture:** 以 `ida_analyze_util.py` 为唯一共享入口，集中解析 `CS2VIBE_STRING_MIN_LENGTH` 并生成统一的 `Strings(default_setup=False)` / `setup(...)` 代码片段。单目标调用点改为复用共享 setup，多目标调用点进一步切换为“一次扫描建立命中索引，再按目标文本取值”，避免同一次 `py_eval` 内重复全表扫描。

**Tech Stack:** Python 3.10+, IDAPython `idautils.Strings`, `unittest`, `uv`

---

## File Structure

- Modify: `ida_analyze_util.py`
  - 新增统一最小长度解析 helper
  - 新增统一 `Strings.setup(...)` 代码片段 helper
  - 新增“单次扫描建立精确匹配索引”的代码片段 helper
  - 更新 `_collect_xref_func_starts_for_string()`
- Modify: `ida_preprocessor_scripts/_define_inputfunc.py`
  - 接入共享 `Strings` setup 片段
- Modify: `ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py`
  - 接入共享 `Strings` setup 片段
- Modify: `ida_preprocessor_scripts/_registerconcommand.py`
  - 改为单次扫描复用同一份 `Strings` 实例
- Modify: `ida_preprocessor_scripts/_register_event_listener_abstract.py`
  - 改为单次扫描复用同一份 `Strings` 实例
- Modify: `tests/test_ida_analyze_util.py`
  - 新增共享 helper 测试
  - 增强 `_collect_xref_func_starts_for_string()` 的构造代码断言
- Modify: `tests/test_define_inputfunc_preprocessor.py`
  - 增强生成的 `py_eval` 代码断言
- Modify: `tests/test_registerconcommand_preprocessor.py`
  - 增强多目标单次扫描相关断言
- Modify: `tests/test_register_event_listener_abstract_preprocessor.py`
  - 增强多目标单次扫描相关断言
- Modify: `tests/test_ida_preprocessor_scripts.py`
  - 为 `find-CBaseFilter_InputTestActivator.py` Linux fallback 增加回归测试
- Modify: `README.md`
  - 记录 `CS2VIBE_STRING_MIN_LENGTH`

### Task 1: Add shared string-enumeration helpers

**Files:**
- Modify: `ida_analyze_util.py`
- Modify: `tests/test_ida_analyze_util.py`

- [ ] **Step 1: Write the failing helper tests**

```python
class TestIdaStringEnumerationSupport(unittest.TestCase):
    def test_resolve_ida_string_min_length_defaults_to_four(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            self.assertEqual(4, ida_analyze_util._resolve_ida_string_min_length())

    def test_resolve_ida_string_min_length_rejects_invalid_values(self) -> None:
        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "not-an-int"},
            clear=False,
        ):
            self.assertEqual(4, ida_analyze_util._resolve_ida_string_min_length())

        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "0"},
            clear=False,
        ):
            self.assertEqual(4, ida_analyze_util._resolve_ida_string_min_length())

        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "6"},
            clear=False,
        ):
            self.assertEqual(6, ida_analyze_util._resolve_ida_string_min_length())

    def test_build_ida_strings_setup_py_lines_embeds_resolved_min_length(self) -> None:
        lines = ida_analyze_util._build_ida_strings_setup_py_lines()
        code = "\n".join(lines)
        self.assertIn("strings = idautils.Strings(default_setup=False)", code)
        self.assertIn(
            "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)",
            code,
        )

    def test_build_ida_exact_string_index_py_lines_reuses_single_strings_loop(self) -> None:
        lines = ida_analyze_util._build_ida_exact_string_index_py_lines(
            target_texts_var_name="target_texts",
            result_var_name="string_hits",
        )
        code = "\n".join(lines)
        self.assertIn("string_hits = {text: [] for text in target_texts if text}", code)
        self.assertIn("for item in strings:", code)
        self.assertIn("current_text = str(item)", code)
        self.assertIn("if current_text in string_hits:", code)
```

- [ ] **Step 2: Run the helper tests to verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestIdaStringEnumerationSupport
```

Expected: FAIL with `AttributeError` for missing helper names such as `_resolve_ida_string_min_length`.

- [ ] **Step 3: Implement the shared helpers in `ida_analyze_util.py`**

```python
DEFAULT_IDA_STRING_MIN_LENGTH = 4


def _resolve_ida_string_min_length() -> int:
    raw = os.environ.get("CS2VIBE_STRING_MIN_LENGTH")
    if raw is None:
        return DEFAULT_IDA_STRING_MIN_LENGTH
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_IDA_STRING_MIN_LENGTH
    return value if value >= 1 else DEFAULT_IDA_STRING_MIN_LENGTH


def _build_ida_strings_setup_py_lines(
    *,
    strings_var_name: str = "strings",
    min_length: int | None = None,
) -> list[str]:
    resolved_min_length = (
        _resolve_ida_string_min_length()
        if min_length is None
        else int(min_length)
    )
    return [
        f"{strings_var_name} = idautils.Strings(default_setup=False)",
        (
            f"{strings_var_name}.setup("
            f"strtypes=[ida_nalt.STRTYPE_C], minlen={resolved_min_length})"
        ),
    ]


def _build_ida_exact_string_index_py_lines(
    *,
    target_texts_var_name: str,
    result_var_name: str = "string_hits",
    strings_var_name: str = "strings",
    item_var_name: str = "item",
) -> list[str]:
    return [
        f"{result_var_name} = {{text: [] for text in {target_texts_var_name} if text}}",
        *_build_ida_strings_setup_py_lines(strings_var_name=strings_var_name),
        f"for {item_var_name} in {strings_var_name}:",
        "    try:",
        f"        current_text = str({item_var_name})",
        "    except Exception:",
        "        continue",
        f"    if current_text in {result_var_name}:",
        f"        {result_var_name}[current_text].append(int({item_var_name}.ea))",
    ]
```

- [ ] **Step 4: Run the helper tests to verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestIdaStringEnumerationSupport
```

Expected: PASS.

- [ ] **Step 5: Commit the helper foundation**

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "test(ida): 覆盖字符串枚举共享辅助"
```

### Task 2: Wire shared setup into `_collect_xref_func_starts_for_string`

**Files:**
- Modify: `ida_analyze_util.py`
- Modify: `tests/test_ida_analyze_util.py`

- [ ] **Step 1: Extend `_collect_xref_func_starts_for_string()` tests**

```python
async def test_collect_xref_func_starts_for_string_embeds_shared_strings_setup(
    self,
) -> None:
    session = AsyncMock()
    session.call_tool.return_value = _py_eval_payload(["0x180001123"])

    with patch.object(
        ida_analyze_util,
        "_normalize_func_starts_for_code_addrs",
        AsyncMock(return_value={0x180001000}),
    ):
        await ida_analyze_util._collect_xref_func_starts_for_string(
            session=session,
            xref_string="_projectile",
            debug=True,
        )

    py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
    self.assertIn("import ida_nalt, idautils, json", py_code)
    self.assertIn("strings = idautils.Strings(default_setup=False)", py_code)
    self.assertIn(
        "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)",
        py_code,
    )
    self.assertIn("for s in strings:", py_code)
    self.assertNotIn("for s in idautils.Strings():", py_code)


async def test_collect_xref_func_starts_for_string_honors_env_min_length(
    self,
) -> None:
    session = AsyncMock()
    session.call_tool.return_value = _py_eval_payload(["0x180001123"])

    with patch.dict(
        os.environ,
        {"CS2VIBE_STRING_MIN_LENGTH": "6"},
        clear=False,
    ):
        with patch.object(
            ida_analyze_util,
            "_normalize_func_starts_for_code_addrs",
            AsyncMock(return_value={0x180001000}),
        ):
            await ida_analyze_util._collect_xref_func_starts_for_string(
                session=session,
                xref_string="FULLMATCH:_projectile",
                debug=True,
            )

    py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
    self.assertIn("minlen=6", py_code)
    self.assertIn("if current_str == search_str:", py_code)
```

- [ ] **Step 2: Run the focused async tests to verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_collect_xref_func_starts_for_string_embeds_shared_strings_setup \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_collect_xref_func_starts_for_string_honors_env_min_length
```

Expected: FAIL because current `py_code` still contains `for s in idautils.Strings():` and no `minlen=6`.

- [ ] **Step 3: Refactor `_collect_xref_func_starts_for_string()` to use the shared helpers**

```python
py_lines = [
    "import ida_nalt, idautils, json",
    f"search_str = {json.dumps(search_str)}",
    "code_addrs = set()",
    *_build_ida_strings_setup_py_lines(strings_var_name="strings"),
    "for s in strings:",
    "    current_str = str(s)",
    f"    if {match_expr}:",
    "        for xref in idautils.XrefsTo(s.ea, 0):",
    "            code_addrs.add(xref.frm)",
    "result = json.dumps([hex(ea) for ea in sorted(code_addrs)])",
]
py_code = "\n".join(py_lines) + "\n"
```

- [ ] **Step 4: Run the focused async tests to verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_collect_xref_func_starts_for_string_embeds_shared_strings_setup \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_collect_xref_func_starts_for_string_honors_env_min_length
```

Expected: PASS.

- [ ] **Step 5: Commit the xref-string path update**

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "fix(preprocess): 统一字符串 xref 枚举阈值"
```

### Task 3: Update single-target preprocessors

**Files:**
- Modify: `ida_preprocessor_scripts/_define_inputfunc.py`
- Modify: `ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py`
- Modify: `tests/test_define_inputfunc_preprocessor.py`
- Modify: `tests/test_ida_preprocessor_scripts.py`

- [ ] **Step 1: Add failing tests for the two single-target paths**

```python
def test_build_define_inputfunc_py_eval_uses_shared_strings_setup(self) -> None:
    code = define_inputfunc._build_define_inputfunc_py_eval(
        input_name="ShowHudHint",
        handler_ptr_offset=0x10,
        allowed_segment_names=(".data",),
    )

    self.assertIn("strings = idautils.Strings(default_setup=False)", code)
    self.assertIn(
        "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)",
        code,
    )
    self.assertIn("for item in strings:", code)
    self.assertNotIn("for item in idautils.Strings():", code)


class TestFindCBaseFilterInputTestActivator(unittest.IsolatedAsyncioTestCase):
    async def test_linux_fallback_uses_shared_strings_setup(self) -> None:
        module = _load_module(
            "ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py",
            "find_CBaseFilter_InputTestActivator",
        )
        session = AsyncMock()
        session.call_tool.side_effect = [
            _py_eval_payload(json.dumps("0x180012340")),
            _FakeCallToolResult([]),
        ]

        with patch.object(
            module,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_sig": "48 89 5C 24 ? 57",
                    "func_size": "0x20",
                }
            ),
        ), patch.object(module, "write_func_yaml"):
            result = await module._linux_resolve_via_string_xref(
                session=session,
                expected_outputs=[
                    "/tmp/CBaseFilter_InputTestActivator.linux.yaml"
                ],
                platform="linux",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        py_code = session.call_tool.await_args_list[0].kwargs["arguments"]["code"]
        self.assertIn("strings = idautils.Strings(default_setup=False)", py_code)
        self.assertIn("for s in strings:", py_code)
        self.assertNotIn("for s in idautils.Strings():", py_code)
```

- [ ] **Step 2: Run the single-target tests to verify they fail**

Run:

```bash
uv run python -m unittest \
  tests.test_define_inputfunc_preprocessor.TestBuildDefineInputFuncPyEval.test_build_define_inputfunc_py_eval_uses_shared_strings_setup \
  tests.test_ida_preprocessor_scripts.TestFindCBaseFilterInputTestActivator.test_linux_fallback_uses_shared_strings_setup
```

Expected: FAIL because the generated `py_eval` code still uses raw `idautils.Strings()`.

- [ ] **Step 3: Implement the single-target preprocessor updates**

```python
from ida_analyze_util import (
    _build_ida_strings_setup_py_lines,
    parse_mcp_result,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)

# _define_inputfunc.py body_lines excerpt
body_lines = [
    "import idaapi, ida_nalt, idautils, idc, ida_bytes",
    "input_name = params['input_name']",
    ...
    *_build_ida_strings_setup_py_lines(strings_var_name="strings"),
    "for item in strings:",
    "    try:",
    "        if str(item) == input_name:",
]

# find-CBaseFilter_InputTestActivator.py py_code excerpt
py_lines = [
    "import ida_nalt, idautils, idc, json",
    "search_str = 'TestActivator'",
    "func_va = None",
    *_build_ida_strings_setup_py_lines(strings_var_name='strings'),
    "for s in strings:",
    "    if str(s) == search_str:",
]
py_code = "\n".join(py_lines) + "\n"
```

- [ ] **Step 4: Run the single-target tests to verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_define_inputfunc_preprocessor.TestBuildDefineInputFuncPyEval.test_build_define_inputfunc_py_eval_uses_shared_strings_setup \
  tests.test_ida_preprocessor_scripts.TestFindCBaseFilterInputTestActivator.test_linux_fallback_uses_shared_strings_setup
```

Expected: PASS.

- [ ] **Step 5: Commit the single-target preprocessor changes**

```bash
git add \
  ida_preprocessor_scripts/_define_inputfunc.py \
  ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py \
  tests/test_define_inputfunc_preprocessor.py \
  tests/test_ida_preprocessor_scripts.py
git commit -m "fix(preprocess): 统一单目标字符串扫描"
```

### Task 4: Refactor `registerconcommand` to one-pass exact-string indexing

**Files:**
- Modify: `ida_preprocessor_scripts/_registerconcommand.py`
- Modify: `tests/test_registerconcommand_preprocessor.py`

- [ ] **Step 1: Add failing builder assertions for one-pass indexing**

```python
def test_build_registerconcommand_py_eval_linux_uses_one_pass_exact_string_index(
    self,
) -> None:
    code = registerconcommand._build_registerconcommand_py_eval(
        platform="linux",
        command_name="bot_add",
        help_string=(
            "bot_add <t|ct> <type> <difficulty> <name> - "
            "Adds a bot matching the given criteria."
        ),
        search_window_before_call=48,
        search_window_after_xref=24,
    )

    self.assertIn("target_texts = [command_name, help_string]", code)
    self.assertIn("string_hits = {text: [] for text in target_texts if text}", code)
    self.assertIn("strings = idautils.Strings(default_setup=False)", code)
    self.assertIn("for item in strings:", code)
    self.assertEqual(1, code.count("for item in strings:"))
    self.assertIn("command_string_addrs = string_hits.get(command_name, [])", code)
    self.assertIn("help_string_addrs = string_hits.get(help_string, [])", code)
    self.assertNotIn("for item in idautils.Strings():", code)
```

- [ ] **Step 2: Run the `registerconcommand` builder test to verify it fails**

Run:

```bash
uv run python -m unittest \
  tests.test_registerconcommand_preprocessor.TestBuildRegisterConCommandPyEval.test_build_registerconcommand_py_eval_linux_uses_one_pass_exact_string_index
```

Expected: FAIL because the builder still emits `_scan_exact_strings()` with a fresh `idautils.Strings()` loop per target.

- [ ] **Step 3: Replace repeated scans with a shared exact-string index**

```python
body_lines = [
    "import idaapi, ida_nalt, idautils, idc, ida_bytes",
    ...
    "target_texts = [command_name, help_string]",
    *_build_ida_exact_string_index_py_lines(
        target_texts_var_name="target_texts",
        result_var_name="string_hits",
    ),
    "command_string_addrs = string_hits.get(command_name, [])",
    "help_string_addrs = string_hits.get(help_string, [])",
    (
        "_debug("
        "f\"string_hits command={command_name!r} count={len(command_string_addrs)} "
        "help={help_string!r} count={len(help_string_addrs)}\")"
    ),
]
```

- [ ] **Step 4: Run the `registerconcommand` builder test to verify it passes**

Run:

```bash
uv run python -m unittest \
  tests.test_registerconcommand_preprocessor.TestBuildRegisterConCommandPyEval.test_build_registerconcommand_py_eval_linux_uses_one_pass_exact_string_index
```

Expected: PASS.

- [ ] **Step 5: Commit the `registerconcommand` refactor**

```bash
git add \
  ida_preprocessor_scripts/_registerconcommand.py \
  tests/test_registerconcommand_preprocessor.py
git commit -m "fix(preprocess): 合并命令字符串单次扫描"
```

### Task 5: Refactor `register_event_listener`, update docs, and run focused regression

**Files:**
- Modify: `ida_preprocessor_scripts/_register_event_listener_abstract.py`
- Modify: `tests/test_register_event_listener_abstract_preprocessor.py`
- Modify: `README.md`

- [ ] **Step 1: Add failing assertions for shared exact-string indexing**

```python
def test_build_register_event_listener_py_eval_uses_one_pass_exact_string_index(
    self,
) -> None:
    register_event_listener = _import_register_event_listener_module()
    code = register_event_listener._build_register_event_listener_py_eval(
        platform="windows",
        source_func_va="0x180010000",
        anchor_event_name="CLoopModeGame::OnClientPollNetworking",
        search_window_after_anchor=24,
        search_window_before_call=64,
    )

    self.assertIn("target_texts = [anchor_event_name]", code)
    self.assertIn("string_hits = {text: [] for text in target_texts if text}", code)
    self.assertIn("strings = idautils.Strings(default_setup=False)", code)
    self.assertIn("for item in strings:", code)
    self.assertEqual(1, code.count("for item in strings:"))
    self.assertIn("anchor_string_addrs = string_hits.get(anchor_event_name, [])", code)
    self.assertNotIn("for item in idautils.Strings():", code)
```

- [ ] **Step 2: Run the `register_event_listener` builder test to verify it fails**

Run:

```bash
uv run python -m unittest \
  tests.test_register_event_listener_abstract_preprocessor.TestBuildRegisterEventListenerPyEval.test_build_register_event_listener_py_eval_uses_one_pass_exact_string_index
```

Expected: FAIL because the template still emits `_scan_exact_strings()` over raw `idautils.Strings()`.

- [ ] **Step 3: Implement one-pass indexing and document the environment variable**

```python
# _register_event_listener_abstract.py template excerpt
body_lines = [
    "import idaapi, ida_hexrays, ida_nalt, idautils, idc, ida_bytes",
    ...
    "target_texts = [anchor_event_name]",
    *_build_ida_exact_string_index_py_lines(
        target_texts_var_name="target_texts",
        result_var_name="string_hits",
    ),
    "anchor_string_addrs = string_hits.get(anchor_event_name, [])",
]

# README.md updates
- Env fallbacks: `CS2VIBE_LLM_APIKEY`, `CS2VIBE_LLM_BASEURL`, `CS2VIBE_LLM_MODEL`, `CS2VIBE_LLM_TEMPERATURE`, `CS2VIBE_LLM_EFFORT`, `CS2VIBE_LLM_FAKE_AS`
- IDA preprocessor environment: `CS2VIBE_STRING_MIN_LENGTH` controls `idautils.Strings(...).setup(minlen=...)`; defaults to `4`; invalid or `< 1` values fall back to `4`
```

- [ ] **Step 4: Run the focused regression suite to verify the whole feature passes**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util \
  tests.test_define_inputfunc_preprocessor \
  tests.test_registerconcommand_preprocessor \
  tests.test_register_event_listener_abstract_preprocessor \
  tests.test_ida_preprocessor_scripts
```

Expected: PASS.

- [ ] **Step 5: Commit the final integration**

```bash
git add \
  ida_preprocessor_scripts/_register_event_listener_abstract.py \
  tests/test_register_event_listener_abstract_preprocessor.py \
  README.md
git commit -m "docs(preprocess): 记录字符串最小长度配置"
```

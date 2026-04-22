# ILoopType_DeallocateLoopMode Inline Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `find-ILoopType_DeallocateLoopMode` 在 `CEngineServiceMgr_DeactivateLoop` 被内联到 `CEngineServiceMgr__MainLoop` 时，仍能通过多目标 LLM fallback 稳定恢复 `ILoopType_DeallocateLoopMode`。

**Architecture:** 把 `find-ILoopType_DeallocateLoopMode` 的执行依赖拆成“排序依赖”和“运行时硬输入”两层；在 `ida_analyze_util.py` 中把 `LLM_DECOMPILE` 从单 reference / 单 target 扩展为同一 symbol 的多 reference / 多 target bundle；再让 `find-CEngineServiceMgr_DeactivateLoop` 在确认 inline 缺失时返回 `absent_ok`，并由调度层把它视为合法跳过而不是失败。

**Tech Stack:** Python 3、pytest、PyYAML、IDA MCP 预处理链、仓库现有 `preprocess_common_skill` LLM fallback 管线

---

## 文件结构

- `ida_preprocessor_scripts/find-ILoopType_DeallocateLoopMode.py`
  - 只负责声明 `ILoopType_DeallocateLoopMode` 的目标函数、vtable 关系、以及两条有序 `LLM_DECOMPILE` spec。
- `ida_preprocessor_scripts/find-CEngineServiceMgr_DeactivateLoop.py`
  - 负责先走现有 `preprocess_common_skill`；若失败，再基于 `CEngineServiceMgr__MainLoop` 的当前版本 detail 判断 `DeactivateLoop` 是否已内联，并返回 `absent_ok`。
- `ida_preprocessor_scripts/prompt/call_llm_decompile.md`
  - 从单 reference / 单 target 模板改为多 block 模板，接收 `reference_blocks` 与 `target_blocks`。
- `ida_analyze_util.py`
  - 负责把重复 symbol 的 `LLM_DECOMPILE` spec 聚合为有序 bundle，读取多份 reference YAML，收集多个 target detail，渲染多 block prompt，并维持原有 YAML 解析结果结构。
- `ida_skill_preprocessor.py`
  - 把脚本返回值标准化为三态：`success`、`absent_ok`、`failed`。
- `ida_analyze_bin.py`
  - 负责消费三态预处理结果，并让 `absent_ok` 计入 skip 而不是 fail；同时通过 `prerequisite` 保证排序正确。
- `config.yaml`
  - 把 `find-ILoopType_DeallocateLoopMode` 的硬输入改成 `CEngineServiceMgr__MainLoop.{platform}.yaml`，并显式添加 `prerequisite: [find-CEngineServiceMgr_DeactivateLoop]`。
- `tests/test_ida_preprocessor_scripts.py`
  - 覆盖 ILoopType 脚本的多 spec 转发，以及 `CEngineServiceMgr_DeactivateLoop` 脚本的 inline 缺失判定。
- `tests/test_ida_analyze_util.py`
  - 覆盖 spec 聚合、bundle request、cache key、多 target 缺失降级、multi-block prompt 输入。
- `tests/test_ida_analyze_bin.py`
  - 覆盖 `prerequisite` 排序，以及 `absent_ok` 在调度层的 skip 语义。

### Task 1: 更新 `ILoopType_DeallocateLoopMode` 脚本声明

**Files:**
- Modify: `ida_preprocessor_scripts/find-ILoopType_DeallocateLoopMode.py`
- Test: `tests/test_ida_preprocessor_scripts.py`

- [ ] **Step 1: 在 `tests/test_ida_preprocessor_scripts.py` 写转发失败测试**

```python
class TestFindILoopTypeDeallocateLoopMode(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_two_llm_specs_in_fixed_order(self) -> None:
        module = _load_module(
            Path("ida_preprocessor_scripts/find-ILoopType_DeallocateLoopMode.py"),
            "find_ILoopType_DeallocateLoopMode",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        llm_config = {"model": "gpt-5.4", "fake_as": "codex"}
        expected_llm_decompile_specs = [
            (
                "ILoopType_DeallocateLoopMode",
                "prompt/call_llm_decompile.md",
                "references/engine/CEngineServiceMgr_DeactivateLoop.{platform}.yaml",
            ),
            (
                "ILoopType_DeallocateLoopMode",
                "prompt/call_llm_decompile.md",
                "references/engine/CEngineServiceMgr__MainLoop.{platform}.yaml",
            ),
        ]

        with patch.object(module, "preprocess_common_skill", mock_preprocess_common_skill):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="linux",
                image_base=0x180000000,
                llm_config=llm_config,
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess_common_skill.assert_awaited_once_with(
            session="session",
            expected_outputs=["out.yaml"],
            old_yaml_map={"k": "v"},
            new_binary_dir="bin_dir",
            platform="linux",
            image_base=0x180000000,
            func_names=["ILoopType_DeallocateLoopMode"],
            func_vtable_relations=[("ILoopType_DeallocateLoopMode", "ILoopType")],
            llm_decompile_specs=expected_llm_decompile_specs,
            llm_config=llm_config,
            generate_yaml_desired_fields=[
                (
                    "ILoopType_DeallocateLoopMode",
                    [
                        "func_name",
                        "vfunc_sig",
                        "vfunc_offset",
                        "vfunc_index",
                        "vtable_name",
                    ],
                )
            ],
            debug=True,
        )
```

- [ ] **Step 2: 运行单测确认当前脚本仍只转发一条 spec**

Run: `pytest tests/test_ida_preprocessor_scripts.py::TestFindILoopTypeDeallocateLoopMode::test_preprocess_skill_forwards_two_llm_specs_in_fixed_order -v`

Expected: FAIL，断言里 `llm_decompile_specs` 只有一条 `CEngineServiceMgr_DeactivateLoop`。

- [ ] **Step 3: 修改 `ida_preprocessor_scripts/find-ILoopType_DeallocateLoopMode.py` 的 `LLM_DECOMPILE` 常量**

```python
LLM_DECOMPILE = [
    (
        "ILoopType_DeallocateLoopMode",
        "prompt/call_llm_decompile.md",
        "references/engine/CEngineServiceMgr_DeactivateLoop.{platform}.yaml",
    ),
    (
        "ILoopType_DeallocateLoopMode",
        "prompt/call_llm_decompile.md",
        "references/engine/CEngineServiceMgr__MainLoop.{platform}.yaml",
    ),
]
```

- [ ] **Step 4: 重新运行该测试确认脚本转发顺序稳定**

Run: `pytest tests/test_ida_preprocessor_scripts.py::TestFindILoopTypeDeallocateLoopMode::test_preprocess_skill_forwards_two_llm_specs_in_fixed_order -v`

Expected: PASS

- [ ] **Step 5: 提交这一小步**

```bash
git add ida_preprocessor_scripts/find-ILoopType_DeallocateLoopMode.py tests/test_ida_preprocessor_scripts.py
git commit -m "test(preprocess): 补充 ILoopType 双 spec 转发"
```

### Task 2: 让 `LLM_DECOMPILE` 支持重复 symbol 聚合

**Files:**
- Modify: `ida_analyze_util.py`
- Test: `tests/test_ida_analyze_util.py`

- [ ] **Step 1: 在 `tests/test_ida_analyze_util.py` 添加 spec 聚合与 request bundle 失败测试**

```python
def test_build_llm_decompile_specs_map_groups_duplicate_symbol_names(self) -> None:
    actual = ida_analyze_util._build_llm_decompile_specs_map(
        [
            (
                "ILoopType_DeallocateLoopMode",
                "prompt/call_llm_decompile.md",
                "references/engine/CEngineServiceMgr_DeactivateLoop.{platform}.yaml",
            ),
            (
                "ILoopType_DeallocateLoopMode",
                "prompt/call_llm_decompile.md",
                "references/engine/CEngineServiceMgr__MainLoop.{platform}.yaml",
            ),
        ]
    )

    self.assertEqual(
        {
            "ILoopType_DeallocateLoopMode": [
                {
                    "prompt_path": "prompt/call_llm_decompile.md",
                    "reference_yaml_path": "references/engine/CEngineServiceMgr_DeactivateLoop.{platform}.yaml",
                },
                {
                    "prompt_path": "prompt/call_llm_decompile.md",
                    "reference_yaml_path": "references/engine/CEngineServiceMgr__MainLoop.{platform}.yaml",
                },
            ]
        },
        actual,
    )


def test_build_llm_decompile_specs_map_rejects_mixed_prompt_paths(self) -> None:
    actual = ida_analyze_util._build_llm_decompile_specs_map(
        [
            (
                "ILoopType_DeallocateLoopMode",
                "prompt/call_llm_decompile.md",
                "references/engine/CEngineServiceMgr_DeactivateLoop.{platform}.yaml",
            ),
            (
                "ILoopType_DeallocateLoopMode",
                "prompt/other_prompt.md",
                "references/engine/CEngineServiceMgr__MainLoop.{platform}.yaml",
            ),
        ],
        debug=True,
    )

    self.assertIsNone(actual)
```

```python
async def test_prepare_llm_decompile_request_collects_multiple_references(self) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
        (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
        (preprocessor_dir / "references" / "engine").mkdir(parents=True, exist_ok=True)
        (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
            "{reference_blocks}\n---\n{target_blocks}",
            encoding="utf-8",
        )
        _write_yaml(
            preprocessor_dir / "references" / "engine" / "CEngineServiceMgr_DeactivateLoop.windows.yaml",
            {
                "func_name": "CEngineServiceMgr_DeactivateLoop",
                "disasm_code": "call    qword ptr [rax+30h]",
                "procedure": "loop_type->DeallocateLoopMode();",
            },
        )
        _write_yaml(
            preprocessor_dir / "references" / "engine" / "CEngineServiceMgr__MainLoop.windows.yaml",
            {
                "func_name": "CEngineServiceMgr__MainLoop",
                "disasm_code": "call    qword ptr [rax+30h]",
                "procedure": "loop_type->DeallocateLoopMode();",
            },
        )

        with patch.object(
            ida_analyze_util,
            "_get_preprocessor_scripts_dir",
            return_value=preprocessor_dir,
        ):
            request = ida_analyze_util._prepare_llm_decompile_request(
                "ILoopType_DeallocateLoopMode",
                {
                    "ILoopType_DeallocateLoopMode": [
                        {
                            "prompt_path": "prompt/call_llm_decompile.md",
                            "reference_yaml_path": "references/engine/CEngineServiceMgr_DeactivateLoop.{platform}.yaml",
                        },
                        {
                            "prompt_path": "prompt/call_llm_decompile.md",
                            "reference_yaml_path": "references/engine/CEngineServiceMgr__MainLoop.{platform}.yaml",
                        },
                    ]
                },
                {"model": "gpt-5.4", "fake_as": "codex"},
                platform="windows",
            )

    self.assertEqual(
        ["CEngineServiceMgr_DeactivateLoop", "CEngineServiceMgr__MainLoop"],
        request["target_func_names"],
    )
    self.assertEqual(
        [
            "CEngineServiceMgr_DeactivateLoop",
            "CEngineServiceMgr__MainLoop",
        ],
        [item["func_name"] for item in request["reference_items"]],
    )
```

- [ ] **Step 2: 运行这三条测试确认当前实现不接受重复 symbol**

Run: `python -m unittest tests.test_ida_analyze_util.TestLlmDecompileSupport.test_build_llm_decompile_specs_map_groups_duplicate_symbol_names tests.test_ida_analyze_util.TestLlmDecompileSupport.test_build_llm_decompile_specs_map_rejects_mixed_prompt_paths tests.test_ida_analyze_util.TestLlmDecompileSupport.test_prepare_llm_decompile_request_collects_multiple_references`

Expected: FAIL，当前 `_build_llm_decompile_specs_map` 会把重复 symbol 判定为 duplicated。

- [ ] **Step 3: 修改 `ida_analyze_util.py`，把单 spec map 升级成有序 bundle**

```python
def _build_llm_decompile_specs_map(llm_decompile_specs, debug=False):
    specs_map = {}
    for spec in llm_decompile_specs or []:
        if not isinstance(spec, (tuple, list)) or len(spec) != 3:
            if debug:
                print(f"    Preprocess: invalid llm_decompile spec: {spec}")
            return None

        func_name, prompt_path, reference_yaml_path = spec
        if not isinstance(func_name, str) or not func_name:
            if debug:
                print(f"    Preprocess: invalid llm_decompile target: {func_name}")
            return None
        if not isinstance(prompt_path, str) or not prompt_path:
            if debug:
                print(
                    "    Preprocess: invalid llm_decompile prompt path for "
                    f"{func_name}: {prompt_path!r}"
                )
            return None
        if not isinstance(reference_yaml_path, str) or not reference_yaml_path:
            if debug:
                print(
                    "    Preprocess: invalid llm_decompile reference path for "
                    f"{func_name}: {reference_yaml_path!r}"
                )
            return None

        spec_list = specs_map.setdefault(func_name, [])
        if spec_list and spec_list[0]["prompt_path"] != prompt_path:
            if debug:
                print(
                    "    Preprocess: inconsistent llm_decompile prompt path for "
                    f"{func_name}: {prompt_path!r}"
                )
            return None
        spec_list.append(
            {
                "prompt_path": prompt_path,
                "reference_yaml_path": reference_yaml_path,
            }
        )

    return specs_map
```

```python
def _prepare_llm_decompile_request(
    func_name,
    llm_decompile_specs_map,
    llm_config,
    platform=None,
    debug=False,
):
    llm_specs = (llm_decompile_specs_map or {}).get(func_name)
    if not llm_specs:
        return None

    prompt_path = None
    prompt_template = None
    reference_items = []
    reference_yaml_paths = []

    for llm_spec in llm_specs:
        resolved_prompt_path = Path(
            _resolve_llm_decompile_template_value(llm_spec["prompt_path"], platform)
        )
        resolved_reference_yaml_path = Path(
            _resolve_llm_decompile_template_value(
                llm_spec["reference_yaml_path"],
                platform,
            )
        )
        if not resolved_prompt_path.is_absolute():
            resolved_prompt_path = _get_preprocessor_scripts_dir() / resolved_prompt_path
        if not resolved_reference_yaml_path.is_absolute():
            resolved_reference_yaml_path = _get_preprocessor_scripts_dir() / resolved_reference_yaml_path

        if prompt_path is None:
            prompt_path = resolved_prompt_path.resolve()
            prompt_template = prompt_path.read_text(encoding="utf-8")

        with open(resolved_reference_yaml_path.resolve(), "r", encoding="utf-8") as handle:
            reference_data = yaml.safe_load(handle) or {}

        reference_items.append(
            {
                "func_name": str(reference_data.get("func_name", "") or "").strip(),
                "disasm_code": str(reference_data.get("disasm_code", "") or ""),
                "procedure": str(reference_data.get("procedure", "") or ""),
            }
        )
        reference_yaml_paths.append(os.fspath(resolved_reference_yaml_path.resolve()))

    return {
        "client": None,
        "model": str(llm_config["model"]).strip(),
        "prompt_path": os.fspath(prompt_path),
        "prompt_template": prompt_template,
        "reference_items": reference_items,
        "reference_yaml_paths": reference_yaml_paths,
        "target_func_names": [item["func_name"] for item in reference_items],
        "temperature": llm_config.get("temperature"),
        "effort": llm_config.get("effort"),
        "api_key": llm_config.get("api_key"),
        "base_url": llm_config.get("base_url"),
        "fake_as": str(llm_config.get("fake_as") or "").strip().lower() or None,
    }
```

```python
def _build_llm_decompile_request_cache_key(llm_request):
    if not isinstance(llm_request, dict):
        return None
    model = str(llm_request.get("model", "")).strip()
    prompt_path = str(llm_request.get("prompt_path", "")).strip()
    reference_yaml_paths = tuple(
        str(path).strip()
        for path in llm_request.get("reference_yaml_paths", [])
        if str(path).strip()
    )
    if not model or not prompt_path or not reference_yaml_paths:
        return None
    return model, prompt_path, reference_yaml_paths, llm_request.get("temperature")
```

- [ ] **Step 4: 重新运行上述三条测试**

Run: `python -m unittest tests.test_ida_analyze_util.TestLlmDecompileSupport.test_build_llm_decompile_specs_map_groups_duplicate_symbol_names tests.test_ida_analyze_util.TestLlmDecompileSupport.test_build_llm_decompile_specs_map_rejects_mixed_prompt_paths tests.test_ida_analyze_util.TestLlmDecompileSupport.test_prepare_llm_decompile_request_collects_multiple_references`

Expected: PASS

- [ ] **Step 5: 提交这一小步**

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "refactor(llm): 支持多 reference 聚合"
```

### Task 3: 支持多 target blocks 与“缺失 `DeactivateLoop` 仍继续”

**Files:**
- Modify: `ida_analyze_util.py`
- Modify: `ida_preprocessor_scripts/prompt/call_llm_decompile.md`
- Test: `tests/test_ida_analyze_util.py`

- [ ] **Step 1: 在 `tests/test_ida_analyze_util.py` 添加多 target 降级测试**

```python
async def test_preprocess_common_skill_uses_mainloop_target_when_deactivateloop_target_missing(
    self,
) -> None:
    normalized_payload = {
        "found_vcall": [
            {
                "insn_va": "0x180777700",
                "insn_disasm": "call    qword ptr [rax+30h]",
                "vfunc_offset": "0x30",
                "func_name": "ILoopType_DeallocateLoopMode",
            }
        ],
        "found_call": [],
        "found_funcptr": [],
        "found_gv": [],
        "found_struct_offset": [],
    }

    with patch.object(
        ida_analyze_util,
        "_load_llm_decompile_target_details_via_mcp",
        AsyncMock(
            return_value=[
                {
                    "func_name": "CEngineServiceMgr__MainLoop",
                    "func_va": "0x180555500",
                    "disasm_code": "call    qword ptr [rax+30h]",
                    "procedure": "loop_type->DeallocateLoopMode();",
                }
            ]
        ),
    ), patch.object(
        ida_analyze_util,
        "call_llm_decompile",
        new_callable=AsyncMock,
        return_value=normalized_payload,
    ) as mock_call_llm_decompile:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/ILoopType_DeallocateLoopMode.windows.yaml"],
            old_yaml_map={},
            new_binary_dir="/tmp",
            platform="windows",
            image_base=0x180000000,
            func_names=["ILoopType_DeallocateLoopMode"],
            func_vtable_relations=[("ILoopType_DeallocateLoopMode", "ILoopType")],
            llm_decompile_specs=[
                (
                    "ILoopType_DeallocateLoopMode",
                    "prompt/call_llm_decompile.md",
                    "references/engine/CEngineServiceMgr_DeactivateLoop.{platform}.yaml",
                ),
                (
                    "ILoopType_DeallocateLoopMode",
                    "prompt/call_llm_decompile.md",
                    "references/engine/CEngineServiceMgr__MainLoop.{platform}.yaml",
                ),
            ],
            llm_config={"model": "gpt-5.4", "fake_as": "codex"},
            generate_yaml_desired_fields=[
                (
                    "ILoopType_DeallocateLoopMode",
                    ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"],
                )
            ],
        )

    self.assertTrue(result)
    self.assertIn(
        "CEngineServiceMgr__MainLoop",
        mock_call_llm_decompile.call_args.kwargs["target_blocks"],
    )
    self.assertNotIn(
        "Target Function: CEngineServiceMgr_DeactivateLoop",
        mock_call_llm_decompile.call_args.kwargs["target_blocks"],
    )
```

```python
async def test_preprocess_common_skill_fails_when_all_llm_targets_are_missing(self) -> None:
    with patch.object(
        ida_analyze_util,
        "_load_llm_decompile_target_details_via_mcp",
        AsyncMock(return_value=[]),
    ), patch.object(
        ida_analyze_util,
        "call_llm_decompile",
        new_callable=AsyncMock,
    ) as mock_call_llm_decompile:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/ILoopType_DeallocateLoopMode.windows.yaml"],
            old_yaml_map={},
            new_binary_dir="/tmp",
            platform="windows",
            image_base=0x180000000,
            func_names=["ILoopType_DeallocateLoopMode"],
            func_vtable_relations=[("ILoopType_DeallocateLoopMode", "ILoopType")],
            llm_decompile_specs=[
                (
                    "ILoopType_DeallocateLoopMode",
                    "prompt/call_llm_decompile.md",
                    "references/engine/CEngineServiceMgr_DeactivateLoop.{platform}.yaml",
                ),
                (
                    "ILoopType_DeallocateLoopMode",
                    "prompt/call_llm_decompile.md",
                    "references/engine/CEngineServiceMgr__MainLoop.{platform}.yaml",
                ),
            ],
            llm_config={"model": "gpt-5.4", "fake_as": "codex"},
            generate_yaml_desired_fields=[
                (
                    "ILoopType_DeallocateLoopMode",
                    ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"],
                )
            ],
        )

    self.assertFalse(result)
    mock_call_llm_decompile.assert_not_awaited()
```

- [ ] **Step 2: 运行这两条测试确认当前实现只支持单 target**

Run: `python -m unittest tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_common_skill_uses_mainloop_target_when_deactivateloop_target_missing tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_common_skill_fails_when_all_llm_targets_are_missing`

Expected: FAIL，当前实现只有 `_load_llm_decompile_target_detail_via_mcp` 单 target 路径。

- [ ] **Step 3: 修改 `ida_analyze_util.py` 与 prompt 模板，支持多 blocks**

```python
def _render_llm_decompile_blocks(reference_items, target_items):
    reference_blocks = "\n\n".join(
        (
            f"### Reference Function: {item['func_name']}\n\n"
            f"**Disassembly for Reference**\n\n```c\n{item['disasm_code']}\n```\n\n"
            f"**Procedure code for Reference**\n\n```c\n{item['procedure']}\n```"
        )
        for item in reference_items
    )
    target_blocks = "\n\n".join(
        (
            f"### Target Function: {item['func_name']}\n\n"
            f"**Disassembly to reverse-engineering**\n\n```c\n{item['disasm_code']}\n```\n\n"
            f"**Procedure code to reverse-engineering**\n\n```c\n{item['procedure']}\n```"
        )
        for item in target_items
    )
    return reference_blocks, target_blocks


async def _load_llm_decompile_target_details_via_mcp(
    session,
    target_func_names,
    new_binary_dir=None,
    platform=None,
    debug=False,
):
    details = []
    for target_func_name in target_func_names:
        detail = await _load_llm_decompile_target_detail_via_mcp(
            session,
            target_func_name,
            new_binary_dir=new_binary_dir,
            platform=platform,
            debug=debug,
        )
        if detail is not None:
            details.append(detail)
    return details
```

```python
async def call_llm_decompile(
    client,
    model,
    symbol_name_list,
    disasm_code,
    procedure,
    disasm_for_reference="",
    procedure_for_reference="",
    prompt_template=None,
    platform=None,
    temperature=None,
    effort=None,
    api_key=None,
    base_url=None,
    fake_as=None,
    debug=False,
    reference_blocks=None,
    target_blocks=None,
):
    if reference_blocks is None:
        reference_blocks = (
            "### Reference Function: Reference\n\n"
            f"**Disassembly for Reference**\n\n```c\n{str(disasm_for_reference or '')}\n```\n\n"
            f"**Procedure code for Reference**\n\n```c\n{str(procedure_for_reference or '')}\n```"
        )
    if target_blocks is None:
        target_blocks = (
            "### Target Function: Target\n\n"
            f"**Disassembly to reverse-engineering**\n\n```c\n{str(disasm_code or '')}\n```\n\n"
            f"**Procedure code to reverse-engineering**\n\n```c\n{str(procedure or '')}\n```"
        )
    prompt = _resolve_llm_decompile_template_value(prompt_template, platform).format(
        symbol_name_list=", ".join(symbol_name_list),
        reference_blocks=reference_blocks,
        target_blocks=target_blocks,
        platform=str(platform or "").strip(),
    )
    request_kwargs = {
        "client": client,
        "model": str(model).strip(),
        "messages": [
            {"role": "system", "content": "You are a reverse engineering expert."},
            {"role": "user", "content": prompt},
        ],
        "debug": debug,
    }
    if temperature is not None:
        request_kwargs["temperature"] = temperature
    if effort is not None:
        request_kwargs["effort"] = effort
    if api_key is not None:
        request_kwargs["api_key"] = api_key
    if base_url is not None:
        request_kwargs["base_url"] = base_url
    if fake_as is not None:
        request_kwargs["fake_as"] = fake_as

    return parse_llm_decompile_response(call_llm_text(**request_kwargs))
```

```md
I have reference functions and target functions that describe the same calling patterns.

These are the reference functions:

{reference_blocks}

These are the functions you need to reverse-engineer:

{target_blocks}

Collect all references to "{symbol_name_list}" across every target function and output YAML.

If nothing is found, output an empty YAML. Do not output anything except the YAML payload.
```

- [ ] **Step 4: 重新运行这两条测试**

Run: `python -m unittest tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_common_skill_uses_mainloop_target_when_deactivateloop_target_missing tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_common_skill_fails_when_all_llm_targets_are_missing`

Expected: PASS

- [ ] **Step 5: 提交这一小步**

```bash
git add ida_analyze_util.py ida_preprocessor_scripts/prompt/call_llm_decompile.md tests/test_ida_analyze_util.py
git commit -m "feat(llm): 支持多 target block 降级"
```

### Task 4: 让 `find-CEngineServiceMgr_DeactivateLoop` 能识别 inline 缺失

**Files:**
- Modify: `ida_preprocessor_scripts/find-CEngineServiceMgr_DeactivateLoop.py`
- Test: `tests/test_ida_preprocessor_scripts.py`

- [ ] **Step 1: 在 `tests/test_ida_preprocessor_scripts.py` 写 `absent_ok` 失败测试**

```python
class TestFindCEngineServiceMgrDeactivateLoop(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_returns_absent_ok_for_verified_inline_sequence(self) -> None:
        module = _load_module(
            Path("ida_preprocessor_scripts/find-CEngineServiceMgr_DeactivateLoop.py"),
            "find_CEngineServiceMgr_DeactivateLoop",
        )

        with patch.object(
            module,
            "preprocess_common_skill",
            AsyncMock(return_value=False),
        ), patch.object(
            module,
            "_load_llm_decompile_target_detail_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "CEngineServiceMgr__MainLoop",
                    "func_va": "0x180555500",
                    "disasm_code": (
                        "call    qword ptr [rax+40h]\n"
                        "call    qword ptr [rax+30h]"
                    ),
                    "procedure": (
                        "loop_type->LoopDeactivate(loop_state);\n"
                        "loop_type->DeallocateLoopMode();"
                    ),
                }
            ),
        ):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={},
                new_binary_dir="bin_dir",
                platform="linux",
                image_base=0x180000000,
                llm_config={"model": "gpt-5.4", "fake_as": "codex"},
                debug=True,
            )

        self.assertEqual("absent_ok", result)
```

```python
    async def test_preprocess_skill_keeps_failure_when_inline_markers_are_incomplete(self) -> None:
        module = _load_module(
            Path("ida_preprocessor_scripts/find-CEngineServiceMgr_DeactivateLoop.py"),
            "find_CEngineServiceMgr_DeactivateLoop",
        )

        with patch.object(
            module,
            "preprocess_common_skill",
            AsyncMock(return_value=False),
        ), patch.object(
            module,
            "_load_llm_decompile_target_detail_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "CEngineServiceMgr__MainLoop",
                    "func_va": "0x180555500",
                    "disasm_code": "call    qword ptr [rax+40h]",
                    "procedure": "loop_type->LoopDeactivate(loop_state);",
                }
            ),
        ):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={},
                new_binary_dir="bin_dir",
                platform="linux",
                image_base=0x180000000,
                llm_config={"model": "gpt-5.4", "fake_as": "codex"},
                debug=True,
            )

        self.assertFalse(result)
```

- [ ] **Step 2: 运行这两条测试确认当前脚本没有 inline 缺失分支**

Run: `pytest tests/test_ida_preprocessor_scripts.py::TestFindCEngineServiceMgrDeactivateLoop::test_preprocess_skill_returns_absent_ok_for_verified_inline_sequence tests/test_ida_preprocessor_scripts.py::TestFindCEngineServiceMgrDeactivateLoop::test_preprocess_skill_keeps_failure_when_inline_markers_are_incomplete -v`

Expected: FAIL，当前脚本只会返回 `True` 或 `False`。

- [ ] **Step 3: 修改 `ida_preprocessor_scripts/find-CEngineServiceMgr_DeactivateLoop.py`，在失败后识别 inline 序列**

```python
from ida_analyze_util import (
    preprocess_common_skill,
    _load_llm_decompile_target_detail_via_mcp,
)

INLINE_SEQUENCE_MARKERS = (
    "LoopDeactivate",
    "DeallocateLoopMode",
)


def _looks_like_inlined_deactivate_loop(detail):
    if not isinstance(detail, dict):
        return False
    joined = "\n".join(
        [
            str(detail.get("disasm_code", "") or ""),
            str(detail.get("procedure", "") or ""),
        ]
    )
    return (
        "CEngineServiceMgr_DeactivateLoop" not in joined
        and all(marker in joined for marker in INLINE_SEQUENCE_MARKERS)
    )


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    if success:
        return True

    mainloop_detail = await _load_llm_decompile_target_detail_via_mcp(
        session,
        "CEngineServiceMgr__MainLoop",
        new_binary_dir=new_binary_dir,
        platform=platform,
        debug=debug,
    )
    if _looks_like_inlined_deactivate_loop(mainloop_detail):
        return "absent_ok"
    return False
```

- [ ] **Step 4: 重新运行这两条测试**

Run: `pytest tests/test_ida_preprocessor_scripts.py::TestFindCEngineServiceMgrDeactivateLoop::test_preprocess_skill_returns_absent_ok_for_verified_inline_sequence tests/test_ida_preprocessor_scripts.py::TestFindCEngineServiceMgrDeactivateLoop::test_preprocess_skill_keeps_failure_when_inline_markers_are_incomplete -v`

Expected: PASS

- [ ] **Step 5: 提交这一小步**

```bash
git add ida_preprocessor_scripts/find-CEngineServiceMgr_DeactivateLoop.py tests/test_ida_preprocessor_scripts.py
git commit -m "fix(engine): 支持 DeactivateLoop 内联缺失"
```

### Task 5: 把 `absent_ok` 贯穿到调度层，并修正排序依赖

**Files:**
- Modify: `ida_skill_preprocessor.py`
- Modify: `ida_analyze_bin.py`
- Modify: `config.yaml`
- Test: `tests/test_ida_analyze_bin.py`

- [ ] **Step 1: 在 `tests/test_ida_analyze_bin.py` 写排序与 `absent_ok` 调度失败测试**

```python
def test_topological_sort_skills_keeps_ilooptype_after_deactivateloop(self) -> None:
    skills = [
        {
            "name": "find-ILoopType_DeallocateLoopMode",
            "expected_output": ["ILoopType_DeallocateLoopMode.{platform}.yaml"],
            "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
            "prerequisite": ["find-CEngineServiceMgr_DeactivateLoop"],
        },
        {
            "name": "find-CEngineServiceMgr_DeactivateLoop",
            "expected_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
            "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
        },
        {
            "name": "find-CEngineServiceMgr__MainLoop",
            "expected_output": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
        },
    ]

    ordered = ida_analyze_bin.topological_sort_skills(skills)

    self.assertLess(
        ordered.index("find-CEngineServiceMgr_DeactivateLoop"),
        ordered.index("find-ILoopType_DeallocateLoopMode"),
    )
```

```python
def test_process_binary_treats_absent_ok_as_skip_and_continues(self) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        binary_dir = Path(temp_dir) / "engine"
        binary_dir.mkdir(parents=True, exist_ok=True)
        (binary_dir / "CEngineServiceMgr__MainLoop.windows.yaml").write_text(
            yaml.safe_dump(
                {
                    "func_name": "CEngineServiceMgr__MainLoop",
                    "func_va": "0x180111000",
                    "func_sig": "40 53",
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        def _fake_preprocess(*, skill_name, expected_outputs, **_kwargs):
            if skill_name == "find-CEngineServiceMgr_DeactivateLoop":
                return "absent_ok"
            output_path = Path(expected_outputs[0])
            output_path.write_text(
                yaml.safe_dump(
                    {
                        "func_name": "ILoopType_DeallocateLoopMode",
                        "vtable_name": "ILoopType",
                        "vfunc_offset": "0x30",
                        "vfunc_index": 6,
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            return "success"

        with patch.object(
            ida_analyze_bin,
            "start_idalib_mcp",
            return_value=object(),
        ), patch.object(
            ida_analyze_bin,
            "ensure_mcp_available",
            side_effect=lambda process, *_args, **_kwargs: (process, True),
        ), patch.object(
            ida_analyze_bin,
            "_run_validate_expected_input_artifacts_via_mcp",
            return_value=[],
        ), patch.object(
            ida_analyze_bin,
            "_run_preprocess_single_skill_via_mcp",
            side_effect=_fake_preprocess,
        ), patch.object(
            ida_analyze_bin,
            "run_skill",
            return_value=False,
        ) as mock_run_skill, patch.object(
            ida_analyze_bin,
            "stop_idalib_mcp",
            return_value=None,
        ):
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path="/tmp/libengine2.so",
                binary_dir=str(binary_dir),
                skills=[
                    {
                        "name": "find-CEngineServiceMgr_DeactivateLoop",
                        "expected_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                        "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                    },
                    {
                        "name": "find-ILoopType_DeallocateLoopMode",
                        "expected_output": ["ILoopType_DeallocateLoopMode.{platform}.yaml"],
                        "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                        "prerequisite": ["find-CEngineServiceMgr_DeactivateLoop"],
                    },
                ],
                old_binary_dir=None,
                platform="windows",
                agent="codex",
                max_retries=1,
                debug=True,
                host="127.0.0.1",
                port=39091,
                ida_args=None,
                llm_model="gpt-5.4",
                llm_apikey=None,
                llm_baseurl=None,
                llm_temperature=None,
                llm_effort="high",
                llm_fake_as="codex",
            )

    self.assertEqual((1, 0, 1), (success, fail, skip))
    mock_run_skill.assert_not_called()
```

- [ ] **Step 2: 运行这两条测试确认当前调度层不理解 `absent_ok`**

Run: `pytest tests/test_ida_analyze_bin.py::TestSkillOrdering::test_topological_sort_skills_keeps_ilooptype_after_deactivateloop tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_treats_absent_ok_as_skip_and_continues -v`

Expected: FAIL，当前预处理返回值仍按 bool 路径处理，字符串 `absent_ok` 会误入成功分支。

- [ ] **Step 3: 修改 `ida_skill_preprocessor.py`、`ida_analyze_bin.py` 和 `config.yaml`**

```python
PREPROCESS_STATUS_SUCCESS = "success"
PREPROCESS_STATUS_FAILED = "failed"
PREPROCESS_STATUS_ABSENT_OK = "absent_ok"


def _normalize_preprocess_status(result):
    if result is True:
        return PREPROCESS_STATUS_SUCCESS
    if result == PREPROCESS_STATUS_ABSENT_OK:
        return PREPROCESS_STATUS_ABSENT_OK
    return PREPROCESS_STATUS_FAILED


async def preprocess_single_skill_via_mcp(
    host,
    port,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    llm_model=None,
    llm_apikey=None,
    llm_baseurl=None,
    llm_temperature=None,
    llm_effort=None,
    llm_fake_as=None,
    debug=False,
):
    result = entry(
        session=session,
        skill_name=skill_name,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        llm_config=llm_config,
        debug=debug,
    )
    if inspect.isawaitable(result):
        result = await result
    return _normalize_preprocess_status(result)
```

```python
preprocess_status = _run_preprocess_single_skill_via_mcp(
    host=host,
    port=port,
    skill_name=skill_name,
    expected_outputs=expected_outputs,
    old_yaml_map=old_yaml_map,
    new_binary_dir=binary_dir,
    platform=platform,
    debug=debug,
    llm_model=llm_model,
    llm_apikey=llm_apikey,
    llm_baseurl=llm_baseurl,
    llm_temperature=llm_temperature,
    llm_effort=llm_effort,
    llm_fake_as=llm_fake_as,
)

if preprocess_status == "success":
    missing_outputs = [p for p in expected_outputs if not os.path.exists(p)]
    if missing_outputs:
        fail_count += 1
        print(f"  Pre-processed but missing expected_output: {skill_name} ({', '.join(os.path.basename(p) for p in missing_outputs)})")
    else:
        success_count += 1
        print(f"  Pre-processed: {skill_name}")
    continue

if preprocess_status == "absent_ok":
    skip_count += 1
    print(f"  Skipping skill: {skill_name} (preprocess reported absent_ok)")
    continue
```

```yaml
      - name: find-ILoopType_DeallocateLoopMode
        expected_output:
          - ILoopType_DeallocateLoopMode.{platform}.yaml
        expected_input:
          - CEngineServiceMgr__MainLoop.{platform}.yaml
        prerequisite:
          - find-CEngineServiceMgr_DeactivateLoop
```

- [ ] **Step 4: 重新运行这两条测试**

Run: `pytest tests/test_ida_analyze_bin.py::TestSkillOrdering::test_topological_sort_skills_keeps_ilooptype_after_deactivateloop tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_treats_absent_ok_as_skip_and_continues -v`

Expected: PASS

- [ ] **Step 5: 提交这一小步**

```bash
git add ida_skill_preprocessor.py ida_analyze_bin.py config.yaml tests/test_ida_analyze_bin.py
git commit -m "fix(schedule): 处理 absent_ok 并固定排序"
```

### Task 6: 跑定向回归并收尾

**Files:**
- Modify: `docs/superpowers/specs/2026-04-21-ilooptype-deallocateloopmode-inline-fallback-design.md`（仅当实现与规格出现必须同步的命名修正时）
- Test: `tests/test_ida_preprocessor_scripts.py`
- Test: `tests/test_ida_analyze_util.py`
- Test: `tests/test_ida_analyze_bin.py`

- [ ] **Step 1: 跑脚本层回归**

Run: `pytest tests/test_ida_preprocessor_scripts.py::TestFindILoopTypeDeallocateLoopMode::test_preprocess_skill_forwards_two_llm_specs_in_fixed_order tests/test_ida_preprocessor_scripts.py::TestFindCEngineServiceMgrDeactivateLoop::test_preprocess_skill_returns_absent_ok_for_verified_inline_sequence tests/test_ida_preprocessor_scripts.py::TestFindCEngineServiceMgrDeactivateLoop::test_preprocess_skill_keeps_failure_when_inline_markers_are_incomplete -v`

Expected: 3 passed

- [ ] **Step 2: 跑 LLM bundle 回归**

Run: `python -m unittest tests.test_ida_analyze_util.TestLlmDecompileSupport.test_build_llm_decompile_specs_map_groups_duplicate_symbol_names tests.test_ida_analyze_util.TestLlmDecompileSupport.test_build_llm_decompile_specs_map_rejects_mixed_prompt_paths tests.test_ida_analyze_util.TestLlmDecompileSupport.test_prepare_llm_decompile_request_collects_multiple_references tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_common_skill_uses_mainloop_target_when_deactivateloop_target_missing tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_common_skill_fails_when_all_llm_targets_are_missing`

Expected: 5 passed

- [ ] **Step 3: 跑调度层回归**

Run: `pytest tests/test_ida_analyze_bin.py::TestSkillOrdering::test_topological_sort_skills_keeps_ilooptype_after_deactivateloop tests/test_ida_analyze_bin.py::TestProcessBinary::test_process_binary_treats_absent_ok_as_skip_and_continues -v`

Expected: 2 passed

- [ ] **Step 4: 若实现命名与 spec 不一致，补齐规格文档**

```md
- 若三态常量名最终不是 `success` / `absent_ok` / `failed`，把规格文档中对应术语一次性统一为实现名称。
- 若 prompt 占位符最终命名不是 `reference_blocks` / `target_blocks`，同步更新规格里的示例与术语。
```

- [ ] **Step 5: 提交收尾**

```bash
git add tests/test_ida_preprocessor_scripts.py tests/test_ida_analyze_util.py tests/test_ida_analyze_bin.py ida_preprocessor_scripts ida_analyze_util.py ida_skill_preprocessor.py ida_analyze_bin.py config.yaml docs/superpowers/specs/2026-04-21-ilooptype-deallocateloopmode-inline-fallback-design.md
git commit -m "fix(engine): 完成 ILoopType 内联降级"
```

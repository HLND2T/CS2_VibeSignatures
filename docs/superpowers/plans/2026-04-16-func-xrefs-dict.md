# FUNC_XREFS Dict Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将统一 `FUNC_XREFS` 协议从 tuple 全仓迁移为 `dict`，并为 `preprocess_func_xrefs_via_mcp()` 增加 `xref_gvs`、`exclude_gvs`、`exclude_signatures`，最终让 `CCSPlayer_MovementServices_ProcessMovement` 能通过 `CPlayer_MovementServices_s_pRunCommandPawn` 的 gv xref 回退定位。

**Architecture:** 先在 `tests/test_ida_analyze_util.py` 写出 dict 契约、gv xref 和局部签名排除的失败用例，再在 `ida_analyze_util.py` 中补最小 helper 与统一过滤流程。随后补脚本转发测试，显式接入 `find-CCSPlayer_MovementServices_ProcessMovement-AND-CCSPlayer_MovementServices_CheckMovingGround.py`，最后用一次性 codemod 将现有 107 个 `FUNC_XREFS*` 脚本迁移为 `dict` 并做静态回归检查。

**Tech Stack:** Python 3、unittest.mock、PyYAML、IDA MCP `py_eval` / `find_bytes`、`ast`、`py_compile`

---

## File Structure

- Modify: `ida_analyze_util.py`
  - 将统一 `func_xrefs` schema 改为 `dict`
  - 新增 gv YAML 地址读取与候选函数内局部 signature 检查 helper
  - 扩展 `preprocess_func_xrefs_via_mcp()`、`_try_preprocess_func_without_llm()`、`_can_probe_future_func_fast_path()`
- Modify: `tests/test_ida_analyze_util.py`
  - 增加 gv xref、gv exclude、局部 `exclude_signatures`、dict schema 校验的回归测试
- Modify: `tests/test_ida_preprocessor_scripts.py`
  - 将现有 `CNetworkServerService_Init` tuple 预期改为 dict
  - 新增 `ProcessMovement` 脚本接入测试
- Modify: `ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement-AND-CCSPlayer_MovementServices_CheckMovingGround.py`
  - 新增 `FUNC_XREFS` dict 配置，并将 `ProcessMovement` 接到 `xref_gvs`
- Modify: 现有 107 个声明 `FUNC_XREFS*` 的脚本
  - 通过一次性 codemod 从 6 tuple 迁移到 9-key dict
  - 精确目标文件列表见 Task 3 的 `TARGET_FILES`
- Memory: `preprocess_common_skill_func_xrefs`
  - 更新为 dict schema、gv xref 和局部 `exclude_signatures` 语义

## 关键实现约束

- `func_xrefs` 只接受 `dict`，旧 tuple 一律视为非法配置
- 允许字段仅限：
  - `func_name`
  - `xref_strings`
  - `xref_gvs`
  - `xref_signatures`
  - `xref_funcs`
  - `exclude_funcs`
  - `exclude_strings`
  - `exclude_gvs`
  - `exclude_signatures`
- 正向来源必须至少一个非空：`xref_strings` / `xref_gvs` / `xref_signatures` / `xref_funcs`
- 全局排除顺序固定：`exclude_funcs`、`exclude_strings`、`exclude_gvs`
- `exclude_signatures` 只允许在经过全局排除后的候选函数体内部检查，禁止退回“全二进制搜 signature 再反推函数”的旧思路

### Task 1: 用回归测试锁定 dict 契约与 gv/signature 语义

**Files:**
- Modify: `tests/test_ida_analyze_util.py`
- Modify: `ida_analyze_util.py`

- [ ] **Step 1: 在 `tests/test_ida_analyze_util.py` 中写出失败用例**

把下面 6 个测试方法追加到 `tests/test_ida_analyze_util.py` 的 `TestFuncXrefsSignatureSupport` 类中，并顺手把现有仍依赖 tuple 的 4 个旧夹具一起改掉：

- `test_preprocess_common_skill_rejects_legacy_five_item_func_xrefs` 改成泛化的 tuple 拒绝用例
- `test_preprocess_common_skill_rejects_empty_positive_xref_sources` 改成 dict fixture
- `test_preprocess_common_skill_llm_batch_uses_xref_resolved_symbol_to_shrink_request` 改成 dict fixture
- `test_preprocess_common_skill_llm_batch_issues_second_request_for_symbol_not_covered_in_first_batch` 改成 dict fixture

```python
    async def test_preprocess_func_xrefs_intersects_string_and_gv_sets(self) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180100000, 0x180200000}),
        ) as mock_collect_string, patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_ea",
            AsyncMock(return_value={0x180200000}),
        ) as mock_collect_ea, patch.object(
            ida_analyze_util,
            "_read_yaml_file",
            return_value={"gv_va": "0x180300000"},
        ) as mock_read_yaml, patch.object(
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
                func_name="CCSPlayer_MovementServices_ProcessMovement",
                xref_strings=["Networking"],
                xref_gvs=["CPlayer_MovementServices_s_pRunCommandPawn"],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertEqual("CCSPlayer_MovementServices_ProcessMovement", result["func_name"])
        self.assertEqual("0x180200000", result["func_va"])
        mock_collect_string.assert_awaited_once_with(
            session="session",
            xref_string="Networking",
            debug=True,
        )
        self.assertTrue(
            str(mock_read_yaml.call_args.args[0]).endswith(
                "CPlayer_MovementServices_s_pRunCommandPawn.windows.yaml"
            )
        )
        mock_collect_ea.assert_awaited_once_with(
            session="session",
            target_ea=0x180300000,
            debug=True,
        )
        mock_gen_sig.assert_awaited_once()

    async def test_preprocess_func_xrefs_exclude_gvs_subtracts_candidate_set(self) -> None:
        def fake_read_yaml(path):
            path = str(path)
            if path.endswith("IncludeGV.windows.yaml"):
                return {"gv_va": "0x180300000"}
            if path.endswith("ExcludeGV.windows.yaml"):
                return {"gv_va": "0x180400000"}
            return None

        async def fake_collect_xref_func_starts_for_ea(*, target_ea, **_kwargs):
            if target_ea == 0x180300000:
                return {0x180111000, 0x180222000}
            if target_ea == 0x180400000:
                return {0x180111000}
            return set()

        with patch.object(
            ida_analyze_util,
            "_read_yaml_file",
            side_effect=fake_read_yaml,
        ), patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_ea",
            AsyncMock(side_effect=fake_collect_xref_func_starts_for_ea),
        ), patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180222000",
                    "func_rva": "0x222000",
                    "func_size": "0x50",
                    "func_sig": "40 53 48 83 EC 20",
                }
            ),
        ):
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="TargetFunc",
                xref_strings=[],
                xref_gvs=["IncludeGV"],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=["ExcludeGV"],
                exclude_signatures=[],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertEqual("0x180222000", result["func_va"])

    async def test_preprocess_func_xrefs_exclude_signatures_only_checks_remaining_candidates(self) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180111000, 0x180222000}),
        ), patch.object(
            ida_analyze_util,
            "_read_yaml_file",
            return_value={"func_va": "0x180111000"},
        ), patch.object(
            ida_analyze_util,
            "_func_contains_signature_via_mcp",
            AsyncMock(side_effect=[True]),
        ) as mock_contains_sig, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(return_value=None),
        ), patch.object(
            ida_analyze_util,
            "_get_func_basic_info_via_mcp",
            AsyncMock(return_value=None),
        ):
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="TargetFunc",
                xref_strings=["OnlyPositiveSource"],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=["AlreadyExcludedFunc"],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=["48 8B ?? ?? 89"],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertIsNone(result)
        mock_contains_sig.assert_awaited_once_with(
            session="session",
            func_va=0x180222000,
            signature="48 8B ?? ?? 89",
            debug=True,
        )

    async def test_preprocess_common_skill_forwards_dict_func_xrefs_fields(self) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(return_value=None),
        ), patch.object(
            ida_analyze_util,
            "preprocess_func_xrefs_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "LoggingChannel_Init",
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_func_xrefs, patch.object(
            ida_analyze_util,
            "write_func_yaml",
        ) as mock_write_func_yaml, patch.object(
            ida_analyze_util,
            "_rename_func_in_ida",
            AsyncMock(return_value=None),
        ):
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
                        "xref_gvs": ["CPlayer_MovementServices_s_pRunCommandPawn"],
                        "xref_signatures": ["C7 44 24 40 64 FF FF FF"],
                        "xref_funcs": [],
                        "exclude_funcs": ["CNetworkServerService_Init"],
                        "exclude_strings": ["FULLMATCH:Other Players"],
                        "exclude_gvs": ["ExcludeGV"],
                        "exclude_signatures": ["48 8B ?? ?? 89"],
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

        self.assertTrue(result)
        self.assertEqual(
            ["CPlayer_MovementServices_s_pRunCommandPawn"],
            mock_func_xrefs.call_args.kwargs["xref_gvs"],
        )
        self.assertEqual(
            ["ExcludeGV"],
            mock_func_xrefs.call_args.kwargs["exclude_gvs"],
        )
        self.assertEqual(
            ["48 8B ?? ?? 89"],
            mock_func_xrefs.call_args.kwargs["exclude_signatures"],
        )
        mock_write_func_yaml.assert_called_once()

    async def test_preprocess_common_skill_rejects_tuple_func_xrefs(self) -> None:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/LoggingChannel_Init.windows.yaml"],
            old_yaml_map={},
            new_binary_dir="/tmp",
            platform="windows",
            image_base=0x180000000,
            func_names=["LoggingChannel_Init"],
            func_xrefs=[
                (
                    "LoggingChannel_Init",
                    ["Networking"],
                    [],
                    [],
                    [],
                    [],
                )
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

    async def test_preprocess_common_skill_rejects_unknown_func_xrefs_key(self) -> None:
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
                    "unexpected_key": ["oops"],
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

把现有两个 LLM batch 测试里的 `func_xrefs=[(...)]` fixture 统一改成下面的 dict 形态：

```python
                    func_xrefs=[
                        {
                            "func_name": second_func_name,
                            "xref_strings": ["dummy-string"],
                            "xref_gvs": [],
                            "xref_signatures": [],
                            "xref_funcs": [first_func_name],
                            "exclude_funcs": [],
                            "exclude_strings": [],
                            "exclude_gvs": [],
                            "exclude_signatures": [],
                        },
                    ],
```

把 `test_preprocess_common_skill_rejects_empty_positive_xref_sources` 里的空正向源 fixture 改成 dict，但保持“应返回 `False`”的断言不变：

```python
            func_xrefs=[
                {
                    "func_name": "LoggingChannel_Init",
                    "xref_strings": [],
                    "xref_gvs": [],
                    "xref_signatures": [],
                    "xref_funcs": [],
                    "exclude_funcs": [],
                    "exclude_strings": [],
                    "exclude_gvs": [],
                    "exclude_signatures": [],
                }
            ],
```

- [ ] **Step 2: 运行新增用例，确认它们先失败**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_func_xrefs_intersects_string_and_gv_sets \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_func_xrefs_exclude_gvs_subtracts_candidate_set \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_func_xrefs_exclude_signatures_only_checks_remaining_candidates \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_common_skill_forwards_dict_func_xrefs_fields \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_common_skill_rejects_tuple_func_xrefs \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_common_skill_rejects_unknown_func_xrefs_key \
  -v
```

Expected: FAIL，至少出现以下一种：
- `TypeError: preprocess_func_xrefs_via_mcp() got an unexpected keyword argument 'xref_gvs'`
- `AssertionError`，因为 `func_xrefs` 还没按 dict 解析
- `AttributeError`，因为 `_func_contains_signature_via_mcp` 还不存在

- [ ] **Step 3: 在 `ida_analyze_util.py` 中实现最小通过代码**

先加两个小 helper，避免继续把逻辑堆进 `preprocess_func_xrefs_via_mcp()`：

```python
def _load_symbol_addr_from_current_yaml(
    new_binary_dir,
    platform,
    symbol_name,
    field_name,
    *,
    debug=False,
    debug_label="dependency",
):
    yaml_path = os.path.join(
        os.fspath(new_binary_dir),
        f"{symbol_name}.{platform}.yaml",
    )
    yaml_data = _read_yaml_file(yaml_path)
    if not isinstance(yaml_data, dict):
        if debug:
            print(
                f"    Preprocess: {debug_label} YAML missing or invalid: "
                f"{os.path.basename(yaml_path)}"
            )
        return None
    try:
        return _parse_int_value(yaml_data.get(field_name))
    except Exception:
        if debug:
            print(
                f"    Preprocess: invalid {field_name} in {debug_label} YAML: "
                f"{os.path.basename(yaml_path)}"
            )
        return None


async def _func_contains_signature_via_mcp(
    session,
    func_va,
    signature,
    debug=False,
):
    try:
        func_va_int = _parse_int_value(func_va)
    except Exception:
        return False

    py_code = (
        "import idaapi, ida_search, json\n"
        f"target_ea = {func_va_int}\n"
        f"pattern = {json.dumps(signature)}\n"
        "func = idaapi.get_func(target_ea)\n"
        "if not func or func.start_ea != target_ea:\n"
        "    result = json.dumps(None)\n"
        "else:\n"
        "    match_ea = ida_search.find_binary(\n"
        "        func.start_ea,\n"
        "        func.end_ea,\n"
        "        pattern,\n"
        "        16,\n"
        "        ida_search.SEARCH_DOWN,\n"
        "    )\n"
        "    result = json.dumps(match_ea != idaapi.BADADDR)\n"
    )
    try:
        eval_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        eval_data = parse_mcp_result(eval_result)
    except Exception as exc:
        if debug:
            print(f"    Preprocess: py_eval error for local signature search: {exc}")
        return False

    if not isinstance(eval_data, dict):
        return False
    result_text = eval_data.get("result", "")
    if not result_text:
        return False
    try:
        parsed = json.loads(result_text)
    except (TypeError, json.JSONDecodeError):
        return False
    return bool(parsed)
```

把 `preprocess_func_xrefs_via_mcp()` 签名改成：

```python
async def preprocess_func_xrefs_via_mcp(
    session,
    func_name,
    xref_strings,
    xref_gvs,
    xref_signatures,
    xref_funcs,
    exclude_funcs,
    exclude_strings,
    exclude_gvs,
    exclude_signatures,
    new_binary_dir,
    platform,
    image_base,
    vtable_class=None,
    allow_func_sig_across_function_boundary=False,
    debug=False,
):
```

把内部候选和排除阶段改成下面的顺序：

```python
    dependency_func_names = list(xref_funcs or []) + list(exclude_funcs or [])
    dependency_gv_names = list(xref_gvs or []) + list(exclude_gvs or [])
    if dependency_func_names or dependency_gv_names or vtable_class:
        if not new_binary_dir:
            if debug:
                print(
                    f"    Preprocess: new_binary_dir is required for "
                    f"func_xrefs dependencies of {func_name}"
                )
            return None
        try:
            new_binary_dir = os.fspath(new_binary_dir)
        except Exception:
            if debug:
                print(
                    f"    Preprocess: invalid new_binary_dir for "
                    f"func_xrefs dependencies of {func_name}"
                )
            return None

    candidate_sets = []

    for xref_string in (xref_strings or []):
        addr_set = await _collect_xref_func_starts_for_string(
            session=session,
            xref_string=xref_string,
            debug=debug,
        )
        if addr_set is None or not addr_set:
            return None
        candidate_sets.append(addr_set)

    for gv_name in (xref_gvs or []):
        gv_va = _load_symbol_addr_from_current_yaml(
            new_binary_dir,
            platform,
            gv_name,
            "gv_va",
            debug=debug,
            debug_label="xref gv",
        )
        if gv_va is None:
            return None
        addr_set = await _collect_xref_func_starts_for_ea(
            session=session,
            target_ea=gv_va,
            debug=debug,
        )
        if not addr_set:
            return None
        candidate_sets.append(addr_set)

    for xref_signature in (xref_signatures or []):
        addr_set = await _collect_xref_func_starts_for_signature(
            session=session,
            xref_signature=xref_signature,
            debug=debug,
        )
        if not addr_set:
            return None
        candidate_sets.append(addr_set)

    for dep_func_name in (xref_funcs or []):
        dep_func_va = _load_symbol_addr_from_current_yaml(
            new_binary_dir,
            platform,
            dep_func_name,
            "func_va",
            debug=debug,
            debug_label="dependency func",
        )
        if dep_func_va is None:
            return None
        addr_set = await _collect_xref_func_starts_for_ea(
            session=session,
            target_ea=dep_func_va,
            debug=debug,
        )
        if not addr_set:
            return None
        candidate_sets.append(addr_set)

    if not candidate_sets:
        if debug:
            print(
                f"    Preprocess: no xref candidate sources configured for {func_name}"
            )
        return None

    common_funcs = set(candidate_sets[0])
    for addr_set in candidate_sets[1:]:
        common_funcs &= addr_set

    excluded_func_addrs = set()
    for excluded_func_name in (exclude_funcs or []):
        excluded_func_va = _load_symbol_addr_from_current_yaml(
            new_binary_dir,
            platform,
            excluded_func_name,
            "func_va",
            debug=debug,
            debug_label="excluded func",
        )
        if excluded_func_va is None:
            return None
        excluded_func_addrs.add(excluded_func_va)

    excluded_string_func_addrs = set()
    for excluded_string in (exclude_strings or []):
        addr_set = await _collect_xref_func_starts_for_string(
            session=session,
            xref_string=excluded_string,
            debug=debug,
        )
        if addr_set is None:
            return None
        excluded_string_func_addrs |= set(addr_set)

    excluded_gv_func_addrs = set()
    for excluded_gv_name in (exclude_gvs or []):
        excluded_gv_va = _load_symbol_addr_from_current_yaml(
            new_binary_dir,
            platform,
            excluded_gv_name,
            "gv_va",
            debug=debug,
            debug_label="excluded gv",
        )
        if excluded_gv_va is None:
            return None
        addr_set = await _collect_xref_func_starts_for_ea(
            session=session,
            target_ea=excluded_gv_va,
            debug=debug,
        )
        if addr_set is None:
            return None
        excluded_gv_func_addrs |= set(addr_set)

    common_funcs -= excluded_func_addrs
    common_funcs -= excluded_string_func_addrs
    common_funcs -= excluded_gv_func_addrs

    if exclude_signatures:
        filtered_funcs = set()
        for candidate_func_va in sorted(common_funcs):
            has_excluded_signature = False
            for excluded_signature in exclude_signatures:
                if await _func_contains_signature_via_mcp(
                    session=session,
                    func_va=candidate_func_va,
                    signature=excluded_signature,
                    debug=debug,
                ):
                    has_excluded_signature = True
                    break
            if not has_excluded_signature:
                filtered_funcs.add(candidate_func_va)
        common_funcs = filtered_funcs
```

把 `preprocess_common_skill()` 的 `func_xrefs` 解析替换成 dict-only：

```python
    allowed_func_xrefs_keys = {
        "func_name",
        "xref_strings",
        "xref_gvs",
        "xref_signatures",
        "xref_funcs",
        "exclude_funcs",
        "exclude_strings",
        "exclude_gvs",
        "exclude_signatures",
    }

    func_xrefs_map = {}
    for spec in func_xrefs:
        if not isinstance(spec, dict):
            if debug:
                print(f"    Preprocess: invalid func_xrefs spec: {spec}")
            return False

        unknown_keys = set(spec) - allowed_func_xrefs_keys
        if unknown_keys:
            if debug:
                print(
                    f"    Preprocess: unknown func_xrefs keys: {sorted(unknown_keys)}"
                )
            return False

        func_name = spec.get("func_name")
        if not isinstance(func_name, str) or not func_name:
            if debug:
                print(f"    Preprocess: invalid func_xrefs target: {func_name}")
            return False

        if func_name in func_xrefs_map:
            if debug:
                print(f"    Preprocess: duplicated func_xrefs target: {func_name}")
            return False

        normalized_spec = {
            "xref_strings": list(spec.get("xref_strings") or []),
            "xref_gvs": list(spec.get("xref_gvs") or []),
            "xref_signatures": list(spec.get("xref_signatures") or []),
            "xref_funcs": list(spec.get("xref_funcs") or []),
            "exclude_funcs": list(spec.get("exclude_funcs") or []),
            "exclude_strings": list(spec.get("exclude_strings") or []),
            "exclude_gvs": list(spec.get("exclude_gvs") or []),
            "exclude_signatures": list(spec.get("exclude_signatures") or []),
        }

        for key, value in normalized_spec.items():
            if any(not isinstance(item, str) or not item for item in value):
                if debug:
                    print(f"    Preprocess: invalid {key} values for {func_name}")
                return False

        if not (
            normalized_spec["xref_strings"]
            or normalized_spec["xref_gvs"]
            or normalized_spec["xref_signatures"]
            or normalized_spec["xref_funcs"]
        ):
            if debug:
                print(f"    Preprocess: empty func_xrefs spec for {func_name}")
            return False

        func_xrefs_map[func_name] = normalized_spec
```

把 `_try_preprocess_func_without_llm()` 的透传更新为：

```python
        func_data = await preprocess_func_xrefs_via_mcp(
            session=session,
            func_name=func_name,
            xref_strings=xref_spec["xref_strings"],
            xref_gvs=xref_spec["xref_gvs"],
            xref_signatures=xref_spec["xref_signatures"],
            xref_funcs=xref_spec["xref_funcs"],
            exclude_funcs=xref_spec["exclude_funcs"],
            exclude_strings=xref_spec["exclude_strings"],
            exclude_gvs=xref_spec["exclude_gvs"],
            exclude_signatures=xref_spec["exclude_signatures"],
            new_binary_dir=new_binary_dir,
            platform=platform,
            image_base=image_base,
            vtable_class=xref_vtable_class,
            allow_func_sig_across_function_boundary=allow_func_sig_across_function_boundary,
            debug=debug,
        )
```

把 `_can_probe_future_func_fast_path()` 的依赖检查升级为同时覆盖 `xref_gvs` / `exclude_gvs`：

```python
    dependency_symbol_names = (
        list(xref_spec.get("xref_funcs") or [])
        + list(xref_spec.get("exclude_funcs") or [])
        + list(xref_spec.get("xref_gvs") or [])
        + list(xref_spec.get("exclude_gvs") or [])
    )
```

- [ ] **Step 4: 重新运行 Task 1 的测试，确认全部通过**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_func_xrefs_intersects_string_and_gv_sets \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_func_xrefs_exclude_gvs_subtracts_candidate_set \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_func_xrefs_exclude_signatures_only_checks_remaining_candidates \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_common_skill_forwards_dict_func_xrefs_fields \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_common_skill_rejects_tuple_func_xrefs \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_preprocess_common_skill_rejects_unknown_func_xrefs_key \
  -v
```

Expected: `OK`

- [ ] **Step 5: 提交核心契约与测试**

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "feat(func-xrefs): 支持 dict 协议与 gv 约束"
```

### Task 2: 补脚本转发测试并接入 `ProcessMovement`

**Files:**
- Modify: `tests/test_ida_preprocessor_scripts.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkServerService_Init.py`
- Modify: `ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement-AND-CCSPlayer_MovementServices_CheckMovingGround.py`

- [ ] **Step 1: 在 `tests/test_ida_preprocessor_scripts.py` 中写出脚本侧失败用例**

把现有 `TestFindCNetworkServerServiceInit.test_script_forwards_six_tuple_func_xrefs()` 改成 dict 预期，并新增一个 `ProcessMovement` 用例：

```python
PROCESS_MOVEMENT_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CCSPlayer_MovementServices_ProcessMovement-AND-"
    "CCSPlayer_MovementServices_CheckMovingGround.py"
)


class TestFindCNetworkServerServiceInit(unittest.IsolatedAsyncioTestCase):
    async def test_script_forwards_dict_func_xrefs(self) -> None:
        module = _load_module(
            CNETWORK_SERVER_SERVICE_INIT_SCRIPT_PATH,
            "find_CNetworkServerService_Init",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_func_xrefs = [
            {
                "func_name": "CNetworkServerService_Init",
                "xref_strings": [
                    "ServerToClient",
                    "Entities",
                    "Local Player",
                    "Other Players",
                ],
                "xref_gvs": [],
                "xref_signatures": [],
                "xref_funcs": [],
                "exclude_funcs": [],
                "exclude_strings": [],
                "exclude_gvs": [],
                "exclude_signatures": [],
            }
        ]
        expected_func_vtable_relations = [
            ("CNetworkServerService_Init", "CNetworkServerService")
        ]

        with patch.object(module, "preprocess_common_skill", mock_preprocess_common_skill):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        self.assertEqual(
            expected_func_xrefs,
            mock_preprocess_common_skill.await_args.kwargs["func_xrefs"],
        )
        self.assertEqual(
            expected_func_vtable_relations,
            mock_preprocess_common_skill.await_args.kwargs["func_vtable_relations"],
        )


class TestFindCcsPlayerMovementServicesProcessMovement(
    unittest.IsolatedAsyncioTestCase
):
    async def test_script_forwards_gv_backed_func_xrefs(self) -> None:
        module = _load_module(
            PROCESS_MOVEMENT_SCRIPT_PATH,
            "find_CCSPlayer_MovementServices_ProcessMovement_AND_CheckMovingGround",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_func_xrefs = [
            {
                "func_name": "CCSPlayer_MovementServices_ProcessMovement",
                "xref_strings": [],
                "xref_gvs": ["CPlayer_MovementServices_s_pRunCommandPawn"],
                "xref_signatures": [],
                "xref_funcs": [],
                "exclude_funcs": [],
                "exclude_strings": [],
                "exclude_gvs": [],
                "exclude_signatures": [],
            }
        ]

        with patch.object(module, "preprocess_common_skill", mock_preprocess_common_skill):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        self.assertEqual(
            expected_func_xrefs,
            mock_preprocess_common_skill.await_args.kwargs["func_xrefs"],
        )
        self.assertEqual(
            [
                "CCSPlayer_MovementServices_ProcessMovement",
                "CCSPlayer_MovementServices_CheckMovingGround",
            ],
            mock_preprocess_common_skill.await_args.kwargs["func_names"],
        )
```

- [ ] **Step 2: 运行脚本测试，确认它们先失败**

Run:

```bash
python -m unittest \
  tests.test_ida_preprocessor_scripts.TestFindCNetworkServerServiceInit.test_script_forwards_dict_func_xrefs \
  tests.test_ida_preprocessor_scripts.TestFindCcsPlayerMovementServicesProcessMovement.test_script_forwards_gv_backed_func_xrefs \
  -v
```

Expected: FAIL，因为现有脚本仍在传 tuple，且 `ProcessMovement` 脚本还没有 `FUNC_XREFS`。

- [ ] **Step 3: 更新两个脚本到新协议**

把 `ida_preprocessor_scripts/find-CNetworkServerService_Init.py` 的 `FUNC_XREFS` 改成：

```python
FUNC_XREFS = [
    {
        "func_name": "CNetworkServerService_Init",
        "xref_strings": [
            "ServerToClient",
            "Entities",
            "Local Player",
            "Other Players",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]
```

把 `ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement-AND-CCSPlayer_MovementServices_CheckMovingGround.py` 改成：

```python
TARGET_FUNCTION_NAMES = [
    "CCSPlayer_MovementServices_ProcessMovement",
    "CCSPlayer_MovementServices_CheckMovingGround",
]

FUNC_XREFS = [
    {
        "func_name": "CCSPlayer_MovementServices_ProcessMovement",
        "xref_strings": [],
        "xref_gvs": ["CPlayer_MovementServices_s_pRunCommandPawn"],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

...

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

- [ ] **Step 4: 重新运行脚本测试，确认它们通过**

Run:

```bash
python -m unittest \
  tests.test_ida_preprocessor_scripts.TestFindCNetworkServerServiceInit.test_script_forwards_dict_func_xrefs \
  tests.test_ida_preprocessor_scripts.TestFindCcsPlayerMovementServicesProcessMovement.test_script_forwards_gv_backed_func_xrefs \
  -v
```

Expected: `OK`

- [ ] **Step 5: 提交脚本接入改动**

```bash
git add \
  tests/test_ida_preprocessor_scripts.py \
  ida_preprocessor_scripts/find-CNetworkServerService_Init.py \
  ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement-AND-CCSPlayer_MovementServices_CheckMovingGround.py
git commit -m "feat(func-xrefs): 接入 ProcessMovement 的 gv 回退"
```

### Task 3: 用 codemod 全仓迁移现有 `FUNC_XREFS*` 脚本

**Files:**
- Modify: `ida_preprocessor_scripts/find-CBaseCombatCharacter_OnKilled.py`
- Modify: `ida_preprocessor_scripts/find-CBaseEntity_SetStateChanged.py`
- Modify: `ida_preprocessor_scripts/find-CBaseEntity_Spawn.py`
- Modify: `ida_preprocessor_scripts/find-CBaseEntity_SpawnRadius.py`
- Modify: `ida_preprocessor_scripts/find-CBaseEntity_TakeDamageOld.py`
- Modify: `ida_preprocessor_scripts/find-CBasePlayerController_HandleCommand_JoinTeam.py`
- Modify: `ida_preprocessor_scripts/find-CBasePlayerController_ProcessUsercmds.py`
- Modify: `ida_preprocessor_scripts/find-CBtActionCoordinatedBuy_Update.py`
- Modify: `ida_preprocessor_scripts/find-CCSBotManager_AddBot.py`
- Modify: `ida_preprocessor_scripts/find-CCSBotManager_BotPlaceCommand.py`
- Modify: `ida_preprocessor_scripts/find-CCSBot_Upkeep.py`
- Modify: `ida_preprocessor_scripts/find-CCSGameRules_BeginRound.py`
- Modify: `ida_preprocessor_scripts/find-CCSGameRules_GoToIntermission.py`
- Modify: `ida_preprocessor_scripts/find-CCSGameRules_TerminateRound.py`
- Modify: `ida_preprocessor_scripts/find-CCSPlayerController_ChangeTeam.py`
- Modify: `ida_preprocessor_scripts/find-CCSPlayerController_RegisterThink.py`
- Modify: `ida_preprocessor_scripts/find-CCSPlayerController_SwitchTeam.py`
- Modify: `ida_preprocessor_scripts/find-CCSPlayerPawnBase_PostThink.py`
- Modify: `ida_preprocessor_scripts/find-CCSPlayer_ItemServices_GiveDefaultItems.py`
- Modify: `ida_preprocessor_scripts/find-CCSPlayer_MovementServices_CheckJumpButton.py`
- Modify: `ida_preprocessor_scripts/find-CCSPlayer_UseServices_OnUse.py`
- Modify: `ida_preprocessor_scripts/find-CCSPlayer_UseServices_OnUseImpl.py`
- Modify: `ida_preprocessor_scripts/find-CCSPlayer_WeaponServices_PickupItem.py`
- Modify: `ida_preprocessor_scripts/find-CDemoRecorder_ParseMessage.py`
- Modify: `ida_preprocessor_scripts/find-CDemoRecorder_WriteSpawnGroups.py`
- Modify: `ida_preprocessor_scripts/find-CEntityInstance_Precache.py`
- Modify: `ida_preprocessor_scripts/find-CEntitySystem_Activate.py`
- Modify: `ida_preprocessor_scripts/find-CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName.py`
- Modify: `ida_preprocessor_scripts/find-CGameResourceService_BuildResourceManifest.py`
- Modify: `ida_preprocessor_scripts/find-CGameRules_ClientSettingsChanged.py`
- Modify: `ida_preprocessor_scripts/find-CGameSceneNode_PostSpawnKeyValues.py`
- Modify: `ida_preprocessor_scripts/find-CLoopModeGame_LoopShutdown-linux.py`
- Modify: `ida_preprocessor_scripts/find-CLoopModeGame_LoopShutdown-windows.py`
- Modify: `ida_preprocessor_scripts/find-CLoopModeGame_ReceivedServerInfo.py`
- Modify: `ida_preprocessor_scripts/find-CLoopModeGame_RegisterEventMap.py`
- Modify: `ida_preprocessor_scripts/find-CLoopModeGame_RegisterEventMapInternal-client.py`
- Modify: `ida_preprocessor_scripts/find-CLoopModeGame_SetGameSystemState.py`
- Modify: `ida_preprocessor_scripts/find-CLoopModeGame_SetWorldSession.py`
- Modify: `ida_preprocessor_scripts/find-CLoopModeGame_Shutdown-linux.py`
- Modify: `ida_preprocessor_scripts/find-CLoopTypeClientServerService_OnLoopActivate.py`
- Modify: `ida_preprocessor_scripts/find-CLoopTypeClientServer_BuildAndActivateLoopTypes.py`
- Modify: `ida_preprocessor_scripts/find-CNavMesh_GetNearestNavArea.py`
- Modify: `ida_preprocessor_scripts/find-CNetChan_ParseMessagesDemo.py`
- Modify: `ida_preprocessor_scripts/find-CNetChan_ParseMessagesDemoInternal.py`
- Modify: `ida_preprocessor_scripts/find-CNetChan_ProcessMessages.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkGameClient_ProcessPacketEntities-linux.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkGameClient_ProcessPacketEntities-windows.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkGameClient_ProcessPacketEntitiesInternal-windows.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkGameClient_RecordEntityBandwidth.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkGameClient_SendMove.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkGameClient_SendMovePacket.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_AssociateNetMessageGroupIdWithChannelCategory.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_AssociateNetMessageWithChannelCategoryAbstract.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_ComputeOrderForPriority.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_ConfirmAllMessageHandlersInstalled.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_DeallocateNetMessageAbstract.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_FindNetworkMessage.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_FindOrCreateNetMessage.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_RegisterFieldChangeCallbackPriority.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkArrayFieldSerializer.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkCategory.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkFieldChangeCallbackInternal.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkFieldSerializer.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_SerializeInternal.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_SerializeMessageInternal.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_UnserializeFromStream.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkMessages_UnserializeMessageInternal.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkServerService_Init.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkSystem_SendNetworkStats.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkTransmitComponent_StateChanged.py`
- Modify: `ida_preprocessor_scripts/find-CNetworkUtlVectorEmbedded_NetworkStateChanged_m_vecRenderAttributes.py`
- Modify: `ida_preprocessor_scripts/find-CPhysicsEntitySolver_PhysEnableEntityCollisions.py`
- Modify: `ida_preprocessor_scripts/find-CPhysicsGameSystem_ProcessContactEvents.py`
- Modify: `ida_preprocessor_scripts/find-CPlayer_MovementServices_ForceButtonState.py`
- Modify: `ida_preprocessor_scripts/find-CPlayer_MovementServices_ForceButtons.py`
- Modify: `ida_preprocessor_scripts/find-CPlayer_MovementServices_PlayWaterStepSound.py`
- Modify: `ida_preprocessor_scripts/find-CPointTeleport_Teleport.py`
- Modify: `ida_preprocessor_scripts/find-CSceneEntity_GetScriptDesc.py`
- Modify: `ida_preprocessor_scripts/find-CSource2Client_OnDisconnect.py`
- Modify: `ida_preprocessor_scripts/find-CSource2GameClients_ClientDisconnect.py`
- Modify: `ida_preprocessor_scripts/find-CSource2GameClients_StartHLTVServer.py`
- Modify: `ida_preprocessor_scripts/find-CSource2GameEntities_CheckTransmit.py`
- Modify: `ida_preprocessor_scripts/find-CSource2Server_Init.py`
- Modify: `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown.py`
- Modify: `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupPrecache.py`
- Modify: `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupShutdown.py`
- Modify: `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal.py`
- Modify: `ida_preprocessor_scripts/find-CSteamworksGameStats_OnReceivedSessionID.py`
- Modify: `ida_preprocessor_scripts/find-CTakeDamageInfo_GetWeaponName.py`
- Modify: `ida_preprocessor_scripts/find-FindUseEntity.py`
- Modify: `ida_preprocessor_scripts/find-FireBulletImpactEvent.py`
- Modify: `ida_preprocessor_scripts/find-FireBullets.py`
- Modify: `ida_preprocessor_scripts/find-GameSystem_Think_CheckSteamBan.py`
- Modify: `ida_preprocessor_scripts/find-GetCSceneEntityScriptDesc.py`
- Modify: `ida_preprocessor_scripts/find-GiveNamedItem.py`
- Modify: `ida_preprocessor_scripts/find-Host_Say.py`
- Modify: `ida_preprocessor_scripts/find-IGameSystem_InitAllSystems.py`
- Modify: `ida_preprocessor_scripts/find-NetworkStateChanged.py`
- Modify: `ida_preprocessor_scripts/find-PhysEnableEntityCollisions-linux.py`
- Modify: `ida_preprocessor_scripts/find-PhysEnableEntityCollisions-windows.py`
- Modify: `ida_preprocessor_scripts/find-RegisterSchemaTypeOverride_CEntityHandle.py`
- Modify: `ida_preprocessor_scripts/find-ScriptBinding_CSPlayerPawn_DestroyWeapon.py`
- Modify: `ida_preprocessor_scripts/find-TraceAttack-linux.py`
- Modify: `ida_preprocessor_scripts/find-TraceAttack-windows.py`
- Modify: `ida_preprocessor_scripts/find-TraceShape.py`
- Modify: `ida_preprocessor_scripts/find-WeaponBuy.py`

- [ ] **Step 1: 先写一个静态失败探针，确认仓库里还有 tuple**

Run:

```bash
python - <<'PY'
import ast
from pathlib import Path

TARGET_FILES = [
    "ida_preprocessor_scripts/find-CBaseCombatCharacter_OnKilled.py",
    "ida_preprocessor_scripts/find-CBaseEntity_SetStateChanged.py",
    "ida_preprocessor_scripts/find-CBaseEntity_Spawn.py",
    "ida_preprocessor_scripts/find-CBaseEntity_SpawnRadius.py",
    "ida_preprocessor_scripts/find-CBaseEntity_TakeDamageOld.py",
    "ida_preprocessor_scripts/find-CBasePlayerController_HandleCommand_JoinTeam.py",
    "ida_preprocessor_scripts/find-CBasePlayerController_ProcessUsercmds.py",
    "ida_preprocessor_scripts/find-CBtActionCoordinatedBuy_Update.py",
    "ida_preprocessor_scripts/find-CCSBotManager_AddBot.py",
    "ida_preprocessor_scripts/find-CCSBotManager_BotPlaceCommand.py",
    "ida_preprocessor_scripts/find-CCSBot_Upkeep.py",
    "ida_preprocessor_scripts/find-CCSGameRules_BeginRound.py",
    "ida_preprocessor_scripts/find-CCSGameRules_GoToIntermission.py",
    "ida_preprocessor_scripts/find-CCSGameRules_TerminateRound.py",
    "ida_preprocessor_scripts/find-CCSPlayerController_ChangeTeam.py",
    "ida_preprocessor_scripts/find-CCSPlayerController_RegisterThink.py",
    "ida_preprocessor_scripts/find-CCSPlayerController_SwitchTeam.py",
    "ida_preprocessor_scripts/find-CCSPlayerPawnBase_PostThink.py",
    "ida_preprocessor_scripts/find-CCSPlayer_ItemServices_GiveDefaultItems.py",
    "ida_preprocessor_scripts/find-CCSPlayer_MovementServices_CheckJumpButton.py",
    "ida_preprocessor_scripts/find-CCSPlayer_UseServices_OnUse.py",
    "ida_preprocessor_scripts/find-CCSPlayer_UseServices_OnUseImpl.py",
    "ida_preprocessor_scripts/find-CCSPlayer_WeaponServices_PickupItem.py",
    "ida_preprocessor_scripts/find-CDemoRecorder_ParseMessage.py",
    "ida_preprocessor_scripts/find-CDemoRecorder_WriteSpawnGroups.py",
    "ida_preprocessor_scripts/find-CEntityInstance_Precache.py",
    "ida_preprocessor_scripts/find-CEntitySystem_Activate.py",
    "ida_preprocessor_scripts/find-CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName.py",
    "ida_preprocessor_scripts/find-CGameResourceService_BuildResourceManifest.py",
    "ida_preprocessor_scripts/find-CGameRules_ClientSettingsChanged.py",
    "ida_preprocessor_scripts/find-CGameSceneNode_PostSpawnKeyValues.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_LoopShutdown-linux.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_LoopShutdown-windows.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_ReceivedServerInfo.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_RegisterEventMap.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_RegisterEventMapInternal-client.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_SetGameSystemState.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_SetWorldSession.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_Shutdown-linux.py",
    "ida_preprocessor_scripts/find-CLoopTypeClientServerService_OnLoopActivate.py",
    "ida_preprocessor_scripts/find-CLoopTypeClientServer_BuildAndActivateLoopTypes.py",
    "ida_preprocessor_scripts/find-CNavMesh_GetNearestNavArea.py",
    "ida_preprocessor_scripts/find-CNetChan_ParseMessagesDemo.py",
    "ida_preprocessor_scripts/find-CNetChan_ParseMessagesDemoInternal.py",
    "ida_preprocessor_scripts/find-CNetChan_ProcessMessages.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_ProcessPacketEntities-linux.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_ProcessPacketEntities-windows.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_ProcessPacketEntitiesInternal-windows.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_RecordEntityBandwidth.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_SendMove.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_SendMovePacket.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_AssociateNetMessageGroupIdWithChannelCategory.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_AssociateNetMessageWithChannelCategoryAbstract.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_ComputeOrderForPriority.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_ConfirmAllMessageHandlersInstalled.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_DeallocateNetMessageAbstract.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_FindNetworkMessage.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_FindOrCreateNetMessage.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_RegisterFieldChangeCallbackPriority.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkArrayFieldSerializer.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkCategory.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkFieldChangeCallbackInternal.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkFieldSerializer.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_SerializeInternal.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_SerializeMessageInternal.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_UnserializeFromStream.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_UnserializeMessageInternal.py",
    "ida_preprocessor_scripts/find-CNetworkServerService_Init.py",
    "ida_preprocessor_scripts/find-CNetworkSystem_SendNetworkStats.py",
    "ida_preprocessor_scripts/find-CNetworkTransmitComponent_StateChanged.py",
    "ida_preprocessor_scripts/find-CNetworkUtlVectorEmbedded_NetworkStateChanged_m_vecRenderAttributes.py",
    "ida_preprocessor_scripts/find-CPhysicsEntitySolver_PhysEnableEntityCollisions.py",
    "ida_preprocessor_scripts/find-CPhysicsGameSystem_ProcessContactEvents.py",
    "ida_preprocessor_scripts/find-CPlayer_MovementServices_ForceButtonState.py",
    "ida_preprocessor_scripts/find-CPlayer_MovementServices_ForceButtons.py",
    "ida_preprocessor_scripts/find-CPlayer_MovementServices_PlayWaterStepSound.py",
    "ida_preprocessor_scripts/find-CPointTeleport_Teleport.py",
    "ida_preprocessor_scripts/find-CSceneEntity_GetScriptDesc.py",
    "ida_preprocessor_scripts/find-CSource2Client_OnDisconnect.py",
    "ida_preprocessor_scripts/find-CSource2GameClients_ClientDisconnect.py",
    "ida_preprocessor_scripts/find-CSource2GameClients_StartHLTVServer.py",
    "ida_preprocessor_scripts/find-CSource2GameEntities_CheckTransmit.py",
    "ida_preprocessor_scripts/find-CSource2Server_Init.py",
    "ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown.py",
    "ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupPrecache.py",
    "ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupShutdown.py",
    "ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal.py",
    "ida_preprocessor_scripts/find-CSteamworksGameStats_OnReceivedSessionID.py",
    "ida_preprocessor_scripts/find-CTakeDamageInfo_GetWeaponName.py",
    "ida_preprocessor_scripts/find-FindUseEntity.py",
    "ida_preprocessor_scripts/find-FireBulletImpactEvent.py",
    "ida_preprocessor_scripts/find-FireBullets.py",
    "ida_preprocessor_scripts/find-GameSystem_Think_CheckSteamBan.py",
    "ida_preprocessor_scripts/find-GetCSceneEntityScriptDesc.py",
    "ida_preprocessor_scripts/find-GiveNamedItem.py",
    "ida_preprocessor_scripts/find-Host_Say.py",
    "ida_preprocessor_scripts/find-IGameSystem_InitAllSystems.py",
    "ida_preprocessor_scripts/find-NetworkStateChanged.py",
    "ida_preprocessor_scripts/find-PhysEnableEntityCollisions-linux.py",
    "ida_preprocessor_scripts/find-PhysEnableEntityCollisions-windows.py",
    "ida_preprocessor_scripts/find-RegisterSchemaTypeOverride_CEntityHandle.py",
    "ida_preprocessor_scripts/find-ScriptBinding_CSPlayerPawn_DestroyWeapon.py",
    "ida_preprocessor_scripts/find-TraceAttack-linux.py",
    "ida_preprocessor_scripts/find-TraceAttack-windows.py",
    "ida_preprocessor_scripts/find-TraceShape.py",
    "ida_preprocessor_scripts/find-WeaponBuy.py",
]
ALLOWED_KEYS = {
    "func_name",
    "xref_strings",
    "xref_gvs",
    "xref_signatures",
    "xref_funcs",
    "exclude_funcs",
    "exclude_strings",
    "exclude_gvs",
    "exclude_signatures",
}

bad = []
for path_str in TARGET_FILES:
    path = Path(path_str)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.startswith("FUNC_XREFS"):
                value = ast.literal_eval(node.value)
                if not isinstance(value, list):
                    bad.append((path_str, target.id, "not-list"))
                    continue
                for index, item in enumerate(value):
                    if not isinstance(item, dict):
                        bad.append((path_str, target.id, f"entry-{index}-not-dict"))
                        continue
                    unknown = sorted(set(item) - ALLOWED_KEYS)
                    if unknown:
                        bad.append((path_str, target.id, f"entry-{index}-unknown-{unknown}"))

if bad:
    raise SystemExit(f"bad func_xrefs schema: {bad[:5]}")
PY
```

Expected: FAIL，并报告至少一个 `entry-0-not-dict`。

- [ ] **Step 2: 运行一次性 codemod，把 6 tuple 迁移成 9-key dict**

Run:

```bash
python - <<'PY'
import ast
from pathlib import Path

TARGET_FILES = [
    "ida_preprocessor_scripts/find-CBaseCombatCharacter_OnKilled.py",
    "ida_preprocessor_scripts/find-CBaseEntity_SetStateChanged.py",
    "ida_preprocessor_scripts/find-CBaseEntity_Spawn.py",
    "ida_preprocessor_scripts/find-CBaseEntity_SpawnRadius.py",
    "ida_preprocessor_scripts/find-CBaseEntity_TakeDamageOld.py",
    "ida_preprocessor_scripts/find-CBasePlayerController_HandleCommand_JoinTeam.py",
    "ida_preprocessor_scripts/find-CBasePlayerController_ProcessUsercmds.py",
    "ida_preprocessor_scripts/find-CBtActionCoordinatedBuy_Update.py",
    "ida_preprocessor_scripts/find-CCSBotManager_AddBot.py",
    "ida_preprocessor_scripts/find-CCSBotManager_BotPlaceCommand.py",
    "ida_preprocessor_scripts/find-CCSBot_Upkeep.py",
    "ida_preprocessor_scripts/find-CCSGameRules_BeginRound.py",
    "ida_preprocessor_scripts/find-CCSGameRules_GoToIntermission.py",
    "ida_preprocessor_scripts/find-CCSGameRules_TerminateRound.py",
    "ida_preprocessor_scripts/find-CCSPlayerController_ChangeTeam.py",
    "ida_preprocessor_scripts/find-CCSPlayerController_RegisterThink.py",
    "ida_preprocessor_scripts/find-CCSPlayerController_SwitchTeam.py",
    "ida_preprocessor_scripts/find-CCSPlayerPawnBase_PostThink.py",
    "ida_preprocessor_scripts/find-CCSPlayer_ItemServices_GiveDefaultItems.py",
    "ida_preprocessor_scripts/find-CCSPlayer_MovementServices_CheckJumpButton.py",
    "ida_preprocessor_scripts/find-CCSPlayer_UseServices_OnUse.py",
    "ida_preprocessor_scripts/find-CCSPlayer_UseServices_OnUseImpl.py",
    "ida_preprocessor_scripts/find-CCSPlayer_WeaponServices_PickupItem.py",
    "ida_preprocessor_scripts/find-CDemoRecorder_ParseMessage.py",
    "ida_preprocessor_scripts/find-CDemoRecorder_WriteSpawnGroups.py",
    "ida_preprocessor_scripts/find-CEntityInstance_Precache.py",
    "ida_preprocessor_scripts/find-CEntitySystem_Activate.py",
    "ida_preprocessor_scripts/find-CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName.py",
    "ida_preprocessor_scripts/find-CGameResourceService_BuildResourceManifest.py",
    "ida_preprocessor_scripts/find-CGameRules_ClientSettingsChanged.py",
    "ida_preprocessor_scripts/find-CGameSceneNode_PostSpawnKeyValues.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_LoopShutdown-linux.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_LoopShutdown-windows.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_ReceivedServerInfo.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_RegisterEventMap.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_RegisterEventMapInternal-client.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_SetGameSystemState.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_SetWorldSession.py",
    "ida_preprocessor_scripts/find-CLoopModeGame_Shutdown-linux.py",
    "ida_preprocessor_scripts/find-CLoopTypeClientServerService_OnLoopActivate.py",
    "ida_preprocessor_scripts/find-CLoopTypeClientServer_BuildAndActivateLoopTypes.py",
    "ida_preprocessor_scripts/find-CNavMesh_GetNearestNavArea.py",
    "ida_preprocessor_scripts/find-CNetChan_ParseMessagesDemo.py",
    "ida_preprocessor_scripts/find-CNetChan_ParseMessagesDemoInternal.py",
    "ida_preprocessor_scripts/find-CNetChan_ProcessMessages.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_ProcessPacketEntities-linux.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_ProcessPacketEntities-windows.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_ProcessPacketEntitiesInternal-windows.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_RecordEntityBandwidth.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_SendMove.py",
    "ida_preprocessor_scripts/find-CNetworkGameClient_SendMovePacket.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_AssociateNetMessageGroupIdWithChannelCategory.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_AssociateNetMessageWithChannelCategoryAbstract.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_ComputeOrderForPriority.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_ConfirmAllMessageHandlersInstalled.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_DeallocateNetMessageAbstract.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_FindNetworkMessage.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_FindOrCreateNetMessage.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_RegisterFieldChangeCallbackPriority.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkArrayFieldSerializer.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkCategory.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkFieldChangeCallbackInternal.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_RegisterNetworkFieldSerializer.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_SerializeInternal.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_SerializeMessageInternal.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_UnserializeFromStream.py",
    "ida_preprocessor_scripts/find-CNetworkMessages_UnserializeMessageInternal.py",
    "ida_preprocessor_scripts/find-CNetworkServerService_Init.py",
    "ida_preprocessor_scripts/find-CNetworkSystem_SendNetworkStats.py",
    "ida_preprocessor_scripts/find-CNetworkTransmitComponent_StateChanged.py",
    "ida_preprocessor_scripts/find-CNetworkUtlVectorEmbedded_NetworkStateChanged_m_vecRenderAttributes.py",
    "ida_preprocessor_scripts/find-CPhysicsEntitySolver_PhysEnableEntityCollisions.py",
    "ida_preprocessor_scripts/find-CPhysicsGameSystem_ProcessContactEvents.py",
    "ida_preprocessor_scripts/find-CPlayer_MovementServices_ForceButtonState.py",
    "ida_preprocessor_scripts/find-CPlayer_MovementServices_ForceButtons.py",
    "ida_preprocessor_scripts/find-CPlayer_MovementServices_PlayWaterStepSound.py",
    "ida_preprocessor_scripts/find-CPointTeleport_Teleport.py",
    "ida_preprocessor_scripts/find-CSceneEntity_GetScriptDesc.py",
    "ida_preprocessor_scripts/find-CSource2Client_OnDisconnect.py",
    "ida_preprocessor_scripts/find-CSource2GameClients_ClientDisconnect.py",
    "ida_preprocessor_scripts/find-CSource2GameClients_StartHLTVServer.py",
    "ida_preprocessor_scripts/find-CSource2GameEntities_CheckTransmit.py",
    "ida_preprocessor_scripts/find-CSource2Server_Init.py",
    "ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown.py",
    "ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupPrecache.py",
    "ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupShutdown.py",
    "ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal.py",
    "ida_preprocessor_scripts/find-CSteamworksGameStats_OnReceivedSessionID.py",
    "ida_preprocessor_scripts/find-CTakeDamageInfo_GetWeaponName.py",
    "ida_preprocessor_scripts/find-FindUseEntity.py",
    "ida_preprocessor_scripts/find-FireBulletImpactEvent.py",
    "ida_preprocessor_scripts/find-FireBullets.py",
    "ida_preprocessor_scripts/find-GameSystem_Think_CheckSteamBan.py",
    "ida_preprocessor_scripts/find-GetCSceneEntityScriptDesc.py",
    "ida_preprocessor_scripts/find-GiveNamedItem.py",
    "ida_preprocessor_scripts/find-Host_Say.py",
    "ida_preprocessor_scripts/find-IGameSystem_InitAllSystems.py",
    "ida_preprocessor_scripts/find-NetworkStateChanged.py",
    "ida_preprocessor_scripts/find-PhysEnableEntityCollisions-linux.py",
    "ida_preprocessor_scripts/find-PhysEnableEntityCollisions-windows.py",
    "ida_preprocessor_scripts/find-RegisterSchemaTypeOverride_CEntityHandle.py",
    "ida_preprocessor_scripts/find-ScriptBinding_CSPlayerPawn_DestroyWeapon.py",
    "ida_preprocessor_scripts/find-TraceAttack-linux.py",
    "ida_preprocessor_scripts/find-TraceAttack-windows.py",
    "ida_preprocessor_scripts/find-TraceShape.py",
    "ida_preprocessor_scripts/find-WeaponBuy.py",
]
TARGET_NAMES = {"FUNC_XREFS", "FUNC_XREFS_WINDOWS", "FUNC_XREFS_LINUX"}
NEW_KEYS = [
    "func_name",
    "xref_strings",
    "xref_gvs",
    "xref_signatures",
    "xref_funcs",
    "exclude_funcs",
    "exclude_strings",
    "exclude_gvs",
    "exclude_signatures",
]
OLD_KEYS = [
    "func_name",
    "xref_strings",
    "xref_signatures",
    "xref_funcs",
    "exclude_funcs",
    "exclude_strings",
]


def normalize_entry(item):
    if isinstance(item, dict):
        entry = {key: list(item.get(key) or []) for key in NEW_KEYS if key != "func_name"}
        entry["func_name"] = item.get("func_name")
    else:
        values = list(item)
        if len(values) != 6:
            raise ValueError(f"expected 6-item tuple, got {values!r}")
        entry = {
            "func_name": values[0],
            "xref_strings": list(values[1] or []),
            "xref_gvs": [],
            "xref_signatures": list(values[2] or []),
            "xref_funcs": list(values[3] or []),
            "exclude_funcs": list(values[4] or []),
            "exclude_strings": list(values[5] or []),
            "exclude_gvs": [],
            "exclude_signatures": [],
        }
    return entry


def render_entries(entries, indent):
    lines = ["["]
    for entry in entries:
        lines.append(f"{indent}{{")
        lines.append(f'{indent}    "func_name": {entry["func_name"]!r},')
        for key in NEW_KEYS[1:]:
            lines.append(f'{indent}    "{key}": {entry[key]!r},')
        lines.append(f"{indent}}},")
    lines.append(f"{indent[:-4]}]")
    return "\n".join(lines)

for path_str in TARGET_FILES:
    path = Path(path_str)
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(path))
    replacements = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id in TARGET_NAMES for target in node.targets):
            continue
        value = ast.literal_eval(node.value)
        normalized = [normalize_entry(item) for item in value]
        indent = " " * node.value.col_offset
        rendered = render_entries(normalized, indent + "    ")
        start = node.value.lineno - 1
        end = node.value.end_lineno - 1
        replacements.append((start, end, rendered))

    if not replacements:
        continue

    lines = text.splitlines()
    for start, end, rendered in sorted(replacements, reverse=True):
        lines[start : end + 1] = rendered.splitlines()
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
```

Expected: 命令成功退出，不报 `ValueError`。

- [ ] **Step 3: 跑静态 schema 探针和 `py_compile`，确认迁移结果稳定**

Run:

```bash
python - <<'PY'
import ast
import py_compile
from pathlib import Path

TARGET_FILES = sorted(
    str(path)
    for path in Path("ida_preprocessor_scripts").glob("*.py")
)
ALLOWED_KEYS = {
    "func_name",
    "xref_strings",
    "xref_gvs",
    "xref_signatures",
    "xref_funcs",
    "exclude_funcs",
    "exclude_strings",
    "exclude_gvs",
    "exclude_signatures",
}

for path_str in TARGET_FILES:
    path = Path(path_str)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.startswith("FUNC_XREFS"):
                value = ast.literal_eval(node.value)
                assert isinstance(value, list), (path_str, target.id, "not-list")
                for item in value:
                    assert isinstance(item, dict), (path_str, target.id, item)
                    assert set(item) <= ALLOWED_KEYS, (path_str, target.id, set(item) - ALLOWED_KEYS)
                    assert item.get("func_name"), (path_str, target.id, item)
                    assert any(
                        item.get(key)
                        for key in ("xref_strings", "xref_gvs", "xref_signatures", "xref_funcs")
                    ), (path_str, target.id, item)

for path_str in [
    "ida_analyze_util.py",
    "tests/test_ida_analyze_util.py",
    "tests/test_ida_preprocessor_scripts.py",
] + TARGET_FILES:
    py_compile.compile(path_str, doraise=True)

print("static func_xrefs migration OK")
PY
```

Expected: 输出 `static func_xrefs migration OK`

- [ ] **Step 4: 提交全仓脚本迁移**

```bash
git add ida_preprocessor_scripts tests/test_ida_preprocessor_scripts.py
git commit -m "refactor(func-xrefs): 迁移脚本配置为 dict"
```

### Task 4: 更新 Serena memory 并做最终定向回归

**Files:**
- Memory: `preprocess_common_skill_func_xrefs`
- Modify: `ida_analyze_util.py`
- Modify: `tests/test_ida_analyze_util.py`
- Modify: `tests/test_ida_preprocessor_scripts.py`
- Modify: `ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement-AND-CCSPlayer_MovementServices_CheckMovingGround.py`

- [ ] **Step 1: 用最终语义更新 Serena memory**

把 `preprocess_common_skill_func_xrefs` memory 改成下面内容：

```markdown
# preprocess_common_skill func_xrefs

## Summary
- `preprocess_common_skill` 只接受 `dict` 风格 `func_xrefs`
- 允许字段固定为：
  - `func_name`
  - `xref_strings`
  - `xref_gvs`
  - `xref_signatures`
  - `xref_funcs`
  - `exclude_funcs`
  - `exclude_strings`
  - `exclude_gvs`
  - `exclude_signatures`
- 正向源 `xref_strings` / `xref_gvs` / `xref_signatures` / `xref_funcs` 不能同时为空

## Contract
- 旧 tuple schema 不再支持，命中后直接视为非法配置
- `exclude_strings` 与 `exclude_gvs` 是全局排除集合：在正向交集后做差集
- `exclude_signatures` 只在剩余候选函数内部检查，命中即排除该候选函数
- `exclude_strings`、`exclude_gvs` 无命中时不视为失败，只视为空排除集

## Operational notes
- `xref_gvs` / `exclude_gvs` 依赖对应 YAML 的 `gv_va`
- `xref_funcs` / `exclude_funcs` 依赖对应 YAML 的 `func_va`
- `_can_probe_future_func_fast_path` 需要同时检查 func/gv 依赖 YAML 是否已存在
- `CCSPlayer_MovementServices_ProcessMovement` 使用 `CPlayer_MovementServices_s_pRunCommandPawn` 作为 gv xref 回退源
```

- [ ] **Step 2: 运行最终定向回归**

Run:

```bash
python -m unittest tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport -v
python -m unittest tests.test_ida_preprocessor_scripts.TestFindCNetworkServerServiceInit -v
python -m unittest tests.test_ida_preprocessor_scripts.TestFindCcsPlayerMovementServicesProcessMovement -v
python - <<'PY'
from pathlib import Path
text = Path(
    "ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement-AND-CCSPlayer_MovementServices_CheckMovingGround.py"
).read_text(encoding="utf-8")
assert '"xref_gvs": ["CPlayer_MovementServices_s_pRunCommandPawn"]' in text
print("process movement gv fallback OK")
PY
```

Expected:
- 三条 `unittest` 命令均输出 `OK`
- 最后一条脚本输出 `process movement gv fallback OK`

- [ ] **Step 3: 确认工作树干净并准备进入执行阶段**

Run:

```bash
git status --short
```

Expected: 没有遗漏的未跟踪临时文件；若仍有代码改动未提交，先补一次提交再执行后续实现流程。

# IDA Analyze Bin Post Process Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `ida_analyze_bin.py` 增加 module/platform 级 `post_process` 阶段，在 `-rename` 开启时统一读取当前 module/platform 的有效 expected output YAML，并对 IDA 数据库执行 rename 与注释写入。

**Architecture:** 保持默认路径为空操作：`rename=False` 时不改变现有 skip 与 IDA 启动行为。`rename=True` 时先按当前 module/platform 的拓扑排序收集有效 YAML mapping，再把 YAML 转成 function rename、data rename、signature comment 三类动作，最后在 IDA 生命周期结束前通过 MCP best-effort 执行。

**Tech Stack:** Python 3、`unittest`、`unittest.mock`、`yaml.safe_load`、IDA Pro MCP tools (`rename`、`py_eval`、`find_bytes`、`set_comments`)

**Status Update (2026-04-28):** 当前分支已完成 Task 1 到 Task 6，并已通过 post_process 定向回归与 `tests.test_ida_analyze_bin` 整模块回归。

**Execution Note:** 运行本计划中的 `unittest` 命令时，应使用仓库虚拟环境解释器，而不是系统 Python；本环境下使用 `.venv/bin/python -m unittest ...`，否则可能因缺少 `python-dotenv` 等依赖导致假性失败。

**Boundary Note:** Task 4 负责动作聚合和 MCP best-effort 执行；Task 5 负责锁定 `process_binary(...)` 的 post_process failure 统计与 `main()` wiring。不要在 Task 4 提前扩展 `fail_count` 语义，也不要在 Task 5 回退 Task 4 的 action-level best-effort 设计。

---

## File Structure

- Modify: `ida_analyze_bin.py`
  - `parse_args()` 增加 `-rename`
  - `main()` 将 `args.rename` 传入 `process_binary(...)`
  - `process_binary(...)` 增加 `rename=False`，在 IDA 生命周期内接入 post_process
  - 新增 YAML 收集 helper、动作构建 helper、MCP 执行 helper
  - 更新 `should_start_binary_processing(...)` 支持 post_process 启动条件
- Modify: `tests/test_ida_analyze_bin.py`
  - 增加 CLI 解析、main wiring、pipeline 启动条件、post_process action 分派、MCP 执行与失败语义测试
- Modify: `docs/superpowers/plans/2026-04-28-ida-analyze-bin-post-process.md`
  - 当前实现计划

## Repository Constraints

- 本计划只实现 `docs/superpowers/specs/2026-04-28-ida-analyze-bin-post-process-design.md` 定义的 `post_process`，不迁移现有 preprocessing 的即时 rename。
- `rename=False` 必须保持现有行为：所有 expected output 已存在时不启动 IDA，不调用 post_process。
- `rename=True` 只遍历当前 module/platform 的 `expected_output`，不处理 `skip_if_exists` 中的额外 artifacts。
- post_process YAML 收集必须额外约束在当前 `binary_dir` 边界内；即使 `resolve_artifact_path(...)` 允许落在更宽的 gamever 根目录，也不能跨 module 读取其他产物。
- post_process 为 best-effort：单个 YAML、单个 rename、单个 comment 失败不阻断后续动作。
- `-rename` 相关的预收集/重收集若发生不可恢复异常，只增加一次 post_process failure，不得让 `process_binary(...)` 直接抛异常，也不得影响无关 skill/vcall 统计。
- 提交消息遵循仓库约定：`<type>(scope): <中文动词开头摘要>`。

### Task 1: Lock CLI And Pipeline Entry Behavior

**Files:**
- Modify: `tests/test_ida_analyze_bin.py`
- Reference: `ida_analyze_bin.py:876`
- Reference: `ida_analyze_bin.py:1618`

- [ ] **Step 1: Add parse_args coverage for default `rename=False`**

在 `tests/test_ida_analyze_bin.py` 的 `TestParseArgsLlmOptions` 中追加：

```python
    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_defaults_rename_to_false(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertFalse(args.rename)
```

- [ ] **Step 2: Add parse_args coverage for `-rename`**

在同一个 class 中追加：

```python
    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_accepts_rename(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-rename",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertTrue(args.rename)
```

- [ ] **Step 3: Add default no-op process test**

在 `TestProcessBinary` 中追加：

```python
    def test_process_binary_does_not_start_ida_for_post_process_when_rename_is_false(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")
            (binary_dir / "CEntFireOutputAutoCompletionFunctor_FireOutput.windows.yaml").write_text(
                "func_name: CEntFireOutputAutoCompletionFunctor_FireOutput\n"
                "func_va: '0x180c165c0'\n",
                encoding="utf-8",
            )

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp") as mock_start_ida,
                patch.object(
                    ida_analyze_bin,
                    "_run_post_process_expected_outputs_via_mcp",
                    create=True,
                ) as mock_post_process,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                            "expected_output": [
                                "CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"
                            ],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                )

        self.assertEqual((0, 0, 1), (success, fail, skip))
        mock_start_ida.assert_not_called()
        mock_post_process.assert_not_called()
```

- [ ] **Step 4: Add skip-then-post-process startup test**

在 `TestProcessBinary` 中追加：

```python
    def test_process_binary_runs_post_process_when_rename_true_and_outputs_exist(
        self,
    ) -> None:
        fake_process = object()

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")
            output_path = binary_dir / "CEntFireOutputAutoCompletionFunctor_FireOutput.windows.yaml"
            output_path.write_text(
                "func_name: CEntFireOutputAutoCompletionFunctor_FireOutput\n"
                "func_va: '0x180c165c0'\n",
                encoding="utf-8",
            )

            with (
                patch.object(
                    ida_analyze_bin,
                    "start_idalib_mcp",
                    return_value=fake_process,
                ) as mock_start_ida,
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_post_process_expected_outputs_via_mcp",
                    return_value=True,
                    create=True,
                ) as mock_post_process,
                patch.object(
                    ida_analyze_bin,
                    "quit_ida_gracefully",
                    return_value=None,
                ) as mock_quit_ida,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                            "expected_output": [
                                "CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"
                            ],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                    rename=True,
                )

        self.assertEqual((0, 0, 1), (success, fail, skip))
        mock_start_ida.assert_called_once_with(binary_path, "127.0.0.1", 13337, "", False)
        mock_post_process.assert_called_once()
        mock_quit_ida.assert_called_once_with(fake_process, "127.0.0.1", 13337, debug=False)
```

- [ ] **Step 5: Run the new entry tests and verify failure before implementation**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_bin.TestParseArgsLlmOptions.test_parse_args_defaults_rename_to_false \
  tests.test_ida_analyze_bin.TestParseArgsLlmOptions.test_parse_args_accepts_rename \
  tests.test_ida_analyze_bin.TestProcessBinary.test_process_binary_does_not_start_ida_for_post_process_when_rename_is_false \
  tests.test_ida_analyze_bin.TestProcessBinary.test_process_binary_runs_post_process_when_rename_true_and_outputs_exist \
  -v
```

Expected:

```text
FAIL: test_parse_args_accepts_rename
```

The command is expected to fail overall because `parse_args()` does not define `-rename` and `process_binary(...)` does not accept `rename` yet. The `rename=False` skip-path test may already pass before implementation; that is acceptable for this task.

- [ ] **Step 6: Commit the failing entry tests**

```bash
git add tests/test_ida_analyze_bin.py
git commit -m "test(ida): 增加 post_process 入口回归"
```

### Task 2: Wire CLI, Main, And IDA Startup Condition

**Files:**
- Modify: `ida_analyze_bin.py:876`
- Modify: `ida_analyze_bin.py:1258`
- Modify: `ida_analyze_bin.py:1618`
- Modify: `ida_analyze_bin.py:1923`
- Test: `tests/test_ida_analyze_bin.py`

- [ ] **Step 1: Add `-rename` to parse_args**

在 `parse_args()` 的 `-debug` 参数之后插入：

```python
    parser.add_argument(
        "-rename",
        action="store_true",
        help="Run post_process rename/comment pass for existing expected output YAML files",
    )
```

- [ ] **Step 2: Update `should_start_binary_processing(...)`**

替换现有函数：

```python
def should_start_binary_processing(
    skills_to_process,
    vcall_targets,
    post_process_yaml_items=None,
):
    """Start IDA when skills, vcall_finder, or post_process still has work to do."""
    return bool(skills_to_process or vcall_targets or post_process_yaml_items)
```

- [ ] **Step 3: Add YAML mapping collection helper**

在 `all_expected_outputs_exist(...)` 后插入：

```python
def _load_post_process_yaml_mapping(path, debug=False):
    """Load one post_process YAML file and return a mapping payload or None."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle)
    except Exception as exc:
        if debug:
            print(f"  Post-process: skipping unreadable YAML {path}: {exc}")
        return None

    if not isinstance(payload, dict):
        if debug:
            print(f"  Post-process: skipping non-mapping YAML {path}")
        return None
    return payload


def _collect_post_process_yaml_mappings(
    binary_dir,
    sorted_skill_names,
    skill_map,
    platform,
    debug=False,
):
    """Collect existing expected output YAML mappings in stable skill/output order."""
    yaml_items = []
    seen_paths = set()

    for skill_name in sorted_skill_names:
        skill = skill_map[skill_name]
        skill_platform = skill.get("platform")
        if skill_platform and skill_platform != platform:
            continue
        try:
            expected_outputs = expand_expected_paths(
                binary_dir,
                skill.get("expected_output", []),
                platform,
            )
        except ValueError as exc:
            if debug:
                print(f"  Post-process: skipping {skill_name}: {exc}")
            continue

        for output_path in expected_outputs:
            resolved_path = str(Path(output_path).resolve())
            if not _is_current_module_artifact_path(resolved_path, binary_dir):
                if debug:
                    print(
                        "  Post-process: skipping YAML outside current module dir "
                        f"{resolved_path}"
                    )
                continue
            if resolved_path in seen_paths:
                continue
            seen_paths.add(resolved_path)
            if not os.path.exists(resolved_path):
                continue
            payload = _load_post_process_yaml_mapping(resolved_path, debug=debug)
            if payload is None:
                continue
            yaml_items.append((resolved_path, payload))

    return yaml_items
```

- [ ] **Step 4: Add a temporary post_process runner stub**

在 `_run_validate_expected_input_artifacts_via_mcp(...)` 后插入：

```python
def _run_post_process_expected_outputs_via_mcp(
    *,
    host,
    port,
    yaml_items,
    debug=False,
):
    """Run post_process for collected expected output YAML mappings."""
    if not yaml_items:
        return True
    return asyncio.run(
        post_process_expected_outputs_via_mcp(
            host=host,
            port=port,
            yaml_items=yaml_items,
            debug=debug,
        )
    )


async def post_process_expected_outputs_via_mcp(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    yaml_items=None,
    debug=False,
):
    """Connect to IDA MCP and execute post_process actions."""
    return True
```

- [ ] **Step 5: Add `rename` to `process_binary(...)` signature and docstring**

Update signature:

```python
def process_binary(
    binary_path,
    skills,
    agent,
    host,
    port,
    ida_args,
    platform,
    debug=False,
    max_retries=3,
    old_binary_dir=None,
    gamever=None,
    module_name=None,
    vcall_targets=None,
    vcall_output_dir="vcall_finder",
    llm_model=DEFAULT_LLM_MODEL,
    llm_apikey=None,
    llm_baseurl=None,
    llm_temperature=None,
    llm_effort="medium",
    llm_fake_as=None,
    rename=False,
):
```

Add to docstring args:

```python
        rename: Run module/platform post_process over valid expected output YAML mappings
```

- [ ] **Step 6: Collect startup-only post_process YAMLs before startup decision**

在 `vcall_targets = list(vcall_targets or [])` 之后插入：

```python
    startup_post_process_yaml_items = []
    startup_post_process_failed = False
    if rename:
        try:
            startup_post_process_yaml_items = _collect_post_process_yaml_mappings(
                binary_dir,
                sorted_skill_names,
                skill_map,
                platform,
                debug=debug,
            )
        except Exception as exc:
            startup_post_process_failed = True
            fail_count += 1
            if debug:
                print(f"  Post-process preflight collection failed: {exc}")
```

替换启动判断：

```python
    if not should_start_binary_processing(
        skills_to_process,
        vcall_targets,
        startup_post_process_yaml_items,
    ):
        if startup_post_process_failed:
            print("  Post-process preflight failed before IDA startup")
        else:
            print("  All skills already have yaml files and no vcall_finder/post_process targets remain, skipping IDA startup")
        return success_count, fail_count, skip_count
```

替换 startup failure 返回：

```python
    if process is None:
        post_process_failure = 1 if startup_post_process_yaml_items else 0
        return (
            success_count,
            fail_count + len(skills_to_process) + len(vcall_targets) + post_process_failure,
            skip_count,
        )
```

- [ ] **Step 7: Recollect YAMLs and invoke post_process before `quit_ida_gracefully(...)`**

在 `finally:` 之前、vcall loop 结束之后插入：

```python
        post_process_yaml_items = []
        post_process_collection_failed = False
        if rename and not startup_post_process_failed:
            try:
                post_process_yaml_items = _collect_post_process_yaml_mappings(
                    binary_dir,
                    sorted_skill_names,
                    skill_map,
                    platform,
                    debug=debug,
                )
            except Exception as exc:
                post_process_collection_failed = True
                fail_count += 1
                if debug:
                    print(f"  Post-process final collection failed: {exc}")

        if rename and post_process_collection_failed:
            print("  Post-process failed during YAML recollection")
        elif rename and post_process_yaml_items:
            process, mcp_ok = ensure_mcp_available(
                process, binary_path, host, port, ida_args, debug
            )
            if not mcp_ok:
                fail_count += 1
                print("  Failed to restore MCP connection, skipping post_process")
            else:
                try:
                    post_process_ok = _run_post_process_expected_outputs_via_mcp(
                        host=host,
                        port=port,
                        yaml_items=post_process_yaml_items,
                        debug=debug,
                    )
                except Exception as exc:
                    post_process_ok = False
                    if debug:
                        print(f"  Post-process error: {exc}")
                if not post_process_ok:
                    fail_count += 1
                    print("  Post-process failed")
```

- [ ] **Step 8: Pass `rename=args.rename` from main**

Update the `process_binary(...)` call in `main()`:

```python
            success, fail, skip = process_binary(
                binary_path, skills, agent,
                DEFAULT_HOST, DEFAULT_PORT, ida_args, platform, debug,
                max_retries=args.maxretry,
                old_binary_dir=old_binary_dir,
                gamever=gamever,
                module_name=module_name,
                vcall_targets=vcall_targets,
                llm_model=args.llm_model,
                llm_apikey=args.llm_apikey,
                llm_baseurl=args.llm_baseurl,
                llm_temperature=args.llm_temperature,
                llm_effort=args.llm_effort,
                llm_fake_as=args.llm_fake_as,
                rename=args.rename,
            )
```

- [ ] **Step 9: Run entry tests**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_bin.TestParseArgsLlmOptions.test_parse_args_defaults_rename_to_false \
  tests.test_ida_analyze_bin.TestParseArgsLlmOptions.test_parse_args_accepts_rename \
  tests.test_ida_analyze_bin.TestProcessBinary.test_process_binary_does_not_start_ida_for_post_process_when_rename_is_false \
  tests.test_ida_analyze_bin.TestProcessBinary.test_process_binary_runs_post_process_when_rename_true_and_outputs_exist \
  -v
```

Expected:

```text
OK
```

- [ ] **Step 10: Commit CLI and lifecycle wiring**

```bash
git add ida_analyze_bin.py tests/test_ida_analyze_bin.py
git commit -m "feat(ida): 增加 post_process 入口参数"
```

### Task 3: Build YAML Action Collection

**Files:**
- Modify: `tests/test_ida_analyze_bin.py`
- Modify: `ida_analyze_bin.py`

- [ ] **Step 1: Add action parsing tests**

在 `TestProcessBinary` 之前新增 class：

```python
class TestPostProcessActionCollection(unittest.TestCase):
    def test_collect_post_process_yaml_mappings_skips_missing_invalid_and_duplicates(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            valid_path = binary_dir / "Valid.windows.yaml"
            invalid_path = binary_dir / "Invalid.windows.yaml"
            scalar_path = binary_dir / "Scalar.windows.yaml"
            valid_path.write_text("func_name: Valid\nfunc_va: '0x180100000'\n", encoding="utf-8")
            invalid_path.write_text("func_name: [\n", encoding="utf-8")
            scalar_path.write_text("- item\n", encoding="utf-8")

            result = ida_analyze_bin._collect_post_process_yaml_mappings(
                str(binary_dir),
                ["skill-a", "skill-b"],
                {
                    "skill-a": {
                        "name": "skill-a",
                        "expected_output": [
                            "Valid.{platform}.yaml",
                            "Missing.{platform}.yaml",
                            "Invalid.{platform}.yaml",
                            "Scalar.{platform}.yaml",
                        ],
                    },
                    "skill-b": {
                        "name": "skill-b",
                        "expected_output": ["Valid.{platform}.yaml"],
                    },
                },
                "windows",
                debug=False,
            )

        self.assertEqual([(str(valid_path.resolve()), {"func_name": "Valid", "func_va": "0x180100000"})], result)

    def test_collect_post_process_yaml_mappings_skips_paths_outside_current_binary_dir(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            gamever_dir = Path(temp_dir) / "bin" / "14141"
            binary_dir = gamever_dir / "server"
            sibling_dir = gamever_dir / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            sibling_dir.mkdir(parents=True, exist_ok=True)
            (sibling_dir / "CrossModule.windows.yaml").write_text(
                "func_name: CrossModule\nfunc_va: '0x180200000'\n",
                encoding="utf-8",
            )

            result = ida_analyze_bin._collect_post_process_yaml_mappings(
                str(binary_dir),
                ["skill-a"],
                {
                    "skill-a": {
                        "name": "skill-a",
                        "expected_output": ["../engine/CrossModule.{platform}.yaml"],
                    },
                },
                "windows",
                debug=False,
            )

        self.assertEqual([], result)

    def test_build_post_process_actions_supports_all_yaml_action_types(self) -> None:
        actions = ida_analyze_bin._build_post_process_actions_from_yaml(
            {
                "vtable_class": "CEntFireOutputAutoCompletionFunctor",
                "vtable_va": "0x1817617a8",
                "func_name": "CEntFireOutputAutoCompletionFunctor_FireOutput",
                "func_va": "0x180c165c0",
                "gv_name": "CCSGameRules__sm_mapGcBanInformation",
                "gv_va": "0x181eff6a8",
                "vfunc_offset": "0xb8",
                "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                "vfunc_sig_disp": 2,
                "struct_name": "CCheckTransmitInfo",
                "member_name": "m_nPlayerSlot",
                "offset": "0x240",
                "offset_sig": "8B 8F ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B F0",
                "offset_sig_disp": 0,
            },
            "fixture.yaml",
            debug=False,
        )

        self.assertEqual(
            [{"addr": "0x180c165c0", "name": "CEntFireOutputAutoCompletionFunctor_FireOutput"}],
            actions["func_renames"],
        )
        self.assertEqual(
            [
                {
                    "addr": "0x1817617a8",
                    "name": "CEntFireOutputAutoCompletionFunctor_vtable",
                    "kind": "vtable",
                },
                {
                    "addr": "0x181eff6a8",
                    "name": "CCSGameRules__sm_mapGcBanInformation",
                    "kind": "global",
                },
            ],
            actions["data_renames"],
        )
        self.assertEqual(
            [
                {
                    "pattern": "48 FF A0 B8 00 00 00 C3",
                    "disp": 2,
                    "comment": "0xB8 = 184LL = CEntFireOutputAutoCompletionFunctor_FireOutput",
                    "source_path": "fixture.yaml",
                    "kind": "vfunc_sig",
                },
                {
                    "pattern": "8B 8F ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B F0",
                    "disp": 0,
                    "comment": "0x240 = 576LL = CCheckTransmitInfo::m_nPlayerSlot",
                    "source_path": "fixture.yaml",
                    "kind": "offset_sig",
                },
            ],
            actions["sig_comments"],
        )

    def test_build_post_process_actions_skips_invalid_fields_without_blocking_valid_actions(
        self,
    ) -> None:
        actions = ida_analyze_bin._build_post_process_actions_from_yaml(
            {
                "func_name": "ValidFunction",
                "func_va": "0x180111000",
                "gv_name": "InvalidGlobal",
                "gv_va": "not-an-address",
                "vfunc_offset": "not-an-offset",
                "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
            },
            "invalid-fields.yaml",
            debug=False,
        )

        self.assertEqual(
            [{"addr": "0x180111000", "name": "ValidFunction"}],
            actions["func_renames"],
        )
        self.assertEqual([], actions["data_renames"])
        self.assertEqual([], actions["sig_comments"])

    def test_build_post_process_actions_skips_invalid_sig_disp_fields(
        self,
    ) -> None:
        actions = ida_analyze_bin._build_post_process_actions_from_yaml(
            {
                "func_name": "ValidFunction",
                "func_va": "0x180111000",
                "vfunc_offset": "0xb8",
                "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                "vfunc_sig_disp": None,
                "struct_name": "CCheckTransmitInfo",
                "member_name": "m_nPlayerSlot",
                "offset": "0x240",
                "offset_sig": "8B 8F ?? ?? ?? ??",
                "offset_sig_disp": None,
            },
            "invalid-disp.yaml",
            debug=False,
        )

        self.assertEqual(
            [{"addr": "0x180111000", "name": "ValidFunction"}],
            actions["func_renames"],
        )
        self.assertEqual([], actions["data_renames"])
        self.assertEqual([], actions["sig_comments"])
```

- [ ] **Step 2: Run action parsing tests and verify failure**

Run:

```bash
python -m unittest tests.test_ida_analyze_bin.TestPostProcessActionCollection -v
```

Expected:

```text
ERROR: test_build_post_process_actions_supports_all_yaml_action_types
```

The failure is expected because `_build_post_process_actions_from_yaml(...)` is not defined.

- [ ] **Step 3: Add action helper functions**

在 `_collect_post_process_yaml_mappings(...)` 后插入：

```python
def _empty_post_process_actions():
    return {
        "func_renames": [],
        "data_renames": [],
        "sig_comments": [],
    }


def _extend_post_process_actions(target, source):
    target["func_renames"].extend(source["func_renames"])
    target["data_renames"].extend(source["data_renames"])
    target["sig_comments"].extend(source["sig_comments"])


def _parse_post_process_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            return int(raw, 0)
        except ValueError:
            return None
    return None


def _parse_post_process_addr(value):
    parsed = _parse_post_process_int(value)
    if parsed is None or parsed < 0:
        return None
    return f"0x{parsed:x}"


def _post_process_text(value):
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _format_post_process_offset_comment(offset_value, label):
    return f"0x{offset_value:X} = {offset_value}LL = {label}"


def _build_post_process_actions_from_yaml(payload, source_path, debug=False):
    actions = _empty_post_process_actions()
    if not isinstance(payload, dict):
        return actions

    vtable_class = _post_process_text(payload.get("vtable_class"))
    vtable_addr = _parse_post_process_addr(payload.get("vtable_va"))
    if vtable_class and vtable_addr:
        actions["data_renames"].append(
            {
                "addr": vtable_addr,
                "name": f"{vtable_class}_vtable",
                "kind": "vtable",
            }
        )
    elif debug and (payload.get("vtable_class") is not None or payload.get("vtable_va") is not None):
        print(f"  Post-process: skipped invalid vtable rename in {source_path}")

    func_name = _post_process_text(payload.get("func_name"))
    func_addr = _parse_post_process_addr(payload.get("func_va"))
    if func_name and func_addr:
        actions["func_renames"].append({"addr": func_addr, "name": func_name})
    elif debug and (payload.get("func_name") is not None or payload.get("func_va") is not None):
        print(f"  Post-process: skipped invalid function rename in {source_path}")

    gv_name = _post_process_text(payload.get("gv_name"))
    gv_addr = _parse_post_process_addr(payload.get("gv_va"))
    if gv_name and gv_addr:
        actions["data_renames"].append(
            {
                "addr": gv_addr,
                "name": gv_name,
                "kind": "global",
            }
        )
    elif debug and (payload.get("gv_name") is not None or payload.get("gv_va") is not None):
        print(f"  Post-process: skipped invalid global rename in {source_path}")

    vfunc_sig = _post_process_text(payload.get("vfunc_sig"))
    vfunc_offset = _parse_post_process_int(payload.get("vfunc_offset"))
    has_vfunc_sig_disp = "vfunc_sig_disp" in payload
    vfunc_sig_disp_raw = payload.get("vfunc_sig_disp")
    vfunc_sig_disp = _parse_post_process_int(vfunc_sig_disp_raw)
    if not has_vfunc_sig_disp:
        vfunc_sig_disp = 0
    if (
        func_name
        and vfunc_sig
        and vfunc_offset is not None
        and vfunc_offset >= 0
        and vfunc_sig_disp is not None
        and vfunc_sig_disp >= 0
    ):
        actions["sig_comments"].append(
            {
                "pattern": vfunc_sig,
                "disp": vfunc_sig_disp,
                "comment": _format_post_process_offset_comment(vfunc_offset, func_name),
                "source_path": source_path,
                "kind": "vfunc_sig",
            }
        )
    elif debug and (payload.get("vfunc_sig") is not None or payload.get("vfunc_offset") is not None):
        print(f"  Post-process: skipped invalid vfunc_sig comment in {source_path}")

    struct_name = _post_process_text(payload.get("struct_name"))
    member_name = _post_process_text(payload.get("member_name"))
    offset_sig = _post_process_text(payload.get("offset_sig"))
    offset_value = _parse_post_process_int(payload.get("offset"))
    has_offset_sig_disp = "offset_sig_disp" in payload
    offset_sig_disp_raw = payload.get("offset_sig_disp")
    offset_sig_disp = _parse_post_process_int(offset_sig_disp_raw)
    if not has_offset_sig_disp:
        offset_sig_disp = 0
    if (
        struct_name
        and member_name
        and offset_sig
        and offset_value is not None
        and offset_value >= 0
        and offset_sig_disp >= 0
    ):
        actions["sig_comments"].append(
            {
                "pattern": offset_sig,
                "disp": offset_sig_disp,
                "comment": _format_post_process_offset_comment(
                    offset_value,
                    f"{struct_name}::{member_name}",
                ),
                "source_path": source_path,
                "kind": "offset_sig",
            }
        )
    elif debug and (payload.get("offset_sig") is not None or payload.get("offset") is not None):
        print(f"  Post-process: skipped invalid offset_sig comment in {source_path}")

    return actions
```

- [ ] **Step 4: Run action parsing tests**

Run:

```bash
python -m unittest tests.test_ida_analyze_bin.TestPostProcessActionCollection -v
```

Expected:

```text
OK
```

- [ ] **Step 5: Commit action collection**

```bash
git add ida_analyze_bin.py tests/test_ida_analyze_bin.py
git commit -m "feat(ida): 生成 post_process 动作"
```

### Task 4: Execute Rename And Comment Actions Through MCP

**Files:**
- Modify: `tests/test_ida_analyze_bin.py`
- Modify: `ida_analyze_bin.py`

- [ ] **Step 1: Add MCP execution tests**

在 `TestPostProcessActionCollection` 后新增：

```python
class TestPostProcessMcpExecution(unittest.IsolatedAsyncioTestCase):
    async def test_post_process_expected_outputs_via_session_executes_renames_and_comments(
        self,
    ) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(
            side_effect=[
                _tool_result([{"pattern": "48 FF A0 B8 00 00 00 C3", "matches": ["0x180a32c60"], "n": 1}]),
                _tool_result({"items": [{"addr": "0x180a32c62", "ok": True}]}),
                _tool_result({"renamed": True}),
                _tool_result({"result": ""}),
            ]
        )

        ok = await ida_analyze_bin.post_process_expected_outputs_via_session(
            session,
            [
                (
                    "fixture.yaml",
                    {
                        "func_name": "CCSPlayer_ItemServices_DropActivePlayerWeapon",
                        "func_va": "0x180c165c0",
                        "vfunc_offset": "0xb8",
                        "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                        "vfunc_sig_disp": 2,
                        "gv_name": "CCSGameRules__sm_mapGcBanInformation",
                        "gv_va": "0x181eff6a8",
                    },
                )
            ],
            debug=False,
        )

        self.assertTrue(ok)
        self.assertEqual(
            [
                call(
                    name="find_bytes",
                    arguments={"patterns": ["48 FF A0 B8 00 00 00 C3"], "limit": 2},
                ),
                call(
                    name="set_comments",
                    arguments={
                        "items": [
                            {
                                "addr": "0x180a32c62",
                                "comment": "0xB8 = 184LL = CCSPlayer_ItemServices_DropActivePlayerWeapon",
                            }
                        ]
                    },
                ),
                call(
                    name="rename",
                    arguments={
                        "batch": {
                            "func": [
                                {
                                    "addr": "0x180c165c0",
                                    "name": "CCSPlayer_ItemServices_DropActivePlayerWeapon",
                                }
                            ]
                        }
                    },
                ),
                call(
                    name="py_eval",
                    arguments={
                        "code": (
                            "import idc\n"
                            "idc.set_name(6474954408, \"CCSGameRules__sm_mapGcBanInformation\", idc.SN_NOWARN)\n"
                        )
                    },
                ),
            ],
            session.call_tool.await_args_list,
        )

    async def test_post_process_expected_outputs_via_session_skips_non_unique_signature_matches(
        self,
    ) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(
            side_effect=[
                _tool_result([{"pattern": "8B 8F ?? ?? ?? ??", "matches": [], "n": 0}]),
                _tool_result([{"pattern": "48 FF A0 B8 00 00 00 C3", "matches": ["0x1801", "0x1802"], "n": 2}]),
            ]
        )

        ok = await ida_analyze_bin.post_process_expected_outputs_via_session(
            session,
            [
                (
                    "fixture.yaml",
                    {
                        "struct_name": "CCheckTransmitInfo",
                        "member_name": "m_nPlayerSlot",
                        "offset": "0x240",
                        "offset_sig": "8B 8F ?? ?? ?? ??",
                        "func_name": "CCSPlayer_ItemServices_DropActivePlayerWeapon",
                        "vfunc_offset": "0xb8",
                        "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                    },
                )
            ],
            debug=False,
        )

        self.assertTrue(ok)
        self.assertEqual(2, session.call_tool.await_count)
        self.assertNotIn("set_comments", [call_item.kwargs["name"] for call_item in session.call_tool.await_args_list])

    async def test_post_process_expected_outputs_via_session_falls_back_to_py_eval_comments(
        self,
    ) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(
            side_effect=[
                _tool_result([{"pattern": "48 FF A0 B8 00 00 00 C3", "matches": [6453142112], "n": 1}]),
                RuntimeError("Unknown tool: set_comments"),
                _tool_result({"result": ""}),
            ]
        )

        ok = await ida_analyze_bin.post_process_expected_outputs_via_session(
            session,
            [
                (
                    "fixture.yaml",
                    {
                        "func_name": "CCSPlayer_ItemServices_DropActivePlayerWeapon",
                        "vfunc_offset": "0xb8",
                        "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                    },
                )
            ],
            debug=False,
        )

        self.assertTrue(ok)
        self.assertEqual("py_eval", session.call_tool.await_args_list[-1].kwargs["name"])
        self.assertIn(
            "idc.set_cmt(6453142112, \"0xB8 = 184LL = CCSPlayer_ItemServices_DropActivePlayerWeapon\", 0)",
            session.call_tool.await_args_list[-1].kwargs["arguments"]["code"],
        )

    async def test_post_process_expected_outputs_via_session_ignores_set_comments_item_errors(
        self,
    ) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(
            side_effect=[
                _tool_result([{"pattern": "48 FF A0 B8 00 00 00 C3", "matches": ["0x180a32c60"], "n": 1}]),
                _tool_result(
                    {
                        "items": [
                            {
                                "addr": "0x180a32c60",
                                "error": "Decompiler comment failed",
                            }
                        ]
                    }
                ),
                _tool_result({"renamed": True}),
            ]
        )

        ok = await ida_analyze_bin.post_process_expected_outputs_via_session(
            session,
            [
                (
                    "fixture.yaml",
                    {
                        "func_name": "CCSPlayer_ItemServices_DropActivePlayerWeapon",
                        "func_va": "0x180c165c0",
                        "vfunc_offset": "0xb8",
                        "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                    },
                )
            ],
            debug=True,
        )

        self.assertTrue(ok)
        self.assertEqual("rename", session.call_tool.await_args_list[-1].kwargs["name"])
        self.assertNotIn(
            "py_eval",
            [call_item.kwargs["name"] for call_item in session.call_tool.await_args_list],
        )
```

- [ ] **Step 2: Run MCP execution tests and verify failure**

Run:

```bash
python -m unittest tests.test_ida_analyze_bin.TestPostProcessMcpExecution -v
```

Expected:

```text
ERROR: test_post_process_expected_outputs_via_session_executes_renames_and_comments
```

The failure is expected because `post_process_expected_outputs_via_session(...)` is not defined.

- [ ] **Step 3: Add MCP execution helper functions**

在 `_build_post_process_actions_from_yaml(...)` 后插入：

```python
def _parse_post_process_match_addr(value):
    parsed = _parse_post_process_int(value)
    if parsed is None or parsed < 0:
        return None
    return parsed


async def _find_post_process_signature_comment_addr(session, action, debug=False):
    try:
        result = await session.call_tool(
            name="find_bytes",
            arguments={"patterns": [action["pattern"]], "limit": 2},
        )
        payload = _parse_tool_json_content(result)
    except Exception as exc:
        if debug:
            print(f"  Post-process: find_bytes failed for {action['source_path']}: {exc}")
        return None

    if not isinstance(payload, list) or not payload:
        return None
    entry = payload[0]
    if not isinstance(entry, dict):
        return None

    matches = entry.get("matches", [])
    match_count = entry.get("n", len(matches))
    if match_count != 1 or not matches:
        if debug:
            print(
                "  Post-process: skipped "
                f"{action['kind']} comment in {action['source_path']} "
                f"because signature matched {match_count}"
            )
        return None

    match_addr = _parse_post_process_match_addr(matches[0])
    if match_addr is None:
        if debug:
            print(f"  Post-process: unparsable signature match in {action['source_path']}")
        return None
    return match_addr + action["disp"]


async def _post_process_set_comments(session, comment_items, debug=False):
    if not comment_items:
        return

    try:
        result = await session.call_tool(
            name="set_comments",
            arguments={"items": comment_items},
        )
        payload = _parse_tool_json_content(result)
        if isinstance(payload, dict):
            for item in payload.get("items", []):
                if isinstance(item, dict) and item.get("error") and debug:
                    print(
                        "  Post-process: set_comments item failed "
                        f"at {item.get('addr')}: {item.get('error')}"
                    )
        return
    except Exception as exc:
        if debug:
            print(f"  Post-process: set_comments unavailable, using py_eval fallback: {exc}")

    for item in comment_items:
        addr_int = _parse_post_process_int(item["addr"])
        if addr_int is None:
            continue
        code = (
            "import idc\n"
            f"idc.set_cmt({addr_int}, {json.dumps(item['comment'])}, 0)\n"
        )
        try:
            await session.call_tool(name="py_eval", arguments={"code": code})
        except Exception as exc:
            if debug:
                print(f"  Post-process: py_eval comment fallback failed at {item['addr']}: {exc}")


async def _post_process_func_renames(session, func_renames, debug=False):
    if not func_renames:
        return
    try:
        await session.call_tool(
            name="rename",
            arguments={"batch": {"func": func_renames}},
        )
    except Exception as exc:
        if debug:
            print(f"  Post-process: function rename batch failed: {exc}")


async def _post_process_data_renames(session, data_renames, debug=False):
    for item in data_renames:
        addr_int = _parse_post_process_int(item["addr"])
        if addr_int is None:
            continue
        code = (
            "import idc\n"
            f"idc.set_name({addr_int}, {json.dumps(item['name'])}, idc.SN_NOWARN)\n"
        )
        try:
            await session.call_tool(name="py_eval", arguments={"code": code})
        except Exception as exc:
            if debug:
                print(
                    "  Post-process: data rename failed "
                    f"{item['addr']} -> {item['name']}: {exc}"
                )


async def post_process_expected_outputs_via_session(
    session,
    yaml_items,
    debug=False,
):
    actions = _empty_post_process_actions()
    for source_path, payload in yaml_items:
        _extend_post_process_actions(
            actions,
            _build_post_process_actions_from_yaml(payload, source_path, debug=debug),
        )

    comment_items = []
    for action in actions["sig_comments"]:
        comment_addr = await _find_post_process_signature_comment_addr(
            session,
            action,
            debug=debug,
        )
        if comment_addr is None:
            continue
        comment_items.append(
            {
                "addr": f"0x{comment_addr:x}",
                "comment": action["comment"],
            }
        )

    await _post_process_set_comments(session, comment_items, debug=debug)
    await _post_process_func_renames(session, actions["func_renames"], debug=debug)
    await _post_process_data_renames(session, actions["data_renames"], debug=debug)
    return True
```

- [ ] **Step 4: Replace temporary MCP connection stub**

替换 `post_process_expected_outputs_via_mcp(...)`：

```python
async def post_process_expected_outputs_via_mcp(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    yaml_items=None,
    debug=False,
):
    """Connect to IDA MCP and execute post_process actions."""
    yaml_items = list(yaml_items or [])
    if not yaml_items:
        return True

    server_url = f"http://{host}:{port}/mcp"

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(10.0, read=120.0),
            trust_env=False,
        ) as http_client:
            async with streamable_http_client(server_url, http_client=http_client) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    return await post_process_expected_outputs_via_session(
                        session,
                        yaml_items,
                        debug=debug,
                    )
    except Exception as exc:
        if debug:
            print(f"  Post-process: MCP connection failed: {exc}")
        return False
```

- [ ] **Step 5: Run MCP execution tests**

Run:

```bash
python -m unittest tests.test_ida_analyze_bin.TestPostProcessMcpExecution -v
```

Expected:

```text
OK
```

- [ ] **Step 6: Commit MCP execution helpers**

```bash
git add ida_analyze_bin.py tests/test_ida_analyze_bin.py
git commit -m "feat(ida): 执行 post_process 重命名"
```

### Task 5: Lock Failure Semantics And Main Wiring

**Files:**
- Modify: `tests/test_ida_analyze_bin.py`
- Modify: `ida_analyze_bin.py`

- [ ] **Step 1: Add post_process failure count tests**

在 `TestProcessBinary` 中追加：

```python
    def test_process_binary_counts_post_process_failure_once(
        self,
    ) -> None:
        fake_process = object()

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")
            (binary_dir / "CEntFireOutputAutoCompletionFunctor_FireOutput.windows.yaml").write_text(
                "func_name: CEntFireOutputAutoCompletionFunctor_FireOutput\n"
                "func_va: '0x180c165c0'\n",
                encoding="utf-8",
            )

            with (
                patch.object(
                    ida_analyze_bin,
                    "start_idalib_mcp",
                    return_value=fake_process,
                ),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_post_process_expected_outputs_via_mcp",
                    side_effect=RuntimeError("boom"),
                ),
                patch.object(
                    ida_analyze_bin,
                    "quit_ida_gracefully",
                    return_value=None,
                ),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                            "expected_output": [
                                "CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"
                            ],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                    rename=True,
                )

        self.assertEqual((0, 1, 1), (success, fail, skip))

    def test_process_binary_counts_post_process_preflight_collection_failure_once(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")
            (binary_dir / "CEntFireOutputAutoCompletionFunctor_FireOutput.windows.yaml").write_text(
                "func_name: CEntFireOutputAutoCompletionFunctor_FireOutput\n"
                "func_va: '0x180c165c0'\n",
                encoding="utf-8",
            )

            with (
                patch.object(
                    ida_analyze_bin,
                    "_collect_post_process_yaml_mappings",
                    side_effect=RuntimeError("collect boom"),
                ),
                patch.object(
                    ida_analyze_bin,
                    "start_idalib_mcp",
                ) as mock_start_ida,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                            "expected_output": [
                                "CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"
                            ],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                    rename=True,
                )

        self.assertEqual((0, 1, 1), (success, fail, skip))
        mock_start_ida.assert_not_called()
```

- [ ] **Step 2: Add startup failure count test for rename-only work**

在 `TestProcessBinary` 中追加：

```python
    def test_process_binary_counts_startup_failure_for_rename_only_work(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")
            (binary_dir / "CEntFireOutputAutoCompletionFunctor_FireOutput.windows.yaml").write_text(
                "func_name: CEntFireOutputAutoCompletionFunctor_FireOutput\n"
                "func_va: '0x180c165c0'\n",
                encoding="utf-8",
            )

            with patch.object(
                ida_analyze_bin,
                "start_idalib_mcp",
                return_value=None,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                            "expected_output": [
                                "CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"
                            ],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                    rename=True,
                )

        self.assertEqual((0, 1, 1), (success, fail, skip))
```

- [ ] **Step 3: Add main wiring assertion**

在 `TestMainLlmWiring` 后新增：

```python
class TestMainPostProcessWiring(unittest.TestCase):
    @patch.object(ida_analyze_bin, "parse_config")
    @patch("ida_analyze_bin.os.path.exists", return_value=True)
    @patch.object(ida_analyze_bin, "parse_args")
    def test_main_passes_rename_to_process_binary(
        self,
        mock_parse_args,
        _mock_exists,
        mock_parse_config,
    ) -> None:
        captured = {}

        def fake_process_binary(*args, **kwargs):
            captured["kwargs"] = kwargs
            return (0, 0, 0)

        mock_parse_args.return_value = SimpleNamespace(
            configyaml="config.yaml",
            bindir="bin",
            gamever="14141",
            oldgamever=None,
            platforms=["windows"],
            module_filter=None,
            modules="*",
            agent="codex",
            ida_args="",
            debug=False,
            maxretry=3,
            vcall_finder_filter=None,
            llm_model="gpt-4.1-mini",
            llm_apikey=None,
            llm_baseurl=None,
            llm_temperature=None,
            llm_effort="high",
            llm_fake_as="codex",
            rename=True,
        )
        mock_parse_config.return_value = [
            {
                "name": "server",
                "skills": [
                    {
                        "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                        "expected_output": [
                            "CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"
                        ],
                        "expected_input": [],
                    }
                ],
                "vcall_finder_objects": [],
                "path_windows": "game/bin/win64/server.dll",
            }
        ]

        with patch.object(ida_analyze_bin, "process_binary", new=fake_process_binary):
            ida_analyze_bin.main()

        self.assertTrue(captured["kwargs"]["rename"])
```

- [ ] **Step 4: Run failure semantics and main wiring tests**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_bin.TestProcessBinary.test_process_binary_counts_post_process_failure_once \
  tests.test_ida_analyze_bin.TestProcessBinary.test_process_binary_counts_post_process_preflight_collection_failure_once \
  tests.test_ida_analyze_bin.TestProcessBinary.test_process_binary_counts_startup_failure_for_rename_only_work \
  tests.test_ida_analyze_bin.TestMainPostProcessWiring.test_main_passes_rename_to_process_binary \
  -v
```

Expected:

```text
OK
```

- [ ] **Step 5: Commit failure semantics**

```bash
git add ida_analyze_bin.py tests/test_ida_analyze_bin.py
git commit -m "fix(ida): 统计 post_process 失败"
```

### Task 6: Run Targeted Regression And Review

**Files:**
- Verify: `ida_analyze_bin.py`
- Verify: `tests/test_ida_analyze_bin.py`
- Verify: `docs/superpowers/specs/2026-04-28-ida-analyze-bin-post-process-design.md`

- [ ] **Step 1: Run focused post_process test groups**

Run:

```bash
python -m unittest \
  tests.test_ida_analyze_bin.TestParseArgsLlmOptions.test_parse_args_defaults_rename_to_false \
  tests.test_ida_analyze_bin.TestParseArgsLlmOptions.test_parse_args_accepts_rename \
  tests.test_ida_analyze_bin.TestPostProcessActionCollection \
  tests.test_ida_analyze_bin.TestPostProcessMcpExecution \
  tests.test_ida_analyze_bin.TestProcessBinary.test_process_binary_does_not_start_ida_for_post_process_when_rename_is_false \
  tests.test_ida_analyze_bin.TestProcessBinary.test_process_binary_runs_post_process_when_rename_true_and_outputs_exist \
  tests.test_ida_analyze_bin.TestProcessBinary.test_process_binary_counts_post_process_failure_once \
  tests.test_ida_analyze_bin.TestProcessBinary.test_process_binary_counts_startup_failure_for_rename_only_work \
  tests.test_ida_analyze_bin.TestMainPostProcessWiring.test_main_passes_rename_to_process_binary \
  -v
```

Expected:

```text
OK
```

- [ ] **Step 2: Run existing IDA analyze bin test module**

Run:

```bash
python -m unittest tests.test_ida_analyze_bin -v
```

Expected:

```text
OK
```

- [ ] **Step 3: Inspect final diff**

Run:

```bash
git diff -- ida_analyze_bin.py tests/test_ida_analyze_bin.py docs/superpowers/plans/2026-04-28-ida-analyze-bin-post-process.md
```

Expected:

```text
diff --git a/ida_analyze_bin.py b/ida_analyze_bin.py
diff --git a/tests/test_ida_analyze_bin.py b/tests/test_ida_analyze_bin.py
diff --git a/docs/superpowers/plans/2026-04-28-ida-analyze-bin-post-process.md b/docs/superpowers/plans/2026-04-28-ida-analyze-bin-post-process.md
```

- [ ] **Step 4: Review spec coverage**

Check these exact requirements against the diff:

```text
- parse_args has -rename and defaults to False
- main passes args.rename into process_binary
- process_binary defaults rename=False
- rename=False does not start IDA only for existing outputs
- rename=True starts IDA when valid expected output YAML mappings exist
- post_process runs after skill pipeline and vcall_finder loop, before quit_ida_gracefully
- YAML collection uses expand_expected_paths and only current expected_output entries
- YAML collection rejects paths outside the current binary_dir
- missing, invalid, scalar, and duplicate YAML files do not block valid files
- vtable_class/vtable_va generates data rename to <class>_vtable
- func_name/func_va generates function rename
- gv_name/gv_va generates data rename
- vfunc_sig comment uses unique signature match and vfunc_sig_disp default 0
- offset_sig comment uses unique signature match and offset_sig_disp default 0
- offset comment hex uses uppercase digits and decimal appends LL
- set_comments is preferred and py_eval comment fallback exists
- set_comments item-level errors are logged and ignored without aborting follow-up actions
- single action failures do not fail whole post_process
- preflight/final YAML collection exceptions increment fail_count once without escaping process_binary
- startup/MCP-level post_process failure increments fail_count once
```

- [ ] **Step 5: Commit final verification adjustments if needed**

If Step 1 or Step 2 required code or test adjustments, commit them:

```bash
git add ida_analyze_bin.py tests/test_ida_analyze_bin.py
git commit -m "fix(ida): 完善 post_process 回归"
```

If no adjustments were needed, do not create an empty commit.

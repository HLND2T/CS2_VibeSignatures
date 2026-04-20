# IGameSystem GamePostInit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `IGameSystem_GamePostInit` 增加一个不依赖 LLM 的 slot-only 预处理脚本，直接从本轮生成的 `IGameSystem_LoopPostInitAllSystems` YAML 出发，程序化提取 `vtable_name`、`vfunc_offset`、`vfunc_index` 并生成目标 YAML。

**Architecture:** 新增一个独立 helper `ida_preprocessor_scripts/_igamesystem_slot_dispatch_common.py`，专门负责“读取 dispatcher YAML -> 扫描 Windows wrapper / Linux inline vcall -> 去重 -> rank/order 映射 -> 写 slot-only YAML”。`find-IGameSystem_GamePostInit.py` 保持为薄封装脚本，只声明 dispatcher 依赖与 target spec；`config.yaml` 只做 skill/symbol 注册，不修改现有 `_igamesystem_dispatch_common.py`。

**Tech Stack:** Python 3.10+, `yaml.safe_load`, IDA MCP `py_eval`, `unittest`, `AsyncMock`, `write_func_yaml`

---

> 注：按当前仓库规则，计划中不包含 `git commit` 步骤；只有用户明确要求时才提交。

## File Structure

- Create: `ida_preprocessor_scripts/_igamesystem_slot_dispatch_common.py`
  - 新 helper，负责读取 dispatcher YAML、构造平台专用 `py_eval`、归一化和去重 slot entry、按 `dispatch_rank` / `multi_order` 映射并写 slot-only YAML。
- Create: `ida_preprocessor_scripts/find-IGameSystem_GamePostInit.py`
  - 新 skill 脚本，只声明 `DISPATCHER_YAML_STEM`、`TARGET_SPECS`、`EXPECTED_DISPATCH_COUNT`，并调用新 helper。
- Modify: `config.yaml`
  - 在现有 IGameSystem 相关 skill 区域注册 `find-IGameSystem_GamePostInit`，并在同一模块的 `symbols` 区域注册 `IGameSystem_GamePostInit`。
- Create: `tests/test_igamesystem_slot_dispatch_preprocessor.py`
  - 新的专用单测文件，覆盖 helper 的 `py_eval` 生成、dispatcher YAML 读取、去重与 slot-only 写出、skill 薄封装调用、`config.yaml` 注册。

## Task 1: 先把 helper 回归测试写出来

**Files:**
- Create: `tests/test_igamesystem_slot_dispatch_preprocessor.py`

- [ ] **Step 1: 写 helper 的失败单测**

```python
import importlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import yaml


def _import_slot_dispatch_module():
    return importlib.import_module(
        "ida_preprocessor_scripts._igamesystem_slot_dispatch_common"
    )


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


class TestBuildIgameSystemSlotDispatchPyEval(unittest.TestCase):
    def test_build_slot_dispatch_py_eval_windows_embeds_wrapper_walk(self) -> None:
        module = _import_slot_dispatch_module()

        code = module._build_slot_dispatch_py_eval(
            source_func_va="0x1805000C0",
            platform="windows",
        )

        self.assertIn("candidate_targets", code)
        self.assertIn("call', 'jmp'", code)
        self.assertIn("wrapper_entries", code)
        self.assertIn("op.type == idaapi.o_displ", code)
        self.assertIn("vfunc_offset", code)
        compile(code, "<igamesystem_slot_dispatch_windows>", "exec")

    def test_build_slot_dispatch_py_eval_linux_embeds_inline_vcall_scan(self) -> None:
        module = _import_slot_dispatch_module()

        code = module._build_slot_dispatch_py_eval(
            source_func_va="0xDD4720",
            platform="linux",
        )

        self.assertIn("call_entries", code)
        self.assertIn("op.type == idaapi.o_displ", code)
        self.assertIn("mov", code)
        self.assertIn("call", code)
        self.assertIn("vfunc_index", code)
        compile(code, "<igamesystem_slot_dispatch_linux>", "exec")


class TestPreprocessIgameSystemSlotDispatchSkill(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_deduplicates_unique_slots_and_writes_slot_only_yaml(
        self,
    ) -> None:
        module = _import_slot_dispatch_module()
        session = AsyncMock()

        with TemporaryDirectory() as tmpdir:
            new_binary_dir = Path(tmpdir)
            dispatcher_yaml = (
                new_binary_dir
                / "IGameSystem_LoopPostInitAllSystems.windows.yaml"
            )
            dispatcher_yaml.write_text(
                yaml.safe_dump({"func_va": "0x1805000C0"}, sort_keys=False),
                encoding="utf-8",
            )

            with patch.object(
                module,
                "_call_py_eval_json",
                AsyncMock(
                    return_value={
                        "entries": [
                            {
                                "source_ea": "0x18050013E",
                                "source_kind": "wrapper",
                                "vfunc_offset": "0x28",
                                "vfunc_index": 5,
                            },
                            {
                                "source_ea": "0x18050018D",
                                "source_kind": "wrapper",
                                "vfunc_offset": "0x28",
                                "vfunc_index": 5,
                            },
                        ]
                    }
                ),
            ), patch.object(module, "write_func_yaml") as mock_write:
                result = await module.preprocess_igamesystem_slot_dispatch_skill(
                    session=session,
                    expected_outputs=[
                        "/tmp/IGameSystem_GamePostInit.windows.yaml"
                    ],
                    new_binary_dir=str(new_binary_dir),
                    platform="windows",
                    dispatcher_yaml_stem="IGameSystem_LoopPostInitAllSystems",
                    target_specs=[
                        {
                            "target_name": "IGameSystem_GamePostInit",
                            "vtable_name": "IGameSystem",
                            "dispatch_rank": 0,
                        }
                    ],
                    multi_order="index",
                    expected_dispatch_count=1,
                    debug=True,
                )

        self.assertTrue(result)
        mock_write.assert_called_once_with(
            "/tmp/IGameSystem_GamePostInit.windows.yaml",
            {
                "func_name": "IGameSystem_GamePostInit",
                "vtable_name": "IGameSystem",
                "vfunc_offset": "0x28",
                "vfunc_index": 5,
            },
        )

    async def test_preprocess_skill_rejects_dispatcher_yaml_without_func_va(self) -> None:
        module = _import_slot_dispatch_module()
        session = AsyncMock()

        with TemporaryDirectory() as tmpdir:
            new_binary_dir = Path(tmpdir)
            dispatcher_yaml = (
                new_binary_dir
                / "IGameSystem_LoopPostInitAllSystems.windows.yaml"
            )
            dispatcher_yaml.write_text(
                yaml.safe_dump({"func_name": "IGameSystem_LoopPostInitAllSystems"}),
                encoding="utf-8",
            )

            result = await module.preprocess_igamesystem_slot_dispatch_skill(
                session=session,
                expected_outputs=["/tmp/IGameSystem_GamePostInit.windows.yaml"],
                new_binary_dir=str(new_binary_dir),
                platform="windows",
                dispatcher_yaml_stem="IGameSystem_LoopPostInitAllSystems",
                target_specs=[
                    {
                        "target_name": "IGameSystem_GamePostInit",
                        "vtable_name": "IGameSystem",
                    }
                ],
                multi_order="index",
                expected_dispatch_count=1,
                debug=True,
            )

        self.assertFalse(result)
```

- [ ] **Step 2: 运行新测试，确认它先失败**

Run: `uv run python -m unittest tests.test_igamesystem_slot_dispatch_preprocessor`

Expected: FAIL，错误包含 `ModuleNotFoundError: No module named 'ida_preprocessor_scripts._igamesystem_slot_dispatch_common'`

## Task 2: 实现 slot-dispatch helper 到 helper 测试通过

**Files:**
- Create: `ida_preprocessor_scripts/_igamesystem_slot_dispatch_common.py`
- Test: `tests/test_igamesystem_slot_dispatch_preprocessor.py`

- [ ] **Step 1: 新建 helper 基础骨架和通用小工具**

```python
#!/usr/bin/env python3
"""Shared preprocess helpers for slot-only IGameSystem dispatcher skills."""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import parse_mcp_result, write_func_yaml


def _read_yaml(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _parse_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ValueError("empty integer string")
        return int(raw, 0)
    return int(value)


async def _call_py_eval_json(session, code, debug=False, error_label="py_eval"):
    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": code},
        )
        result_data = parse_mcp_result(result)
    except Exception:
        if debug:
            print(f"    Preprocess: {error_label} error")
        return None

    raw = None
    if isinstance(result_data, dict):
        raw = result_data.get("result", "")
    elif result_data is not None:
        raw = str(result_data)

    if not raw:
        return None

    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        if debug:
            print(f"    Preprocess: invalid JSON result from {error_label}")
        return None
```

- [ ] **Step 2: 加入 Windows / Linux 两条 `py_eval` 生成路径**

```python
def _build_slot_dispatch_py_eval(source_func_va, platform):
    is_windows = 1 if platform == "windows" else 0
    return (
        "import idaapi, idautils, idc, json\n"
        f"func_addr = {source_func_va}\n"
        f"is_windows = {is_windows}\n"
        "if not idaapi.get_func(func_addr):\n"
        "    idaapi.add_func(func_addr)\n"
        "func = idaapi.get_func(func_addr)\n"
        "result_obj = {'entries': []}\n"
        "if func:\n"
        "    if is_windows:\n"
        "        candidate_targets = []\n"
        "        for head in idautils.Heads(func.start_ea, func.end_ea):\n"
        "            if idc.print_insn_mnem(head) in ('call', 'jmp'):\n"
        "                target = idc.get_operand_value(head, 0)\n"
        "                if target and target != func.start_ea:\n"
        "                    if not idaapi.get_func(target):\n"
        "                        idaapi.add_func(target)\n"
        "                    if idaapi.get_func(target):\n"
        "                        candidate_targets.append((head, target))\n"
        "        wrapper_entries = []\n"
        "        for call_ea, target in candidate_targets:\n"
        "            wrapper = idaapi.get_func(target)\n"
        "            if not wrapper:\n"
        "                continue\n"
        "            found = None\n"
        "            for inner in idautils.Heads(wrapper.start_ea, wrapper.end_ea):\n"
        "                if idc.print_insn_mnem(inner) not in ('call', 'jmp'):\n"
        "                    continue\n"
        "                insn = idaapi.insn_t()\n"
        "                if not idaapi.decode_insn(insn, inner):\n"
        "                    continue\n"
        "                op = insn.ops[0]\n"
        "                if op.type == idaapi.o_displ and op.addr >= 0 and (op.addr % 8) == 0:\n"
        "                    if found is not None:\n"
        "                        found = None\n"
        "                        break\n"
        "                    found = {\n"
        "                        'source_ea': hex(call_ea),\n"
        "                        'source_kind': 'wrapper',\n"
        "                        'vfunc_offset': hex(op.addr),\n"
        "                        'vfunc_index': op.addr // 8,\n"
        "                    }\n"
        "            if found is not None:\n"
        "                wrapper_entries.append(found)\n"
        "        result_obj['entries'] = wrapper_entries\n"
        "    else:\n"
        "        call_entries = []\n"
        "        for head in idautils.Heads(func.start_ea, func.end_ea):\n"
        "            if idc.print_insn_mnem(head) != 'call':\n"
        "                continue\n"
        "            insn = idaapi.insn_t()\n"
        "            if not idaapi.decode_insn(insn, head):\n"
        "                continue\n"
        "            op = insn.ops[0]\n"
        "            if op.type != idaapi.o_displ or op.addr < 0 or (op.addr % 8) != 0:\n"
        "                continue\n"
        "            prev = idc.prev_head(head, func.start_ea)\n"
        "            prev_mnem = idc.print_insn_mnem(prev) if prev != idaapi.BADADDR else ''\n"
        "            if prev_mnem != 'mov':\n"
        "                continue\n"
        "            call_entries.append({\n"
        "                'source_ea': hex(head),\n"
        "                'source_kind': 'inline',\n"
        "                'vfunc_offset': hex(op.addr),\n"
        "                'vfunc_index': op.addr // 8,\n"
        "            })\n"
        "        result_obj['entries'] = call_entries\n"
        "result = json.dumps(result_obj)\n"
    )
```

- [ ] **Step 3: 实现读取 dispatcher YAML、去重映射和 slot-only 输出**

```python
async def preprocess_igamesystem_slot_dispatch_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    dispatcher_yaml_stem,
    target_specs,
    multi_order="index",
    expected_dispatch_count=None,
    debug=False,
):
    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required")
        return False

    if not isinstance(target_specs, list) or not target_specs:
        if debug:
            print("    Preprocess: target_specs must be a non-empty list")
        return False

    normalized_specs = []
    has_dispatch_rank = False
    for spec in target_specs:
        if not isinstance(spec, dict):
            return False
        target_name = spec.get("target_name")
        vtable_name = spec.get("vtable_name")
        if not target_name or not vtable_name:
            return False
        dispatch_rank = spec.get("dispatch_rank")
        if dispatch_rank is not None:
            dispatch_rank = _parse_int(dispatch_rank)
            if dispatch_rank < 0:
                return False
            has_dispatch_rank = True
        normalized_specs.append(
            {
                "target_name": str(target_name),
                "vtable_name": str(vtable_name),
                "dispatch_rank": dispatch_rank,
            }
        )

    if has_dispatch_rank and any(
        spec["dispatch_rank"] is None for spec in normalized_specs
    ):
        return False

    if expected_dispatch_count is None:
        expected_dispatch_count = (
            max(spec["dispatch_rank"] for spec in normalized_specs) + 1
            if has_dispatch_rank
            else len(normalized_specs)
        )
    else:
        expected_dispatch_count = _parse_int(expected_dispatch_count)

    matched_outputs = {}
    for spec in normalized_specs:
        filename = f'{spec["target_name"]}.{platform}.yaml'
        matched = [
            path for path in expected_outputs if os.path.basename(path) == filename
        ]
        if len(matched) != 1:
            return False
        matched_outputs[spec["target_name"]] = matched[0]

    dispatcher_yaml_path = os.path.join(
        new_binary_dir,
        f"{dispatcher_yaml_stem}.{platform}.yaml",
    )
    dispatcher_yaml = _read_yaml(dispatcher_yaml_path)
    if not isinstance(dispatcher_yaml, dict) or not dispatcher_yaml.get("func_va"):
        if debug:
            print(
                f"    Preprocess: failed to read dispatcher YAML "
                f"{os.path.basename(dispatcher_yaml_path)}"
            )
        return False

    py_code = _build_slot_dispatch_py_eval(
        source_func_va=str(dispatcher_yaml["func_va"]),
        platform=platform,
    )
    parsed = await _call_py_eval_json(
        session=session,
        code=py_code,
        debug=debug,
        error_label="py_eval extracting slot dispatch entries",
    )
    entries = parsed.get("entries") if isinstance(parsed, dict) else None
    if not isinstance(entries, list) or not entries:
        return False

    unique_entries = {}
    for entry in entries:
        vfunc_offset = _parse_int(entry.get("vfunc_offset"))
        vfunc_index = _parse_int(entry.get("vfunc_index"))
        if vfunc_offset < 0 or (vfunc_offset % 8) != 0:
            return False
        if vfunc_index != (vfunc_offset // 8):
            return False
        unique_entries[(vfunc_offset, vfunc_index)] = {
            "vfunc_offset": hex(vfunc_offset),
            "vfunc_index": vfunc_index,
        }

    ordered_entries = [
        unique_entries[key]
        for key in sorted(unique_entries.keys(), key=lambda item: (item[1], item[0]))
    ]
    if len(ordered_entries) != expected_dispatch_count:
        if debug:
            print(
                f"    Preprocess: expected {expected_dispatch_count} unique slot "
                f"entries, got {len(ordered_entries)}"
            )
        return False

    selected_entries = []
    if has_dispatch_rank:
        for spec in normalized_specs:
            rank = spec["dispatch_rank"]
            if rank >= len(ordered_entries):
                return False
            selected_entries.append((spec, ordered_entries[rank]))
    else:
        selected = (
            ordered_entries
            if multi_order == "index"
            else ordered_entries[: len(normalized_specs)]
        )
        if len(selected) < len(normalized_specs):
            return False
        selected_entries = list(zip(normalized_specs, selected))

    for spec, entry in selected_entries:
        write_func_yaml(
            matched_outputs[spec["target_name"]],
            {
                "func_name": spec["target_name"],
                "vtable_name": spec["vtable_name"],
                "vfunc_offset": entry["vfunc_offset"],
                "vfunc_index": entry["vfunc_index"],
            },
        )

    return True
```

- [ ] **Step 4: 跑 helper 测试，确认由红转绿**

Run: `uv run python -m unittest tests.test_igamesystem_slot_dispatch_preprocessor`

Expected: PASS，至少通过 4 个测试；输出包含 `OK`

## Task 3: 加薄封装 skill 和 `config.yaml` 注册

**Files:**
- Create: `ida_preprocessor_scripts/find-IGameSystem_GamePostInit.py`
- Modify: `config.yaml`
- Modify: `tests/test_igamesystem_slot_dispatch_preprocessor.py`

- [ ] **Step 1: 给 skill 薄封装和配置注册补失败测试**

```python
class TestGamePostInitSkill(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_delegates_to_slot_dispatch_helper(self) -> None:
        module = importlib.import_module(
            "ida_preprocessor_scripts.find-IGameSystem_GamePostInit"
        )
        session = AsyncMock()

        with patch.object(
            module,
            "preprocess_igamesystem_slot_dispatch_skill",
            AsyncMock(return_value=True),
        ) as mock_helper:
            result = await module.preprocess_skill(
                session=session,
                skill_name="find-IGameSystem_GamePostInit",
                expected_outputs=["/tmp/IGameSystem_GamePostInit.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp/bin/server",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        mock_helper.assert_awaited_once_with(
            session=session,
            expected_outputs=["/tmp/IGameSystem_GamePostInit.windows.yaml"],
            new_binary_dir="/tmp/bin/server",
            platform="windows",
            dispatcher_yaml_stem="IGameSystem_LoopPostInitAllSystems",
            target_specs=[
                {
                    "target_name": "IGameSystem_GamePostInit",
                    "vtable_name": "IGameSystem",
                    "dispatch_rank": 0,
                }
            ],
            multi_order="index",
            expected_dispatch_count=1,
            debug=True,
        )


class TestGamePostInitConfig(unittest.TestCase):
    def test_config_registers_gamepostinit_skill_and_symbol(self) -> None:
        config = yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8"))
        modules = config["modules"]

        skill = next(
            skill
            for module in modules
            for skill in module.get("skills", [])
            if skill.get("name") == "find-IGameSystem_GamePostInit"
        )
        symbol = next(
            symbol
            for module in modules
            for symbol in module.get("symbols", [])
            if symbol.get("name") == "IGameSystem_GamePostInit"
        )

        self.assertEqual(
            ["IGameSystem_GamePostInit.{platform}.yaml"],
            skill["expected_output"],
        )
        self.assertEqual(
            ["IGameSystem_LoopPostInitAllSystems.{platform}.yaml"],
            skill["expected_input"],
        )
        self.assertEqual("vfunc", symbol["category"])
        self.assertIn("IGameSystem::GamePostInit", symbol["alias"])
```

- [ ] **Step 2: 运行测试，确认它因为 script / config 尚未落地而失败**

Run: `uv run python -m unittest tests.test_igamesystem_slot_dispatch_preprocessor`

Expected: FAIL，错误包含以下任一信息即可：
- `ModuleNotFoundError: No module named 'ida_preprocessor_scripts.find-IGameSystem_GamePostInit'`
- `StopIteration`（表示 `config.yaml` 尚未注册 `find-IGameSystem_GamePostInit`）

- [ ] **Step 3: 新建薄封装 skill 并更新 `config.yaml`**

```python
#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_GamePostInit skill."""

from ida_preprocessor_scripts._igamesystem_slot_dispatch_common import (
    preprocess_igamesystem_slot_dispatch_skill,
)

DISPATCHER_YAML_STEM = "IGameSystem_LoopPostInitAllSystems"

TARGET_SPECS = [
    {
        "target_name": "IGameSystem_GamePostInit",
        "vtable_name": "IGameSystem",
        "dispatch_rank": 0,
    },
]

EXPECTED_DISPATCH_COUNT = 1


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
    _ = image_base

    return await preprocess_igamesystem_slot_dispatch_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        dispatcher_yaml_stem=DISPATCHER_YAML_STEM,
        target_specs=TARGET_SPECS,
        multi_order="index",
        expected_dispatch_count=EXPECTED_DISPATCH_COUNT,
        debug=debug,
    )
```

```yaml
      - name: find-IGameSystem_GameShutdown
        expected_output:
          - IGameSystem_GameShutdown.{platform}.yaml
        expected_input:
          - CGameRulesGameSystem_GameShutdown.{platform}.yaml

      - name: find-IGameSystem_GamePostInit
        expected_output:
          - IGameSystem_GamePostInit.{platform}.yaml
        expected_input:
          - IGameSystem_LoopPostInitAllSystems.{platform}.yaml
```

```yaml
      - name: IGameSystem_GameShutdown
        category: vfunc
        alias:
          - IGameSystem::GameShutdown

      - name: IGameSystem_GamePostInit
        category: vfunc
        alias:
          - IGameSystem::GamePostInit
```

- [ ] **Step 4: 重新跑专用测试，确认 helper + skill + config 一起通过**

Run: `uv run python -m unittest tests.test_igamesystem_slot_dispatch_preprocessor`

Expected: PASS，输出包含 `OK`

## Task 4: 做一次目标化回归，确认没有破坏现有预处理入口

**Files:**
- Test: `tests/test_igamesystem_slot_dispatch_preprocessor.py`
- Test: `tests/test_ida_preprocessor_scripts.py`

- [ ] **Step 1: 先跑新加的专用测试文件**

Run: `uv run python -m unittest tests.test_igamesystem_slot_dispatch_preprocessor -v`

Expected: PASS，逐条列出 `TestBuildIgameSystemSlotDispatchPyEval`、`TestPreprocessIgameSystemSlotDispatchSkill`、`TestGamePostInitSkill`、`TestGamePostInitConfig` 的通过结果

- [ ] **Step 2: 再跑现有预处理总测试文件做冒烟**

Run: `uv run python -m unittest tests.test_ida_preprocessor_scripts -v`

Expected: PASS；如果存在与本改动无关的既有失败，先记录失败名称并停止扩散修改，不在本任务里顺手修 unrelated case

- [ ] **Step 3: 做一次配置和文件落点的人工复核**

Run: `rg -n "find-IGameSystem_GamePostInit|IGameSystem_GamePostInit" config.yaml ida_preprocessor_scripts tests -S`

Expected: 至少命中以下 4 处：
- `ida_preprocessor_scripts/find-IGameSystem_GamePostInit.py`
- `ida_preprocessor_scripts/_igamesystem_slot_dispatch_common.py`
- `config.yaml`
- `tests/test_igamesystem_slot_dispatch_preprocessor.py`

## 交付检查

- 新 helper 只读取 `new_binary_dir/{dispatcher_yaml_stem}.{platform}.yaml`
- 新 helper 不做 `xref_strings` 搜索
- 新 helper 不依赖 `IGameSystem_vtable` YAML
- `expected_dispatch_count` 对应的是去重后的 unique slot 数量
- `find-IGameSystem_GamePostInit.py` 只输出四个字段：
  - `func_name`
  - `vtable_name`
  - `vfunc_offset`
  - `vfunc_index`
- `config.yaml` 同时注册：
  - `find-IGameSystem_GamePostInit`
  - `IGameSystem_GamePostInit`

## 执行说明

- 默认先执行 Task 1 和 Task 2，把 helper 语义锁死
- Task 3 再接 skill 和 config，避免把“helper 逻辑错误”和“注册缺失”混在一起排查
- Task 4 只做目标化回归，不扩展到全仓库测试

# CEntitySystem_RemoveEntity Preprocessor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增 `find-CEntitySystem_RemoveEntity` 预处理脚本，并通过可复用工具类从 `SV_Kill_SmokeGrenade_CommandHandler` 内定位唯一直接 `call` / 尾调用 `jmp` 目标。

**Architecture:** 实现分三层：`_direct_branch_target_common.py` 负责读取源 YAML、扫描 IDA 函数内直接分支、按 `GENERATE_YAML_DESIRED_FIELDS` 写出目标 YAML；`find-CEntitySystem_RemoveEntity.py` 只声明源函数、目标函数和字段契约；`config.yaml` 把新 skill 接入现有预处理链。公共 helper 只支持直接 `call imm` / `jmp imm`，并在候选数量不是 1 时 fail-fast。

**Tech Stack:** Python 3、IDA MCP `py_eval`、PyYAML、`ida_analyze_util.write_func_yaml`、`ida_analyze_util.preprocess_gen_func_sig_via_mcp`

---

## File Structure

- Create: `ida_preprocessor_scripts/_direct_branch_target_common.py`
  - 公共 helper 与 `DirectBranchTargetLocator` 工具类
  - 负责 `py_eval` 扫描、唯一目标校验、函数信息查询、字段契约写出和 best-effort rename
- Create: `ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py`
  - 薄封装预处理脚本
  - 声明 `SOURCE_FUNCTION_NAME`、`TARGET_FUNCTION_NAMES`、`GENERATE_YAML_DESIRED_FIELDS`
- Modify: `config.yaml`
  - 在 `find-SV_Kill_SmokeGrenade_CommandHandler` 附近新增 `find-CEntitySystem_RemoveEntity`
  - 在 symbol metadata 中新增 `CEntitySystem_RemoveEntity`
- Create: `docs/superpowers/plans/2026-04-27-centitysystem-removeentity-preprocessor-implementation.md`
  - 当前实施计划文档

## Execution Constraints

- 不修改已有公共 helper 行为。
- 不运行完整 build 或完整 test。
- 定向验证只使用 `python -m py_compile` 和轻量静态 YAML 检查。
- YAML 输出字段必须完全由 `GENERATE_YAML_DESIRED_FIELDS` 决定。
- 所有预处理失败路径返回 `False`，不向上层抛出异常。

### Task 1: 新增直接分支目标公共 helper

**Files:**
- Create: `ida_preprocessor_scripts/_direct_branch_target_common.py`

- [ ] **Step 1: 创建 `_direct_branch_target_common.py`**

Create `ida_preprocessor_scripts/_direct_branch_target_common.py` with this full content:

```python
#!/usr/bin/env python3
"""Shared preprocess helpers for direct branch target skills."""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import (
    parse_mcp_result,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)


_SUPPORTED_FIELDS = {
    "func_name",
    "func_sig",
    "func_va",
    "func_rva",
    "func_size",
}


_DIRECT_BRANCH_TARGET_PY_EVAL = """import idaapi, idautils, idc, json
func_addr = __FUNC_ADDR__
allowed_mnemonics = set(__ALLOWED_MNEMONICS__)
result_obj = None
if not idaapi.get_func(func_addr):
    idaapi.add_func(func_addr)
func = idaapi.get_func(func_addr)

def _func_start_for_target(target_ea):
    target_func = idaapi.get_func(target_ea)
    if not target_func:
        idaapi.add_func(target_ea)
        target_func = idaapi.get_func(target_ea)
    if not target_func:
        return None
    return int(target_func.start_ea)

if func:
    targets = []
    seen = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        mnem = idc.print_insn_mnem(head).lower()
        if mnem not in allowed_mnemonics:
            continue
        insn = idaapi.insn_t()
        if not idaapi.decode_insn(insn, head):
            continue
        op = insn.ops[0]
        if op.type not in (idaapi.o_near, idaapi.o_far):
            continue
        refs = []
        for target_ea in idautils.CodeRefsFrom(head, False):
            target_start = _func_start_for_target(target_ea)
            if target_start is not None:
                refs.append(target_start)
        refs = sorted(set(refs))
        if len(refs) != 1:
            continue
        target_start = refs[0]
        if target_start in seen:
            continue
        seen.add(target_start)
        targets.append({
            "source_ea": hex(head),
            "source_mnemonic": mnem,
            "target_va": hex(target_start),
        })
    result_obj = {
        "source_func_va": hex(func.start_ea),
        "source_func_size": hex(func.end_ea - func.start_ea),
        "targets": targets,
    }
result = json.dumps(result_obj)
"""


def _debug(debug, message):
    if debug:
        print(f"    Preprocess: {message}")


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


def _normalize_requested_fields(generate_yaml_desired_fields, target_name, debug=False):
    if not generate_yaml_desired_fields:
        _debug(debug, "missing generate_yaml_desired_fields")
        return None

    desired_map = {}
    try:
        for symbol_name, fields in generate_yaml_desired_fields:
            desired_map[str(symbol_name)] = list(fields)
    except Exception:
        _debug(debug, "invalid generate_yaml_desired_fields")
        return None

    fields = desired_map.get(target_name)
    if not fields:
        _debug(debug, f"missing desired fields for {target_name}")
        return None

    normalized = []
    seen = set()
    for field in fields:
        field_name = str(field)
        if field_name not in _SUPPORTED_FIELDS:
            _debug(debug, f"unsupported requested field for {target_name}: {field_name}")
            return None
        if field_name in seen:
            _debug(debug, f"duplicate requested field for {target_name}: {field_name}")
            return None
        seen.add(field_name)
        normalized.append(field_name)

    return normalized


def _resolve_output_path(expected_outputs, target_name, platform, debug=False):
    filename = f"{target_name}.{platform}.yaml"
    matches = [
        path for path in expected_outputs if os.path.basename(path) == filename
    ]
    if len(matches) != 1:
        _debug(debug, f"expected exactly one output for {filename}")
        return None
    return matches[0]


async def _call_py_eval_json(session, code, debug=False, error_label="py_eval"):
    try:
        result = await session.call_tool(name="py_eval", arguments={"code": code})
        result_data = parse_mcp_result(result)
    except Exception:
        _debug(debug, f"{error_label} error")
        return None

    raw = None
    if isinstance(result_data, dict):
        stderr_text = result_data.get("stderr", "")
        if stderr_text and debug:
            print("    Preprocess: py_eval stderr:")
            print(str(stderr_text).strip())
        raw = result_data.get("result", "")
    elif result_data is not None:
        raw = str(result_data)

    if not raw:
        return None

    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        _debug(debug, f"invalid JSON result from {error_label}")
        return None


def _build_direct_branch_target_py_eval(func_va, allowed_mnemonics):
    normalized = [str(item).lower() for item in allowed_mnemonics]
    return (
        _DIRECT_BRANCH_TARGET_PY_EVAL
        .replace("__FUNC_ADDR__", str(func_va))
        .replace("__ALLOWED_MNEMONICS__", json.dumps(normalized))
    )


async def _rename_func_best_effort(session, func_va, func_name, debug=False):
    if not func_va or not func_name:
        return
    try:
        await session.call_tool(
            name="rename",
            arguments={
                "batch": {
                    "func": {"addr": str(func_va), "name": str(func_name)}
                }
            },
        )
    except Exception:
        _debug(debug, f"failed to rename {func_name} (non-fatal)")


class DirectBranchTargetLocator:
    """Locate one direct call/jmp target inside a known source function."""

    def __init__(self, session, debug=False):
        self.session = session
        self.debug = debug

    async def collect_targets(self, source_func_va, allowed_mnemonics=("call", "jmp")):
        code = _build_direct_branch_target_py_eval(
            func_va=source_func_va,
            allowed_mnemonics=allowed_mnemonics,
        )
        parsed = await _call_py_eval_json(
            session=self.session,
            code=code,
            debug=self.debug,
            error_label="py_eval collecting direct branch targets",
        )
        if not isinstance(parsed, dict):
            _debug(self.debug, "failed to collect direct branch targets")
            return None

        raw_targets = parsed.get("targets")
        if not isinstance(raw_targets, list):
            _debug(self.debug, "direct branch target result missing targets list")
            return None

        targets = []
        seen = set()
        for item in raw_targets:
            if not isinstance(item, dict):
                _debug(self.debug, "invalid direct branch target entry")
                return None
            target_va = item.get("target_va")
            try:
                target_va_int = _parse_int(target_va)
            except Exception:
                _debug(self.debug, f"invalid target_va: {target_va}")
                return None
            if target_va_int in seen:
                continue
            seen.add(target_va_int)
            targets.append(
                {
                    "source_ea": str(item.get("source_ea", "")),
                    "source_mnemonic": str(item.get("source_mnemonic", "")),
                    "target_va": hex(target_va_int),
                }
            )

        return targets

    async def query_func_info(self, target_va):
        try:
            target_va_int = _parse_int(target_va)
        except Exception:
            _debug(self.debug, f"invalid target func_va: {target_va}")
            return None

        code = (
            "import idaapi, json\n"
            f"target_ea = {target_va_int}\n"
            "func = idaapi.get_func(target_ea)\n"
            "if func and func.start_ea == target_ea:\n"
            "    result = json.dumps({\n"
            "        'func_va': hex(func.start_ea),\n"
            "        'func_size': hex(func.end_ea - func.start_ea),\n"
            "    })\n"
            "else:\n"
            "    result = json.dumps(None)\n"
        )
        parsed = await _call_py_eval_json(
            session=self.session,
            code=code,
            debug=self.debug,
            error_label="py_eval querying direct branch target function info",
        )
        return parsed if isinstance(parsed, dict) else None

    async def rename_func_best_effort(self, func_va, func_name):
        await _rename_func_best_effort(
            session=self.session,
            func_va=func_va,
            func_name=func_name,
            debug=self.debug,
        )


async def _build_requested_payload(
    session,
    target_name,
    requested_fields,
    func_info,
    image_base,
    debug=False,
):
    try:
        func_va = str(func_info["func_va"])
        func_va_int = _parse_int(func_va)
        func_size = str(func_info["func_size"])
    except Exception:
        _debug(debug, f"incomplete function info for {target_name}")
        return None

    available = {
        "func_name": target_name,
        "func_va": func_va,
        "func_size": func_size,
    }

    if "func_rva" in requested_fields:
        available["func_rva"] = hex(func_va_int - image_base)

    if "func_sig" in requested_fields:
        sig_info = await preprocess_gen_func_sig_via_mcp(
            session=session,
            func_va=func_va,
            image_base=image_base,
            debug=debug,
        )
        if not isinstance(sig_info, dict) or not sig_info.get("func_sig"):
            _debug(debug, f"failed to generate func_sig for {target_name}")
            return None
        available["func_sig"] = sig_info["func_sig"]
        if "func_rva" in requested_fields and sig_info.get("func_rva"):
            available["func_rva"] = sig_info["func_rva"]
        if "func_size" in requested_fields and sig_info.get("func_size"):
            available["func_size"] = sig_info["func_size"]

    payload = {}
    for field in requested_fields:
        if field not in available:
            _debug(debug, f"requested field is not available for {target_name}: {field}")
            return None
        payload[field] = available[field]

    return payload


async def preprocess_direct_branch_target_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    source_yaml_stem,
    target_name,
    generate_yaml_desired_fields,
    rename_to=None,
    allowed_mnemonics=("call", "jmp"),
    expected_target_count=1,
    debug=False,
):
    if yaml is None:
        _debug(debug, "PyYAML is required")
        return False

    if expected_target_count != 1:
        _debug(debug, "expected_target_count must be 1")
        return False

    requested_fields = _normalize_requested_fields(
        generate_yaml_desired_fields,
        target_name,
        debug=debug,
    )
    if requested_fields is None:
        return False

    output_path = _resolve_output_path(
        expected_outputs,
        target_name,
        platform,
        debug=debug,
    )
    if output_path is None:
        return False

    source_path = os.path.join(
        new_binary_dir,
        f"{source_yaml_stem}.{platform}.yaml",
    )
    source_yaml = _read_yaml(source_path)
    if not isinstance(source_yaml, dict) or not source_yaml.get("func_va"):
        _debug(debug, f"failed to read source function YAML: {source_path}")
        return False

    source_func_va = str(source_yaml["func_va"])
    locator = DirectBranchTargetLocator(session=session, debug=debug)
    targets = await locator.collect_targets(
        source_func_va=source_func_va,
        allowed_mnemonics=allowed_mnemonics,
    )
    if not isinstance(targets, list) or len(targets) != expected_target_count:
        count = len(targets) if isinstance(targets, list) else "N/A"
        _debug(
            debug,
            f"expected {expected_target_count} direct branch target, got {count}",
        )
        return False

    target_va = targets[0]["target_va"]
    func_info = await locator.query_func_info(target_va)
    if not isinstance(func_info, dict):
        _debug(debug, f"failed to query function info for {target_name}")
        return False

    payload = await _build_requested_payload(
        session=session,
        target_name=target_name,
        requested_fields=requested_fields,
        func_info=func_info,
        image_base=image_base,
        debug=debug,
    )
    if payload is None:
        return False

    write_func_yaml(output_path, payload)

    await locator.rename_func_best_effort(
        func_va=target_va,
        func_name=rename_to,
    )

    if debug:
        print(
            "    Preprocess: "
            f"written {os.path.basename(output_path)} from direct branch target {target_va}"
        )

    return True
```

- [ ] **Step 2: 编译检查公共 helper**

Run:

```bash
python -m py_compile ida_preprocessor_scripts/_direct_branch_target_common.py
```

Expected:

```text
no output, exit code 0
```

### Task 2: 新增 `find-CEntitySystem_RemoveEntity.py`

**Files:**
- Create: `ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py`

- [ ] **Step 1: 创建薄封装脚本**

Create `ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py` with this full content:

```python
#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_RemoveEntity skill."""

from ida_preprocessor_scripts._direct_branch_target_common import (
    preprocess_direct_branch_target_skill,
)


SOURCE_FUNCTION_NAME = "SV_Kill_SmokeGrenade_CommandHandler"

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_RemoveEntity",
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEntitySystem_RemoveEntity",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]


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
    _ = skill_name, old_yaml_map
    return await preprocess_direct_branch_target_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        source_yaml_stem=SOURCE_FUNCTION_NAME,
        target_name=TARGET_FUNCTION_NAMES[0],
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        rename_to=TARGET_FUNCTION_NAMES[0],
        debug=debug,
    )
```

- [ ] **Step 2: 编译检查两个新增 Python 文件**

Run:

```bash
python -m py_compile ida_preprocessor_scripts/_direct_branch_target_common.py ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py
```

Expected:

```text
no output, exit code 0
```

### Task 3: 接入 `config.yaml`

**Files:**
- Modify: `config.yaml`

- [ ] **Step 1: 在 skill 列表中新增 `find-CEntitySystem_RemoveEntity`**

Find this existing block near the server projectile commands:

```yaml
      - name: find-SV_Kill_SmokeGrenade_CommandHandler
        expected_output:
          - SV_Kill_SmokeGrenade_CommandHandler.{platform}.yaml
```

Change it to:

```yaml
      - name: find-SV_Kill_SmokeGrenade_CommandHandler
        expected_output:
          - SV_Kill_SmokeGrenade_CommandHandler.{platform}.yaml

      - name: find-CEntitySystem_RemoveEntity
        expected_output:
          - CEntitySystem_RemoveEntity.{platform}.yaml
        expected_input:
          - SV_Kill_SmokeGrenade_CommandHandler.{platform}.yaml
```

- [ ] **Step 2: 在 symbol metadata 中新增 `CEntitySystem_RemoveEntity`**

Find this existing block:

```yaml
      - name: SV_Kill_SmokeGrenade_CommandHandler
        category: func

      - name: CBaseModelEntity_SetModel
        category: func
        alias:
          - CBaseModelEntity::SetModel
```

Change it to:

```yaml
      - name: SV_Kill_SmokeGrenade_CommandHandler
        category: func

      - name: CEntitySystem_RemoveEntity
        category: func
        alias:
          - CEntitySystem::RemoveEntity

      - name: CBaseModelEntity_SetModel
        category: func
        alias:
          - CBaseModelEntity::SetModel
```

- [ ] **Step 3: 静态检查新增配置项**

Run:

```bash
python - <<'PY'
from pathlib import Path

text = Path("config.yaml").read_text(encoding="utf-8")
required = [
    "find-CEntitySystem_RemoveEntity",
    "CEntitySystem_RemoveEntity.{platform}.yaml",
    "SV_Kill_SmokeGrenade_CommandHandler.{platform}.yaml",
    "CEntitySystem::RemoveEntity",
]
missing = [item for item in required if item not in text]
if missing:
    raise SystemExit(f"missing config entries: {missing}")
print("config entries present")
PY
```

Expected:

```text
config entries present
```

### Task 4: 定向验证与收尾检查

**Files:**
- Verify: `ida_preprocessor_scripts/_direct_branch_target_common.py`
- Verify: `ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py`
- Verify: `config.yaml`

- [ ] **Step 1: 运行 Python 编译检查**

Run:

```bash
python -m py_compile ida_preprocessor_scripts/_direct_branch_target_common.py ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py
```

Expected:

```text
no output, exit code 0
```

- [ ] **Step 2: 检查字段契约没有被脚本绕过**

Run:

```bash
python - <<'PY'
from pathlib import Path

common = Path("ida_preprocessor_scripts/_direct_branch_target_common.py").read_text(encoding="utf-8")
script = Path("ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py").read_text(encoding="utf-8")

if "generate_yaml_desired_fields" not in common:
    raise SystemExit("common helper does not accept generate_yaml_desired_fields")
if "_build_requested_payload" not in common:
    raise SystemExit("common helper does not centralize requested payload building")
if "GENERATE_YAML_DESIRED_FIELDS" not in script:
    raise SystemExit("skill script does not declare GENERATE_YAML_DESIRED_FIELDS")
if "func_sig" not in script:
    raise SystemExit("skill script does not request func_sig")

print("field contract checks passed")
PY
```

Expected:

```text
field contract checks passed
```

- [ ] **Step 3: 查看最终 diff**

Run:

```bash
git diff -- ida_preprocessor_scripts/_direct_branch_target_common.py ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py config.yaml
```

Expected:

```text
diff shows only the new helper, the new skill script, and the two config.yaml insertions described in this plan
```

- [ ] **Step 4: 暂不运行完整测试或构建**

Do not run full test suites or build commands unless the user explicitly requests them. Record in the final implementation response that only targeted compile/static checks were run.

### Task 5: 提交实施改动

**Files:**
- Commit: `ida_preprocessor_scripts/_direct_branch_target_common.py`
- Commit: `ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py`
- Commit: `config.yaml`

- [ ] **Step 1: 检查工作区中本任务相关文件**

Run:

```bash
git status --short
```

Expected:

```text
new helper, new skill script, config.yaml changes, and this plan file may appear; unrelated pre-existing changes must not be reverted
```

- [ ] **Step 2: 提交实现文件**

Run:

```bash
git add ida_preprocessor_scripts/_direct_branch_target_common.py ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py config.yaml
git commit -m "feat(preprocessor): 新增 RemoveEntity 定位脚本"
```

Expected:

```text
commit succeeds
```

Do not commit unrelated files.

## Self-Review Notes

- Spec coverage: tasks cover the shared helper, concrete script, `config.yaml` skill wiring, symbol metadata, field-contract behavior, and targeted verification.
- Scope check: this is one bounded preprocessor addition, not multiple independent subsystems.
- Placeholder scan: this plan contains no deferred implementation placeholders.
- Type consistency: the helper entry is named `preprocess_direct_branch_target_skill`, the script imports that exact name, and `GENERATE_YAML_DESIRED_FIELDS` is passed through unchanged.

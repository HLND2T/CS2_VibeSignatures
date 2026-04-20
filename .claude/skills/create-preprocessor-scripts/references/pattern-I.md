# Pattern I -- Interface vfunc offset via thunk instruction walk

**Use when:** the target is a **pure interface vfunc** (e.g. `ILoopMode::HandleInputEvent`) where:
- No unique `func_sig` or `vfunc_sig` is feasible (the function is just a generic `jmp [reg+disp]` thunk, too short to sign uniquely)
- A concrete-class thunk function that wraps the interface call is already found (via its output YAML)
- That thunk body ends with exactly `jmp [reg+disp]` and the displacement IS the vtable offset

The script reads the thunk's `func_va` from its YAML, uses `py_eval` + `idaapi.decode_insn` to walk the function body, finds the first `jmp` instruction with an `o_displ` operand, and records the displacement as `vfunc_offset`.

## User inputs

- **Interface name** -- e.g. `ILoopMode`
- **Target vfunc name** -- e.g. `ILoopMode_HandleInputEvent`
- **Thunk function name** (predecessor) -- e.g. `CLoopTypeClientServerService_HandleInputEvent` (a concrete-class wrapper that does `jmp [reg+disp]`)
- **Module** -- where the thunk lives (e.g. `engine`)

## Template

```python
#!/usr/bin/env python3
"""Preprocess script for find-{TARGET_FUNC_NAME} skill.

Resolves {INTERFACE_CLASS}::{METHOD_NAME} vfunc_offset by walking instructions
inside {THUNK_FUNC_NAME} (a thin thunk) and reading the displacement byte of
the first 'jmp [reg+disp]' encountered. No LLM decompile required.
"""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import parse_mcp_result, write_func_yaml

PREDECESSOR_STEM = "{THUNK_FUNC_NAME}"
TARGET_FUNC_NAME = "{TARGET_FUNC_NAME}"
VTABLE_CLASS = "{INTERFACE_CLASS}"

_PY_EVAL_TEMPLATE = r"""
import idaapi, json

func_va = FUNC_VA_PLACEHOLDER

insn = idaapi.insn_t()
func = idaapi.get_func(func_va)
if func is None:
    result = json.dumps({"error": "function not found at " + hex(func_va)})
else:
    vfunc_offset = None
    ea = func.start_ea
    while ea < func.end_ea:
        length = idaapi.decode_insn(insn, ea)
        if length == 0:
            break
        mnem = insn.get_canon_mnem()
        if mnem == "jmp":
            op = insn.Op1
            # o_displ = displaced memory operand, e.g. [rax+28h]
            if op.type == idaapi.o_displ:
                vfunc_offset = int(op.addr) & 0xFFFF_FFFF
                break
        ea += length
    if vfunc_offset is not None:
        result = json.dumps({"vfunc_offset": vfunc_offset})
    else:
        result = json.dumps({"error": "no jmp+disp instruction found in function"})
"""


def _read_func_va(yaml_path):
    """Return func_va as int from a function YAML, or None on failure."""
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            va = data.get("func_va")
            if va is not None:
                return int(str(va), 0)
    except Exception:
        pass
    return None


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
    """Walk {THUNK_FUNC_NAME} instructions to extract {INTERFACE_CLASS} vfunc_offset."""
    _ = skill_name

    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required")
        return False

    # Determine expected output path
    expected_filename = f"{TARGET_FUNC_NAME}.{'{'}platform{'}'}.yaml"
    matching_outputs = [p for p in expected_outputs if os.path.basename(p) == expected_filename]
    if len(matching_outputs) != 1:
        if debug:
            print(f"    Preprocess: expected exactly one output for {expected_filename}, got {matching_outputs}")
        return False
    output_path = matching_outputs[0]

    # Reuse previous gamever result if available
    if TARGET_FUNC_NAME in old_yaml_map:
        old_data = old_yaml_map[TARGET_FUNC_NAME]
        vfunc_offset_raw = old_data.get("vfunc_offset")
        if vfunc_offset_raw is not None:
            try:
                vfunc_offset = int(str(vfunc_offset_raw), 0)
                if debug:
                    print(f"    Preprocess: reusing old vfunc_offset={hex(vfunc_offset)} for {TARGET_FUNC_NAME}")
                write_func_yaml(output_path, {
                    "func_name": TARGET_FUNC_NAME,
                    "vtable_name": VTABLE_CLASS,
                    "vfunc_offset": hex(vfunc_offset),
                    "vfunc_index": vfunc_offset // 8,
                })
                return True
            except (ValueError, TypeError):
                pass

    # Read thunk func_va from its output YAML
    predecessor_yaml = os.path.join(new_binary_dir, f"{PREDECESSOR_STEM}.{'{'}platform{'}'}.yaml")
    func_va = _read_func_va(predecessor_yaml)
    if func_va is None:
        if debug:
            print(f"    Preprocess: failed to read func_va from {predecessor_yaml}")
        return False

    if debug:
        print(f"    Preprocess: walking instructions at {hex(func_va)} to find jmp displacement")

    # Walk instructions via IDA to find the first jmp [reg+disp]
    py_code = _PY_EVAL_TEMPLATE.replace("FUNC_VA_PLACEHOLDER", str(func_va))
    try:
        raw = await session.call_tool("py_eval", {"code": py_code})
        result_data = parse_mcp_result(raw)
    except Exception as exc:
        if debug:
            print(f"    Preprocess: py_eval error: {exc}")
        return False

    result_str = None
    if isinstance(result_data, dict):
        if debug:
            stderr = result_data.get("stderr", "")
            if stderr:
                print(f"    Preprocess py_eval stderr: {stderr.strip()}")
        result_str = result_data.get("result", "")
    if not result_str:
        if debug:
            print("    Preprocess: empty py_eval result")
        return False

    try:
        payload = json.loads(result_str)
    except (json.JSONDecodeError, TypeError) as exc:
        if debug:
            print(f"    Preprocess: JSON parse error: {exc} — raw: {result_str[:200]}")
        return False

    if "error" in payload:
        if debug:
            print(f"    Preprocess: py_eval reported error: {payload['error']}")
        return False

    vfunc_offset = payload.get("vfunc_offset")
    if vfunc_offset is None:
        if debug:
            print("    Preprocess: vfunc_offset missing from py_eval result")
        return False

    vfunc_offset = int(vfunc_offset)
    vfunc_index = vfunc_offset // 8

    if debug:
        print(f"    Preprocess: resolved vfunc_offset={hex(vfunc_offset)} vfunc_index={vfunc_index}")

    write_func_yaml(output_path, {
        "func_name": TARGET_FUNC_NAME,
        "vtable_name": VTABLE_CLASS,
        "vfunc_offset": hex(vfunc_offset),
        "vfunc_index": vfunc_index,
    })
    return True
```

## Key differences from all other patterns

- Does NOT use `preprocess_common_skill` -- uses `py_eval` + `parse_mcp_result` + `write_func_yaml` directly
- No `TARGET_FUNCTION_NAMES`, `FUNC_XREFS`, `LLM_DECOMPILE`, `FUNC_VTABLE_RELATIONS`, or `INHERIT_VFUNCS`
- Imports: `json`, `os`, `yaml`, `parse_mcp_result` and `write_func_yaml` from `ida_analyze_util`
- Output fields: only `func_name`, `vtable_name`, `vfunc_offset`, `vfunc_index` -- no `func_va`, `func_sig`, or `vfunc_sig`
- Has a "reuse previous gamever" fast path that reads `vfunc_offset` from `old_yaml_map` before falling back to the instruction walk
- The `_PY_EVAL_TEMPLATE` uses a raw string (`r"""..."""`) to avoid f-string issues; `FUNC_VA_PLACEHOLDER` is replaced at runtime via `.replace()`
- `op.addr` is masked with `& 0xFFFF_FFFF` to strip any sign-extension artifacts from IDA's 64-bit representation
- config.yaml category is `vfunc`; `expected_input` is the thunk function's YAML (NOT `expected_input` for any vtable)
- No `llm_config` parameter in `preprocess_skill`

## When NOT to use Pattern I

- If a unique `func_sig` is feasible for the concrete thunk -> use Pattern B (`xref_signatures` on the thunk body bytes, combined with `FUNC_VTABLE_RELATIONS`)
- If the interface vfunc has a real function body (not just a thunk) -> use Pattern B or C
- If the offset is in a `call [reg+disp]` rather than `jmp [reg+disp]` -> the same template works, but change `mnem == "jmp"` to `mnem == "call"`

## Checklist

- [ ] `PREDECESSOR_STEM` matches the thunk function's YAML artifact stem
- [ ] `TARGET_FUNC_NAME` and `VTABLE_CLASS` are correct
- [ ] `_PY_EVAL_TEMPLATE` checks `mnem == "jmp"` (or `"call"` if the thunk uses `call` instead)
- [ ] `_PY_EVAL_TEMPLATE` checks `op.type == idaapi.o_displ` and masks with `& 0xFFFF_FFFF`
- [ ] `write_func_yaml` writes `func_name`, `vtable_name`, `vfunc_offset` (hex string), `vfunc_index` (int)
- [ ] config.yaml `expected_input` includes the thunk function's YAML (NOT a vtable YAML)
- [ ] No `llm_config` parameter

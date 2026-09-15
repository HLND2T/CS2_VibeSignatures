#!/usr/bin/env python3
"""Recover INetworkSystem::GetLocalAdr from server-init's known slot load."""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import parse_mcp_result, write_func_yaml

PREDECESSOR_STEM = "CNetworkGameServerBase_Init"
TARGET_FUNC_NAME = "INetworkSystem_GetLocalAdr"
VTABLE_CLASS = "INetworkSystem"
VFUNC_OFFSETS = {"windows": 0x110, "linux": 0x108}

_PY_EVAL_TEMPLATE = r"""
import idaapi, json
func = idaapi.get_func(FUNC_VA_PLACEHOLDER)
needle = OFFSET_PLACEHOLDER
offsets = []
if func:
    insn = idaapi.insn_t()
    ea = func.start_ea
    while ea < func.end_ea:
        size = idaapi.decode_insn(insn, ea)
        if not size:
            break
        for op in (insn.Op1, insn.Op2):
            if op.type == idaapi.o_displ:
                value = int(op.addr) & 0xffffffff
                if value <= 0x200 and value % 8 == 0 and value not in offsets:
                    offsets.append(value)
        ea += size
result = json.dumps({"found": needle in offsets, "offsets": offsets})
"""


async def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map,
                           new_binary_dir, platform, image_base, debug=False):
    """Verify the server-init slot load and write the abstract vfunc artifact."""
    _ = skill_name, old_yaml_map, image_base
    vfunc_offset = VFUNC_OFFSETS.get(platform)
    if vfunc_offset is None:
        return False
    output_name = f"{TARGET_FUNC_NAME}.{platform}.yaml"
    output_path = next((path for path in expected_outputs if os.path.basename(path) == output_name), None)
    if not output_path or yaml is None:
        return False
    source_path = os.path.join(new_binary_dir, f"{PREDECESSOR_STEM}.{platform}.yaml")
    try:
        with open(source_path, encoding="utf-8") as handle:
            func_va = int(str(yaml.safe_load(handle)["func_va"]), 0)
        code = _PY_EVAL_TEMPLATE.replace("FUNC_VA_PLACEHOLDER", str(func_va)).replace("OFFSET_PLACEHOLDER", str(vfunc_offset))
        result = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
        if debug:
            print(f"    Preprocess: slot scan result: {result!r}")
        payload = json.loads(result.get("result", "{}")) if isinstance(result, dict) else {}
    except Exception as exc:
        if debug:
            print(f"    Preprocess: slot scan failed: {exc}")
        return False
    if not payload.get("found"):
        if debug:
            print(f"    Preprocess: slot {hex(vfunc_offset)} absent from {PREDECESSOR_STEM}")
        return False
    write_func_yaml(output_path, {
        "func_name": TARGET_FUNC_NAME,
        "vtable_name": VTABLE_CLASS,
        "vfunc_offset": hex(vfunc_offset),
        "vfunc_index": vfunc_offset // 8,
    })
    return True

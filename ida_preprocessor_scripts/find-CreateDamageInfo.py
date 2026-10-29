#!/usr/bin/env python3
"""Resolve CreateDamageInfo from its current VScript registration descriptor."""

import json
from pathlib import Path

from ida_analyze_util import parse_mcp_result, preprocess_gen_func_sig_via_mcp, write_func_yaml

TARGET_FUNCTION_NAMES = ["CreateDamageInfo"]
HELP_STRING = (
    "(hInflictor, hAttacker, flDamage) - Allocate a damageinfo object, "
    "used as an argument to TakeDamage(). Call DestroyDamageInfo( hInfo ) to free the object."
)

GENERATE_YAML_DESIRED_FIELDS = [
    ("CreateDamageInfo", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]

# ScriptFunctionBinding_t stores its help at +0x10 and native callback at +0x40.
# These are registration-descriptor ABI fields, not CTakeDamageInfo member offsets.
_CALLBACK_PY_EVAL = r"""
import idaapi, ida_bytes, idautils, idc, json
help_text = __HELP__
script_name = "CreateDamageInfo"
candidates = []

def _text(ea):
    raw = idc.get_strlit_contents(ea)
    return raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw

def _has_name(ea):
    if _text(ea) == script_name:
        return True
    return ida_bytes.is_loaded(ea) and _text(ida_bytes.get_qword(ea)) == script_name

globals().update(locals())
for string in idautils.Strings():
    if str(string) != help_text:
        continue
    for ref in idautils.XrefsTo(string.ea):
        owner = idaapi.get_func(ref.frm)
        if not owner:
            continue
        values = {}
        descriptor = None
        named = False
        for index, ea in enumerate(idautils.Heads(ref.frm, owner.end_ea)):
            if index >= 96:
                break
            insn = idaapi.insn_t()
            if not idaapi.decode_insn(insn, ea):
                break
            mnem = idc.print_insn_mnem(ea).lower()
            if mnem in ("call", "ret", "retn"):
                break
            for operand in insn.ops:
                if operand.type == idaapi.o_mem and _has_name(operand.addr):
                    named = True
            dst, src = insn.ops[0], insn.ops[1]
            value = None
            if mnem == "lea" and src.type == idaapi.o_mem:
                value = src.addr
            elif mnem == "mov" and src.type == idaapi.o_reg:
                value = values.get(src.reg)
            elif mnem == "mov" and src.type == idaapi.o_imm:
                value = src.value
            elif mnem == "mov" and src.type == idaapi.o_mem:
                value = ida_bytes.get_qword(src.addr)
            if dst.type == idaapi.o_reg and insn.get_canon_feature() & idaapi.CF_CHG1:
                values.pop(dst.reg, None)
                if value is not None:
                    values[dst.reg] = value
            if mnem != "mov" or dst.type != idaapi.o_mem or src.type != idaapi.o_reg:
                continue
            if value == string.ea:
                descriptor = dst.addr - 0x10
            if descriptor is not None and dst.addr == descriptor + 0x40 and value is not None:
                target = idaapi.get_func(value)
                if named and target and target.start_ea == value:
                    candidates.append({"func_va": hex(value), "descriptor": hex(descriptor)})
result = json.dumps(candidates)
"""


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
    """Validate the named binding before generating a fresh function signature."""
    outputs = [path for path in expected_outputs if Path(path).name == f"CreateDamageInfo.{platform}.yaml"]
    if len(outputs) != 1:
        return False
    try:
        code = _CALLBACK_PY_EVAL.replace("__HELP__", json.dumps(HELP_STRING))
        response = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
        if response.get("stderr"):
            return False
        candidates = json.loads(response["result"])
    except (KeyError, TypeError, ValueError):
        return False
    if not isinstance(candidates, list) or len(candidates) != 1:
        if debug:
            print(f"    Preprocess: expected one CreateDamageInfo binding, got {candidates!r}")
        return False
    payload = await preprocess_gen_func_sig_via_mcp(
        session=session,
        func_va=candidates[0]["func_va"],
        image_base=image_base,
        debug=debug,
    )
    if not isinstance(payload, dict) or not payload.get("func_sig"):
        return False
    payload["func_name"] = "CreateDamageInfo"
    fields = GENERATE_YAML_DESIRED_FIELDS[0][1]
    if any(field not in payload for field in fields):
        return False
    write_func_yaml(outputs[0], {field: payload[field] for field in fields})
    return True

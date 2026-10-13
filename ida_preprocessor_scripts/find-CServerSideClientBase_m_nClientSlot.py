#!/usr/bin/env python3
"""Recover the client slot from GetPlayerInfo's returned member load."""

import json
from pathlib import Path

import yaml

from ida_analyze_util import parse_mcp_result, preprocess_gen_struct_offset_sig_via_mcp, write_struct_offset_yaml
from ida_preprocessor_scripts._define_inputfunc import _resolve_output_path


TARGET_STRUCT_MEMBER_NAMES = ["CServerSideClientBase_m_nClientSlot"]
GENERATE_YAML_DESIRED_FIELDS = [
    (TARGET_STRUCT_MEMBER_NAMES[0], ["struct_name", "member_name", "offset", "size", "offset_sig", "offset_sig_disp"]),
]

MEMBER_QUERY = r"""
import json, ida_funcs, ida_ua, idautils, idc
func = ida_funcs.get_func(source_va)
aliases = {this_register}
reads = []
if func:
    for ea in idautils.FuncItems(func.start_ea):
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            continue
        mnemonic = idc.print_insn_mnem(ea)
        dst, src = insn.ops[0], insn.ops[1]
        if mnemonic == 'mov' and dst.type == ida_ua.o_reg and src.type == ida_ua.o_reg:
            destination, origin = idc.print_operand(ea, 0), idc.print_operand(ea, 1)
            if origin in aliases:
                aliases.add(destination)
            else:
                aliases.discard(destination)
        if mnemonic == 'mov' and idc.print_operand(ea, 0) == 'eax' and src.type == ida_ua.o_displ:
            operand = idc.print_operand(ea, 1)
            if any('[' + reg + '+' in operand for reg in aliases) and ida_ua.get_dtype_size(src.dtype) == 4:
                reads.append({'ea': ea, 'offset': int(src.addr), 'size': 4})
        if mnemonic == 'call':
            aliases.difference_update(volatile_registers)
result = reads
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
    source_path = Path(new_binary_dir) / f"CServerSideClientBase_GetPlayerInfo.{platform}.yaml"
    source = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    params = {
        "source_va": int(source["func_va"], 0),
        "this_register": "rcx" if platform == "windows" else "rdi",
        "volatile_registers": ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]
        + (["rdi", "rsi"] if platform == "linux" else []),
    }
    code = f"import json\nnamespace = {params!r}\nexec({MEMBER_QUERY!r}, namespace)\nresult = json.dumps(namespace['result'])"
    response = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if response.get("stderr"):
        raise RuntimeError(response["stderr"])
    reads = json.loads(response.get("result", "null"))
    if not reads or len(reads) != 1:
        if debug:
            print(f"    Preprocess: expected one returned client member load, got {reads}")
        return False
    payload = await preprocess_gen_struct_offset_sig_via_mcp(
        session,
        "CServerSideClientBase",
        "m_nClientSlot",
        reads[0]["offset"],
        hex(reads[0]["ea"]),
        image_base,
        size=reads[0]["size"],
        debug=debug,
    )
    if payload is None and source.get("func_sig"):
        # Identical return epilogues cannot always be signed uniquely. The
        # validated predecessor signature anchors the freshly located load.
        payload = {
            "struct_name": "CServerSideClientBase",
            "member_name": "m_nClientSlot",
            "offset": hex(reads[0]["offset"]),
            "size": reads[0]["size"],
            "offset_sig": source["func_sig"],
            "offset_sig_disp": reads[0]["ea"] - int(source["func_va"], 0),
        }
    output = _resolve_output_path(expected_outputs, TARGET_STRUCT_MEMBER_NAMES[0], platform, debug)
    if not payload or not output:
        return False
    write_struct_offset_yaml(output, payload)
    return True

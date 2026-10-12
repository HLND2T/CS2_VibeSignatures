#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_m_entityNames skill."""

import json
from pathlib import Path

import yaml

from ida_analyze_util import parse_mcp_result, preprocess_common_skill, write_struct_offset_yaml

# x64 CUtlOrderedMap: comparator, storage allocator, then RB-tree bookkeeping.
MAP_FLAGS_OFFSET = 0xA
MAP_STORAGE_OFFSET = 0x10
MAP_ROOT_OFFSET = 0x18
MAP_SIZE = 0x20


def recover_map_base(accesses):
    """Intersect independent CUtlOrderedMap field accesses, not its storage subobject."""
    flags = {item["offset"] - MAP_FLAGS_OFFSET for item in accesses if item["kind"] == "flags"}
    storage = {item["offset"] - MAP_STORAGE_OFFSET for item in accesses if item["kind"] == "storage"}
    roots = {item["offset"] - MAP_ROOT_OFFSET for item in accesses if item["kind"] == "word"}
    candidates = flags & storage & roots
    return candidates.pop() if len(candidates) == 1 else None


async def _recover_linux_map(session, source_path, output):
    source = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    address = int(source["func_va"], 0)
    code = f"""
import idaapi, idautils, idc, ida_ua, json, re
function = idaapi.get_func({address})
accesses = []
aliases = {{'rdi'}}
PROLOGUE_INSTRUCTION_LIMIT = 16
heads = list(idautils.Heads(function.start_ea, function.end_ea)) if function else []
for ea in heads[:PROLOGUE_INSTRUCTION_LIMIT]:
    if idc.print_insn_mnem(ea) == 'mov' and idc.print_operand(ea, 1) in aliases:
        destination = idc.print_operand(ea, 0)
        if re.fullmatch(r'r[a-z0-9]+', destination): aliases.add(destination)
for ea in heads:
    insn = idautils.DecodeInstruction(ea)
    if not insn: continue
    mnemonic = idc.print_insn_mnem(ea)
    for number, op in enumerate(insn.ops):
        if op.type != idaapi.o_displ: continue
        text = idc.print_operand(ea, number)
        is_this = False
        for register in aliases:
            if '[' + register + '+' in text: is_this = True
        if not is_this: continue
        width = ida_ua.get_dtype_size(op.dtype)
        kind = None
        if mnemonic == 'test' and width == 2 and idc.get_operand_value(ea, 1) == 0x7fff:
            kind = 'flags'
        elif mnemonic == 'mov' and number == 1 and width == 8:
            kind = 'storage'
        elif mnemonic == 'movzx' and number == 1 and width == 2:
            kind = 'word'
        if kind: accesses.append({{'kind': kind, 'offset': int(op.addr)}})
result = json.dumps(accesses)
"""
    response = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
    if response.get("stderr"):
        raise RuntimeError(response["stderr"])
    accesses = json.loads(response.get("result", "null"))
    offset = recover_map_base(accesses or [])
    if offset is None or offset < 0:
        return False
    # The inlined lookup materializes m_Elements (+8), not the map itself.
    # Do not publish a signature whose displacement identifies that subobject.
    write_struct_offset_yaml(
        output,
        {
            "struct_name": "CEntitySystem",
            "member_name": "m_entityNames",
            "offset": hex(offset),
            "size": MAP_SIZE,
        },
    )
    return True


TARGET_STRUCT_MEMBER_NAMES = [
    "CEntitySystem_m_entityNames",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CEntitySystem_m_entityNames",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_AddEntityToNameMap.{platform}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "CEntitySystem_AddEntityToNameMap.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEntitySystem_m_entityNames",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
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
    llm_config=None,
    debug=False,
):
    """Reuse previous gamever offset_sig to locate target struct offset and write YAML."""
    if platform == "linux":
        outputs = [path for path in expected_outputs if Path(path).name == "CEntitySystem_m_entityNames.linux.yaml"]
        if len(outputs) != 1:
            return False
        return await _recover_linux_map(
            session, Path(new_binary_dir) / "CEntitySystem_AddEntityToNameMap.linux.yaml", outputs[0]
        )
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

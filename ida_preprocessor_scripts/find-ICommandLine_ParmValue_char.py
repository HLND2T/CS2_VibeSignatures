#!/usr/bin/env python3
"""Find the string command-line ParmValue call in LinkClasses or its helpers."""

import json

from ida_analyze_util import (
    _export_function_detail_via_mcp,
    _load_llm_decompile_target_details_via_mcp,
    parse_mcp_result,
    preprocess_common_skill,
)

TARGET_FUNCTION_NAMES = ["ICommandLine_ParmValue_char"]
LLM_DECOMPILE = [
    {
        "symbol_name": "ICommandLine_ParmValue_char",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/engine/CNetworkGameClientBase_LinkClasses.{platform}.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"CNetworkGameClientBase_LinkClasses.{platform}.yaml": "required"},
    },
]
FUNC_VTABLE_RELATIONS = [("ICommandLine_ParmValue_char", "ICommandLine")]
GENERATE_YAML_DESIRED_FIELDS = [
    ("ICommandLine_ParmValue_char", ["func_name", "vtable_name", "vfunc_offset", "vfunc_index", "vfunc_sig"]),
]


def select_anchor_details(details):
    """Require a unique owner of the command-line token; reject ambiguous chains."""
    matches = [
        detail
        for detail in details
        if any(token in detail.get("procedure", "").lower() for token in ("3223879006", "-1071088290", "0xc0287d5e"))
    ]
    return matches if len(matches) == 1 else []


async def load_target_details(session, target_func_names, **kwargs):
    roots = await _load_llm_decompile_target_details_via_mcp(session, target_func_names, **kwargs)
    if len(roots) != 1:
        return []
    # Keep the normal inline path fast. If it disappears, inspect bounded direct
    # call/tail-jump chains, including local thunks; never guess a fixed helper VA.
    if select_anchor_details(roots):
        return roots
    root_va = int(roots[0]["func_va"], 0)
    code = f"""
import ida_funcs, ida_segment, idautils, idc, json
pending = [({root_va}, 0)]
seen = set()
addresses = []
overflow = False
while pending:
    ea, depth = pending.pop(0)
    if ea in seen:
        continue
    seen.add(ea)
    if len(seen) > 64:
        overflow = True
        break
    function = ida_funcs.get_func(ea)
    if not function or function.start_ea != ea:
        continue
    if ea != {root_va}:
        addresses.append(hex(ea))
    if depth >= 3:
        continue
    for insn in idautils.FuncItems(ea):
        if idc.print_insn_mnem(insn) not in ('call', 'jmp') or idc.get_operand_type(insn, 0) not in (idc.o_near, idc.o_far):
            continue
        for target in idautils.CodeRefsFrom(insn, False):
            callee = ida_funcs.get_func(target)
            segment = ida_segment.getseg(target)
            if callee and callee.start_ea == target and segment and segment.type == ida_segment.SEG_CODE:
                pending.append((target, depth + 1))
result = json.dumps({{'addresses': addresses, 'overflow': overflow}})
"""
    payload = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
    chain = json.loads(payload["result"])
    if chain["overflow"]:
        return []
    details = list(roots)
    for address in chain["addresses"]:
        detail = await _export_function_detail_via_mcp(session, "LinkClasses_helper", address)
        if detail:
            details.append(detail)
    return select_anchor_details(details)


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
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        llm_target_details_loader=load_target_details,
        debug=debug,
    )

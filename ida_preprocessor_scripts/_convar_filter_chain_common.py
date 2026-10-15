"""LLM discovery across inline bodies and bounded de-inlined ConVar helper chains."""

import json

from ida_analyze_util import (
    _export_function_detail_via_mcp,
    _load_llm_decompile_target_details_via_mcp,
    parse_mcp_result,
    preprocess_common_skill,
)


async def load_helper_details(session, target_func_names, **kwargs):
    roots = await _load_llm_decompile_target_details_via_mcp(session, target_func_names, **kwargs)
    if len(roots) != 1:
        return []
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
        detail = await _export_function_detail_via_mcp(session, "ConVar_helper", address)
        if not detail:
            return []
        details.append(detail)
    return details


async def preprocess_call_chain(**kwargs):
    """Try the predecessor body before following direct calls and tail jumps."""
    if await preprocess_common_skill(**kwargs):
        return True
    return await preprocess_common_skill(**kwargs, llm_target_details_loader=load_helper_details)

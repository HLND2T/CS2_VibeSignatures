"""Export the unique instance-dispatch owner through bounded direct-call chains."""

import json
import re

from ida_analyze_util import (
    _export_function_detail_via_mcp,
    _load_llm_decompile_target_details_via_mcp,
    parse_mcp_result,
)


def select_dispatch_owner(details):
    matches = [
        detail
        for detail in details
        if re.search(r"\(\*(?:\(_QWORD \*\))?a1\s*\+\s*\d+LL\)", detail.get("procedure", ""))
    ]
    return matches if len(matches) == 1 else []


async def load_target_details(session, target_func_names, **kwargs):
    roots = await _load_llm_decompile_target_details_via_mcp(session, target_func_names, **kwargs)
    if len(roots) != 1:
        return []
    if select_dispatch_owner(roots):
        return roots
    root_va = int(roots[0]["func_va"], 0)
    code = f"""
import ida_funcs, ida_segment, idautils, idc, json
pending = [({root_va}, 0)]
seen = set()
addresses = []
overflow = False
while pending:
    address, depth = pending.pop(0)
    if address in seen:
        continue
    seen.add(address)
    if len(seen) > 64:
        overflow = True
        break
    function = ida_funcs.get_func(address)
    if not function or function.start_ea != address:
        continue
    if address != {root_va}:
        addresses.append(hex(address))
    for instruction in idautils.FuncItems(address):
        if idc.print_insn_mnem(instruction) not in ('call', 'jmp'):
            continue
        if idc.get_operand_type(instruction, 0) not in (idc.o_near, idc.o_far):
            continue
        for target in idautils.CodeRefsFrom(instruction, False):
            callee = ida_funcs.get_func(target)
            segment = ida_segment.getseg(target)
            if callee and callee.start_ea == target and segment and segment.type == ida_segment.SEG_CODE:
                if depth >= 3 and target not in seen:
                    overflow = True
                elif depth < 3:
                    pending.append((target, depth + 1))
result = json.dumps({{'addresses': addresses, 'overflow': overflow}})
"""
    payload = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
    chain = json.loads(payload["result"])
    if chain["overflow"]:
        return []
    details = list(roots)
    for address in chain["addresses"]:
        detail = await _export_function_detail_via_mcp(session, "CvarEnumeration_helper", address)
        if not detail:
            return []
        details.append(detail)
    return select_dispatch_owner(details)

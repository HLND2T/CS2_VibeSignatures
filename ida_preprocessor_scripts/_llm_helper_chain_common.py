"""Bounded LLM fallback that follows direct calls and tail jumps when a predecessor is de-inlined.

A predecessor whose body was inlined in one build and de-inlined into helpers in
another must still be discoverable. This module owns the single implementation of
that walk; each target family binds its own export label so helper functions keep
a recognizable target-function heading in the LLM prompt.
"""

import json

from ida_analyze_util import (
    _export_function_detail_via_mcp,
    _load_llm_decompile_target_details_via_mcp,
    parse_mcp_result,
    preprocess_common_skill,
)

# A de-inlined predecessor can fan out widely, so the walk fails closed on the
# first budget overrun instead of handing a partial chain to the LLM.
MAX_CHAIN_FUNCTIONS = 64
MAX_CHAIN_DEPTH = 3


def make_helper_loader(export_label):
    """Build the bounded direct-call/tail-jump detail loader for one target family."""

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
    if len(seen) > {MAX_CHAIN_FUNCTIONS}:
        overflow = True
        break
    function = ida_funcs.get_func(ea)
    if not function or function.start_ea != ea:
        continue
    if ea != {root_va}:
        addresses.append(hex(ea))
    if depth >= {MAX_CHAIN_DEPTH}:
        continue
    for insn in idautils.FuncItems(ea):
        if idc.print_insn_mnem(insn) not in ("call", "jmp") or idc.get_operand_type(insn, 0) not in (idc.o_near, idc.o_far):
            continue
        for target in idautils.CodeRefsFrom(insn, False):
            callee = ida_funcs.get_func(target)
            segment = ida_segment.getseg(target)
            if callee and callee.start_ea == target and segment and segment.type == ida_segment.SEG_CODE:
                pending.append((target, depth + 1))
result = json.dumps({{"addresses": addresses, "overflow": overflow}})
"""
        chain = json.loads(
            parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))["result"]
        )
        if chain["overflow"]:
            return []
        details = list(roots)
        for address in chain["addresses"]:
            detail = await _export_function_detail_via_mcp(session, export_label, address)
            if not detail:
                return []
            details.append(detail)
        return details

    return load_helper_details


load_helper_details = make_helper_loader("GameEvent_helper")


async def preprocess_call_chain(helper_loader=None, **kwargs):
    """Try the predecessor body before following direct calls and tail jumps."""
    if await preprocess_common_skill(**kwargs):
        return True
    return await preprocess_common_skill(
        **kwargs,
        llm_target_details_loader=helper_loader or load_helper_details,
    )

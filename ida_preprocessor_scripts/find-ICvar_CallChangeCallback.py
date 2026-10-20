"""Find the change callback dispatch in SetValueInternal or its de-inlined helpers."""

import json

from ida_analyze_util import (
    _export_function_detail_via_mcp,
    _load_llm_decompile_target_details_via_mcp,
    parse_mcp_result,
    preprocess_common_skill,
)

TARGET_FUNCTION_NAMES = ["ICvar_CallChangeCallback"]
LLM_DECOMPILE = [
    {
        "symbol_name": "ICvar_CallChangeCallback",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/tier0/ConVarRefAbstract_SetValueInternal.{platform}.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"ConVarRefAbstract_SetValueInternal.{platform}.yaml": "required"},
    }
]
FUNC_VTABLE_RELATIONS = [("ICvar_CallChangeCallback", "ICvar")]
GENERATE_YAML_DESIRED_FIELDS = [
    ("ICvar_CallChangeCallback", ["func_name", "vtable_name", "vfunc_offset", "vfunc_index", "vfunc_sig"])
]


def validate_dispatch(result):
    """Reject multiple candidate dispatches instead of selecting the first one."""
    entries = [entry for entry in result.get("found_vcall", []) if entry.get("func_name") == TARGET_FUNCTION_NAMES[0]]
    return ["Expected one unambiguous ICvar_CallChangeCallback dispatch"] if len(entries) > 1 else []


async def load_helper_details(session, target_func_names, **kwargs):
    """Export bounded direct-call/tail-jump chains only after inline discovery fails."""
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
        detail = await _export_function_detail_via_mcp(session, "SetValueInternal_helper", address)
        if not detail:
            return []
        details.append(detail)
    return details


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
    kwargs = dict(
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
        llm_result_validator=validate_dispatch,
        debug=debug,
    )
    if await preprocess_common_skill(**kwargs):
        return True
    return await preprocess_common_skill(**kwargs, llm_target_details_loader=load_helper_details)

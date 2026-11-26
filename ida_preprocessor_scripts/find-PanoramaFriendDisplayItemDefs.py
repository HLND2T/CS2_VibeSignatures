#!/usr/bin/env python3
"""Find native friend display-item callbacks in their Panorama API registrars."""

import json

from ida_analyze_util import parse_mcp_result, preprocess_gen_func_sig_via_mcp, write_func_yaml
from ida_preprocessor_scripts._define_inputfunc import _resolve_output_path


API_COMPONENTS = {
    "FriendsListAPI": "CUiComponent_FriendsList",
    "PartyListAPI": "CUiComponent_PartyList",
}
METHODS = (
    "GetFriendDisplayItemDefCount",
    "GetFriendDisplayItemDefByIndex",
    "GetFriendDisplayItemDefFeatured",
)
TARGET_FUNCTION_NAMES = [f"{api}_{method}" for api in API_COMPONENTS for method in METHODS]


REGISTRATION_QUERY = r"""
import ida_bytes, ida_funcs, ida_idaapi, ida_segment, ida_ua, idautils, idc


def exact_string_refs(text):
    rdata = ida_segment.get_segm_by_name('.rdata')
    if not rdata:
        return set()
    refs = set()
    cursor = rdata.start_ea
    pattern = text.encode('ascii') + b'\0'
    while cursor < rdata.end_ea:
        ea = ida_bytes.find_bytes(pattern, cursor, range_end=rdata.end_ea)
        if ea == ida_idaapi.BADADDR:
            break
        if ida_bytes.get_item_head(ea) == ea:
            refs.update(ref for ref in idautils.DataRefsTo(ea) if ida_funcs.get_func(ref))
        cursor = ea + len(pattern)
    return refs


def is_lea(ea, register):
    return idc.print_insn_mnem(ea) == 'lea' and idc.print_operand(ea, 0) == register


def function_lea(ea):
    if not is_lea(ea, 'rax'):
        return None
    refs = list(idautils.DataRefsFrom(ea))
    if len(refs) == 1:
        func = ida_funcs.get_func(refs[0])
        if func and func.start_ea == refs[0]:
            return refs[0]
    return None


def stack_slot(ea, operand):
    insn = idautils.DecodeInstruction(ea)
    op = insn.ops[operand]
    text = idc.print_operand(ea, operand)
    if op.type in (ida_ua.o_phrase, ida_ua.o_displ) and ('[rsp' in text or '[rbp' in text):
        return op.reg, op.addr
    return None


def stored_rax(ea):
    if idc.print_insn_mnem(ea) == 'mov' and idc.print_operand(ea, 1) == 'rax':
        return stack_slot(ea, 0)
    return None


def registrars(api, component):
    api_wrappers = {ida_funcs.get_func(ref).start_ea for ref in exact_string_refs(api)}
    candidates = set()
    for ref in exact_string_refs(component):
        wrapper = ida_funcs.get_func(ref)
        if wrapper.start_ea not in api_wrappers or not is_lea(ref, 'rdx'):
            continue
        heads = list(idautils.FuncItems(wrapper.start_ea))
        index = heads.index(ref)
        before = heads[max(0, index - 3):index]
        after = heads[index + 1:index + 5]
        if len(after) != 4 or not before:
            continue
        load, store, vtable, invoke = after
        callback = function_lea(load)
        slot = stored_rax(store)
        descriptor = next((stack_slot(ea, 1) for ea in before if is_lea(ea, 'r8')), None)
        if (callback is not None and slot and descriptor
                and slot == (descriptor[0], descriptor[1] + 8)
                and idc.print_insn_mnem(vtable) == 'mov'
                and idc.print_operand(vtable, 0) == 'rax'
                and idc.print_operand(vtable, 1) == '[rcx]'
                and idc.print_insn_mnem(invoke) == 'call'
                and idc.print_operand(invoke, 0).startswith('qword ptr [rax+')):
            candidates.add(callback)
    return candidates


def method_callbacks(registrar, method):
    heads = list(idautils.FuncItems(registrar))
    candidates = set()
    for ref in exact_string_refs(method).intersection(heads):
        if not is_lea(ref, 'rcx'):
            continue
        index = heads.index(ref)
        # The registrar receives the method name and a stack descriptor in RDX.
        # Follow the pointer stored in that descriptor within this registration.
        block = []
        for ea in reversed(heads[:index]):
            mnemonic = idc.print_insn_mnem(ea)
            if mnemonic == 'call' or mnemonic.startswith('j'):
                break
            block.append(ea)
        descriptors = [stack_slot(ea, 1) for ea in block if is_lea(ea, 'rdx')]
        if len(descriptors) != 1 or descriptors[0] is None:
            continue
        following = heads[index + 1:index + 3]
        if len(following) != 2 or idc.print_insn_mnem(following[-1]) != 'call':
            continue
        invoke = idautils.DecodeInstruction(following[-1])
        if invoke.ops[0].type != ida_ua.o_near:
            continue
        for offset, store in enumerate(block[:-1]):
            if stored_rax(store) != descriptors[0]:
                continue
            callback = function_lea(block[offset + 1])
            if callback is not None:
                candidates.add(callback)
    return candidates


result = {}
for api, component in api_components.items():
    matches = registrars(api, component)
    if len(matches) != 1:
        continue
    for method in methods:
        result[f'{api}_{method}'] = sorted(method_callbacks(next(iter(matches)), method))
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
    if platform != "windows":
        return False

    params = {"api_components": API_COMPONENTS, "methods": METHODS}
    code = f"import json\nnamespace = {params!r}\nexec({REGISTRATION_QUERY!r}, namespace)\nresult = json.dumps(namespace['result'])"
    response = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if response.get("stderr"):
        raise RuntimeError(response["stderr"])
    matches = json.loads(response.get("result", "{}"))

    outputs = []
    for name in TARGET_FUNCTION_NAMES:
        candidates = matches.get(name, [])
        if len(candidates) != 1:
            if debug:
                print(f"    Preprocess: expected one Panorama callback for {name}, got {candidates}")
            return False
        output = _resolve_output_path(expected_outputs, name, platform, debug)
        payload = await preprocess_gen_func_sig_via_mcp(session, candidates[0], image_base, debug=debug)
        if not output or not payload:
            return False
        outputs.append((output, {"func_name": name, **payload}))

    for output, payload in outputs:
        write_func_yaml(output, payload)
    return True

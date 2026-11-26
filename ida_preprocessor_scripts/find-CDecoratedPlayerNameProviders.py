#!/usr/bin/env python3
"""Recover the player-name slot and XUID layout from Windows RTTI and code."""

import json

from ida_analyze_util import (
    parse_mcp_result,
    preprocess_gen_struct_offset_sig_via_mcp,
    preprocess_gen_vfunc_sig_via_mcp,
    preprocess_vtable_via_mcp,
    write_func_yaml,
    write_struct_offset_yaml,
    write_vtable_yaml,
)
from ida_preprocessor_scripts._define_inputfunc import _resolve_output_path


FRIENDS_PROVIDER = "CDecoratedPlayerNameProviderViaFriendsListApi"
TARGET_CLASS_NAMES = [
    FRIENDS_PROVIDER,
    "CDecoratedPlayerNameProviderViaLobbyApi",
    "CDecoratedPlayerNameProviderViaMatchDraftApi",
    "CDecoratedPlayerNameProviderViaPartyListApi",
]
TARGET_FUNCTION_NAMES = [f"{name}_GetPlayerName" for name in TARGET_CLASS_NAMES]
TARGET_STRUCT_MEMBER_NAMES = [f"{FRIENDS_PROVIDER}_m_xuid"]
POINTER_SIZE = 8


LAYOUT_QUERY = r"""
import ida_bytes, ida_funcs, ida_ua, idautils, idc


def body(ea):
    func = ida_funcs.get_func(ea)
    if func and func.start_ea == ea:
        return tuple(idautils.FuncItems(ea))
    return ()


def member_load(ea, destinations):
    insn = idautils.DecodeInstruction(ea)
    src = insn.ops[1]
    if (idc.print_insn_mnem(ea) == 'mov'
            and idc.print_operand(ea, 0) in destinations
            and src.type == ida_ua.o_displ
            and idc.print_operand(ea, 1).startswith('[rcx+')
            and ida_ua.get_dtype_size(src.dtype) == pointer_size):
        return src.addr
    return None


def dispatch_site():
    # The std::function vtable contains _Do_call, which dispatches to the
    # provider's name method. Match its body without baking in either slot.
    prefix = '??_7?$_Func_impl_no_alloc@V_lambda_3_@?1??GetDecoratedPlayerName2@IDecoratedPlayerNameProvider@@'
    vtables = [ea for ea, name in idautils.Names() if name.startswith(prefix)]
    sites = set()
    for vtable in vtables:
        for entry in idautils.DataRefsFrom(vtable):
            inspect_dispatch(entry, sites)
        # IDA stores a vtable as individual pointer data items.
        cursor = vtable + pointer_size
        while ida_bytes.get_item_head(cursor) == cursor and not ida_bytes.has_name(ida_bytes.get_full_flags(cursor)):
            entry = ida_bytes.get_qword(cursor)
            if not body(entry):
                break
            inspect_dispatch(entry, sites)
            cursor += pointer_size
    if len(vtables) == 1 and len(sites) == 1:
        return next(iter(sites))
    return None


def inspect_dispatch(entry, sites):
    heads = body(entry)
    if len(heads) != 3:
        return
    capture, load_vtable, jump = heads
    insn = idautils.DecodeInstruction(jump)
    target = insn.ops[0]
    if (member_load(capture, {'rcx'}) is not None
            and idc.print_insn_mnem(load_vtable) == 'mov'
            and idc.print_operand(load_vtable, 0) == 'rax'
            and idc.print_operand(load_vtable, 1) == '[rcx]'
            and idc.print_insn_mnem(jump) == 'jmp'
            and target.type == ida_ua.o_displ
            and idc.print_operand(jump, 0).startswith('qword ptr [rax+')
            and target.addr % pointer_size == 0):
        sites.add((jump, target.addr))


def provider_layout():
    dispatch = dispatch_site()
    if dispatch is None:
        return None
    site, slot = dispatch
    index = slot // pointer_size
    thunks = {}
    getters = []
    for name, entries in tables.items():
        if index not in entries:
            return None
        target = entries[index]
        heads = body(target)
        if len(heads) != 2:
            return None
        load, jump = heads
        offset = member_load(load, {'rcx', 'rdx'})
        if (offset is None or idc.print_insn_mnem(jump) != 'jmp'
                or idautils.DecodeInstruction(jump).ops[0].type != ida_ua.o_near):
            return None
        thunks[name] = [target, ida_funcs.get_func(target).end_ea - target]
        if name == friends_provider:
            for getter in set(entries.values()):
                instructions = body(getter)
                if (len(instructions) == 2 and member_load(getter, {'rax'}) == offset
                        and idc.print_insn_mnem(instructions[1]) == 'retn'):
                    getters.append((getter, offset))
    if len(getters) != 1:
        return None
    return {'site': site, 'slot': slot, 'index': index, 'thunks': thunks, 'getter': getters[0]}


result = provider_layout()
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False,
):
    if platform != "windows":
        return False

    tables = {}
    outputs = []
    for name in TARGET_CLASS_NAMES:
        output = _resolve_output_path(expected_outputs, f"{name}_vtable", platform, debug)
        table = await preprocess_vtable_via_mcp(session, name, image_base, platform, debug=debug)
        if not output or not table:
            return False
        tables[name] = {index: int(ea, 0) for index, ea in table["vtable_entries"].items()}
        outputs.append((write_vtable_yaml, output, table))

    params = {"tables": tables, "friends_provider": FRIENDS_PROVIDER, "pointer_size": POINTER_SIZE}
    code = f"import json\nnamespace = {params!r}\nexec({LAYOUT_QUERY!r}, namespace)\nresult = json.dumps(namespace['result'])"
    response = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if response.get("stderr"):
        raise RuntimeError(response["stderr"])
    layout = json.loads(response.get("result", "null"))
    if not layout:
        if debug:
            print("    Preprocess: could not verify a unique decorated-name dispatch and XUID getter")
        return False

    slot_signature = await preprocess_gen_vfunc_sig_via_mcp(
        session, layout["site"], layout["slot"], allow_across_function_boundary=True, debug=debug,
    )
    for name, (address, size) in layout["thunks"].items():
        function = f"{name}_GetPlayerName"
        output = _resolve_output_path(expected_outputs, function, platform, debug)
        if not output:
            return False
        payload = {
            "func_name": function,
            "func_va": address,
            "func_rva": address - image_base,
            "func_size": size,
            "vtable_name": name,
            "vfunc_offset": layout["slot"],
            "vfunc_index": layout["index"],
        }
        if slot_signature:
            payload["vfunc_sig"] = slot_signature["vfunc_sig"]
            payload["vfunc_sig_allow_across_function_boundary"] = True
        outputs.append((write_func_yaml, output, payload))

    getter, xuid_offset = layout["getter"]
    member = "m_xuid"
    output = _resolve_output_path(expected_outputs, f"{FRIENDS_PROVIDER}_{member}", platform, debug)
    if not output:
        return False
    payload = await preprocess_gen_struct_offset_sig_via_mcp(
        session, FRIENDS_PROVIDER, member, xuid_offset, getter, image_base,
        size=POINTER_SIZE, allow_across_function_boundary=True, debug=debug,
    )
    if payload is None:
        # The getter can have byte-identical copies. Its containing RTTI
        # vtable and agreement with the name thunk still identify the member.
        payload = {"struct_name": FRIENDS_PROVIDER, "member_name": member, "offset": xuid_offset, "size": POINTER_SIZE}
    else:
        payload["offset_sig_allow_across_function_boundary"] = True
    outputs.append((write_struct_offset_yaml, output, payload))

    for writer, output, payload in outputs:
        writer(output, payload)
    return True

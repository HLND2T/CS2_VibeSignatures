#!/usr/bin/env python3
"""Derive and validate the 14197 registration-permission byte setter/getter pair."""

import inspect
import json

from ida_analyze_util import parse_mcp_result
from ida_preprocessor_scripts._network_registry_vfunc_common import VFUNC_FIELDS
from ida_preprocessor_scripts._vtable_slot_anchor_common import (
    _load_vfunc_anchor_slot,
    _load_vtable_entries,
    _write_slot_func_yaml,
)

VTABLE_CLASS = "CNetworkMessages"
CALLBACK_NAME = "CNetworkMessages_RegisterNetworkFieldChangeCallbackInternal"
TARGET_FUNCTION_NAMES = [
    "CNetworkMessages_AllowAdditionalMessageRegistration",
    "CNetworkMessages_IsAdditionalMessageRegistrationAllowed",
]
ALLOW_SLOT_DELTA = 1
IS_ALLOWED_SLOT_DELTA = 2
GENERATE_YAML_DESIRED_FIELDS = [(name, list(VFUNC_FIELDS)) for name in TARGET_FUNCTION_NAMES]


def _probe_registration_byte_pair(setter_va, getter_va):
    """Run inside IDA: return the shared byte offset only for a simple this-based pair."""
    import ida_hexrays as hx

    setter = hx.decompile(setter_va)
    getter = hx.decompile(getter_va)
    if setter is None or getter is None or len(setter.argidx) != 2 or len(getter.argidx) != 1:
        return None
    if len(setter.body.cblock) != 1 or len(getter.body.cblock) != 1:
        return None
    write, read = setter.body.cblock[0], getter.body.cblock[0]
    if write.op != hx.cit_expr or read.op != hx.cit_return:
        return None

    def uncast(expr):
        while expr.op == hx.cot_cast:
            expr = expr.x
        return expr

    def field_offset(expr, receiver_index):
        expr = uncast(expr)
        if expr.type.get_size() != 1:
            return None
        if expr.op == hx.cot_memptr:
            receiver, offset = uncast(expr.x), expr.m
        elif expr.op == hx.cot_ptr:
            address = uncast(expr.x)
            if address.op != hx.cot_add:
                return None
            receiver, step = uncast(address.x), uncast(address.y)
            if step.op != hx.cot_num:
                return None
            scale = address.x.type.get_ptrarr_objsize() if address.x.type.is_ptr() else 1
            if scale <= 0:
                return None
            offset = step.numval() * scale
        else:
            return None
        if receiver.op != hx.cot_var or receiver.v.idx != receiver_index or offset <= 0:
            return None
        return int(offset)

    assignment = uncast(write.cexpr)
    if assignment.op != hx.cot_asg:
        return None
    value = uncast(assignment.y)
    if value.op != hx.cot_var or value.v.idx != setter.argidx[1]:
        return None
    written_offset = field_offset(assignment.x, setter.argidx[0])
    read_offset = field_offset(read.creturn.expr, getter.argidx[0])
    return written_offset if written_offset is not None and written_offset == read_offset else None


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
    """Validate the current callback anchor and its adjacent byte accessors."""
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    entries = _load_vtable_entries(new_binary_dir, VTABLE_CLASS, platform, debug=debug)
    if entries is None:
        return False
    callback_index = _load_vfunc_anchor_slot(
        new_binary_dir, platform, CALLBACK_NAME, VTABLE_CLASS, entries, debug=debug
    )
    if callback_index is None:
        return False

    slots = [callback_index + ALLOW_SLOT_DELTA, callback_index + IS_ALLOWED_SLOT_DELTA]
    if any(slot not in entries for slot in slots) or len({entries[slot] for slot in slots}) != len(slots):
        return False
    code = (
        inspect.getsource(_probe_registration_byte_pair)
        + f"\nimport json\nresult = json.dumps(_probe_registration_byte_pair({entries[slots[0]]}, {entries[slots[1]]}))\n"
    )
    try:
        parsed = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
        field_offset = json.loads(parsed.get("result") or "null")
        if type(field_offset) is not int or field_offset <= 0:
            if debug:
                print("    Preprocess: registration accessors do not form a matching byte setter/getter pair")
            return False
    except Exception as exc:
        if debug:
            print(f"    Preprocess: registration byte-pair validation failed: {exc}")
        return False
    if debug:
        print(f"    Preprocess: registration setter/getter share byte field {hex(field_offset)}")

    for name, slot in zip(TARGET_FUNCTION_NAMES, slots):
        if not await _write_slot_func_yaml(
            session=session,
            expected_outputs=expected_outputs,
            platform=platform,
            image_base=image_base,
            target_name=name,
            vtable_class=VTABLE_CLASS,
            vtable_entries=entries,
            slot=slot,
            generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
            debug=debug,
        ):
            return False
    return True

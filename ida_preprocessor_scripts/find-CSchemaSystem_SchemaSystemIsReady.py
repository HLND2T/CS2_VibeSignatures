#!/usr/bin/env python3
"""Resolve the ready getter immediately before VerifySchemaBindingConsistency.

The mismatch string identifies VerifySchemaBindingConsistency, not the ready
getter. Derive its slot from the current vtable, take the preceding slot in
ISchemaSystem's declaration order, and require a single byte load from this.
Do not reuse historical signatures: they identified the consistency checker.
"""

import inspect
import json

from ida_analyze_util import _collect_xref_func_starts_for_string, parse_mcp_result
from ida_preprocessor_scripts._vtable_slot_anchor_common import (
    _load_vtable_entries,
    _write_slot_func_yaml,
    select_lowest_string_slot,
)

TARGET_FUNCTION_NAME = "CSchemaSystem_SchemaSystemIsReady"
VTABLE_CLASS = "CSchemaSystem"
VERIFY_STRING = "%s\r\n\tMismatch - %s\r\n\tModule 1 - %s\r\n\tModule 2 - %s\r\n\r\n"
READY_SLOT_DELTA = -1


def _probe_ready_getter(func_va):
    """Run inside IDA: accept only `return *(byte *)(this + field_offset)`."""
    import ida_hexrays as hx

    cfunc = hx.decompile(func_va)
    if cfunc is None or not len(cfunc.argidx) or len(cfunc.body.cblock) != 1:
        return False
    statement = cfunc.body.cblock[0]
    if statement.op != hx.cit_return:
        return False

    def uncast(expr):
        while expr.op == hx.cot_cast:
            expr = expr.x
        return expr

    value = uncast(statement.creturn.expr)
    if value.op != hx.cot_ptr or value.type.get_size() != 1:
        return False
    address = uncast(value.x)
    if address.op != hx.cot_add:
        return False
    receiver, offset = uncast(address.x), uncast(address.y)
    return (
        receiver.op == hx.cot_var
        and receiver.v.idx == cfunc.argidx[0]
        and offset.op == hx.cot_num
        and offset.numval() > 0
    )


GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CSchemaSystem_SchemaSystemIsReady",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
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
    debug=False,
):
    """Re-derive the ready slot and validate the getter before generating its signature."""
    _ = skill_name, old_yaml_map
    entries = _load_vtable_entries(new_binary_dir, VTABLE_CLASS, platform, debug=debug)
    if entries is None:
        return False
    users = await _collect_xref_func_starts_for_string(session, f"FULLMATCH:{VERIFY_STRING}", debug=debug)
    if not users:
        return False
    verify_slot = select_lowest_string_slot(entries, users, expected_slot_count=1)
    if verify_slot is None or verify_slot + READY_SLOT_DELTA not in entries:
        return False
    ready_slot = verify_slot + READY_SLOT_DELTA
    code = (
        inspect.getsource(_probe_ready_getter)
        + f"\nimport json\nresult = json.dumps(_probe_ready_getter({entries[ready_slot]}))\n"
    )
    try:
        result = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
        if json.loads(result.get("result") or "null") is not True:
            return False
    except Exception as exc:
        if debug:
            print(f"    Preprocess: ready getter validation failed: {exc}")
        return False

    return await _write_slot_func_yaml(
        session=session,
        expected_outputs=expected_outputs,
        platform=platform,
        image_base=image_base,
        target_name=TARGET_FUNCTION_NAME,
        vtable_class=VTABLE_CLASS,
        vtable_entries=entries,
        slot=ready_slot,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

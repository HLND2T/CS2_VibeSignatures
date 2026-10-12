#!/usr/bin/env python3
"""Shared preprocess helpers that resolve a vfunc from a slot derived from the current binary.

Some vfuncs cannot be identified from their own bytes, so a function-head or
xref byte signature would only hold for the build it was written against:

* Twin accessors with byte-identical bodies (e.g. ``GetClassModuleName`` /
  ``GetEnumModuleName``). MSVC folds them into one function, GCC emits copies
  that differ only in RIP-relative displacements. A string that only the twin
  pair references selects exactly their vtable slots, and the interface
  declaration order selects the target -- the lowest of those slots.
* Thin vfuncs that own no string, but are always dispatched through a known
  caller's first argument (e.g. the schema registration routine calling
  ``ISchemaSystem::CompleteModuleRegistration`` on the ``ISchemaSystem *`` it
  received). The slot is read from the decompiled vcall whose vtable and
  ``this`` both come from that argument, so other vcalls in the caller (on
  other objects) never compete.

Both paths re-derive the slot on every run, take the function from the current
vtable artifact, and generate a fresh ``func_sig``; old-gamever signatures are
never reused, because a twin's signature can match the wrong twin after a
layout shift.
"""

import inspect
import json
import os

from ida_analyze_util import (
    _build_vtable_yaml_path,
    _collect_xref_func_starts_for_string,
    _read_yaml_file,
    parse_mcp_result,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)

SLOT_SIZE = 8

_SUPPORTED_FIELDS = {
    "func_name",
    "func_va",
    "func_rva",
    "func_size",
    "func_sig",
    "vtable_name",
    "vfunc_offset",
    "vfunc_index",
}


def _probe_receiver_vcall_offsets(func_va):
    """Run inside IDA: vtable byte offsets called through the first argument of ``func_va``."""
    import ida_hexrays as hx

    cfunc = hx.decompile(func_va)
    if cfunc is None or not len(cfunc.argidx):
        return None
    receiver = cfunc.argidx[0]

    def uncast(expr):
        while expr.op == hx.cot_cast:
            expr = expr.x
        return expr

    def is_receiver(expr):
        expr = uncast(expr)
        return expr.op == hx.cot_var and expr.v.idx == receiver

    def slot_offset(expr):
        # *(*(receiver) + K) or (*(receiver))[N] -> byte offset of the vtable slot.
        expr = uncast(expr)
        if expr.op == hx.cot_idx:
            index = uncast(expr.y)
            if index.op != hx.cot_num:
                return None
            offset = index.numval() * expr.type.get_size()
            base = uncast(expr.x)
        elif expr.op == hx.cot_ptr:
            address = uncast(expr.x)
            offset = 0
            if address.op == hx.cot_add:
                step = uncast(address.y)
                if step.op != hx.cot_num:
                    return None
                scale = address.x.type.get_ptrarr_objsize() if address.x.type.is_ptr() else 1
                offset = step.numval() * scale
                address = uncast(address.x)
            base = address
        else:
            return None
        if base.op == hx.cot_ptr and is_receiver(base.x):
            return offset
        return None

    # A slot load hoisted above an intervening call lands in a local first:
    # ``v = *(*(a1) + K); name = f(); v(a1, name);``.
    slot_vars = {}
    offsets = set()

    class Assignments(hx.ctree_visitor_t):
        def __init__(self):
            super().__init__(hx.CV_FAST)

        def visit_expr(self, expr):
            if expr.op == hx.cot_asg and uncast(expr.x).op == hx.cot_var:
                slot_vars.setdefault(uncast(expr.x).v.idx, set()).add(slot_offset(expr.y))
            return 0

    class Calls(hx.ctree_visitor_t):
        def __init__(self):
            super().__init__(hx.CV_FAST)

        def visit_expr(self, expr):
            if expr.op != hx.cot_call or not expr.a.size() or not is_receiver(expr.a[0]):
                return 0
            callee = uncast(expr.x)
            offset = slot_offset(callee)
            if offset is None and callee.op == hx.cot_var:
                assigned = slot_vars.get(callee.v.idx, set())
                if len(assigned) == 1 and None not in assigned:
                    offset = next(iter(assigned))
            if offset is not None:
                offsets.add(int(offset))
            return 0

    Assignments().apply_to(cfunc.body, None)
    Calls().apply_to(cfunc.body, None)
    return sorted(offsets)


def _debug(debug, message):
    if debug:
        print(f"    Preprocess: {message}")


def _parse_int(value):
    return int(str(value), 0) if isinstance(value, str) else int(value)


def select_lowest_string_slot(vtable_entries, string_users, expected_slot_count):
    """Return the lowest slot whose entry references the twin string, or None.

    ``string_users`` are function starts referencing the string; entries outside
    the vtable (non-virtual users) are ignored. Exactly ``expected_slot_count``
    slots must match, so a new string user or a lost twin fails closed instead
    of silently shifting the selection.
    """
    slots = sorted(index for index, func_va in vtable_entries.items() if func_va in string_users)
    if len(slots) != expected_slot_count:
        return None
    return slots[0]


def select_receiver_vcall_slot(vtable_entries, offsets):
    """Return the single slot index dispatched through the receiver, or None."""
    if not isinstance(offsets, list) or len(set(offsets)) != 1:
        return None
    offset = offsets[0]
    if offset < 0 or offset % SLOT_SIZE:
        return None
    index = offset // SLOT_SIZE
    return index if index in vtable_entries else None


def _normalize_requested_fields(generate_yaml_desired_fields, target_name, debug=False):
    matches = [fields for symbol_name, fields in generate_yaml_desired_fields if symbol_name == target_name]
    if len(matches) != 1:
        _debug(debug, f"expected one desired-field entry for {target_name}")
        return None
    requested = list(matches[0])
    unsupported = sorted(set(requested) - _SUPPORTED_FIELDS)
    if not requested or unsupported:
        _debug(debug, f"unsupported desired fields for {target_name}: {unsupported}")
        return None
    return requested


def _load_vtable_entries(new_binary_dir, vtable_class, platform, debug=False):
    vtable_data = _read_yaml_file(_build_vtable_yaml_path(new_binary_dir, vtable_class, platform))
    entries = vtable_data.get("vtable_entries") if isinstance(vtable_data, dict) else None
    if not isinstance(entries, dict) or not entries:
        _debug(debug, f"{vtable_class} vtable YAML missing or has no entries")
        return None
    try:
        return {int(index): _parse_int(func_va) for index, func_va in entries.items()}
    except (TypeError, ValueError):
        _debug(debug, f"{vtable_class} vtable YAML has invalid entries")
        return None


async def _write_slot_func_yaml(
    session,
    expected_outputs,
    platform,
    image_base,
    target_name,
    vtable_class,
    vtable_entries,
    slot,
    generate_yaml_desired_fields,
    debug=False,
):
    requested = _normalize_requested_fields(generate_yaml_desired_fields, target_name, debug=debug)
    if requested is None:
        return False
    filename = f"{target_name}.{platform}.yaml"
    outputs = [path for path in expected_outputs if os.path.basename(path) == filename]
    if len(outputs) != 1:
        _debug(debug, f"expected exactly one output path for {filename}")
        return False

    func_va = hex(vtable_entries[slot])
    sig_data = await preprocess_gen_func_sig_via_mcp(
        session=session, func_va=func_va, image_base=image_base, debug=debug
    )
    if not isinstance(sig_data, dict) or not sig_data.get("func_sig"):
        _debug(debug, f"failed to generate func_sig for {target_name} at {func_va}")
        return False

    available = {
        "func_name": target_name,
        "func_va": func_va,
        "func_rva": sig_data.get("func_rva"),
        "func_size": sig_data.get("func_size"),
        "func_sig": sig_data["func_sig"],
        "vtable_name": vtable_class,
        "vfunc_offset": hex(slot * SLOT_SIZE),
        "vfunc_index": slot,
    }
    missing = [field for field in requested if available.get(field) is None]
    if missing:
        _debug(debug, f"fields unavailable for {target_name}: {missing}")
        return False
    write_func_yaml(outputs[0], {field: available[field] for field in requested})

    try:
        await session.call_tool(name="rename", arguments={"batch": {"func": {"addr": func_va, "name": target_name}}})
    except Exception:
        _debug(debug, f"failed to rename {target_name} (non-fatal)")
    _debug(debug, f"{target_name} resolved to {vtable_class} vtable index {slot} at {func_va}")
    return True


async def preprocess_string_twin_vfunc_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    target_name,
    vtable_class,
    twin_string,
    expected_slot_count,
    generate_yaml_desired_fields,
    debug=False,
):
    """Resolve the first-declared twin: the lowest ``vtable_class`` slot referencing ``twin_string``."""
    vtable_entries = _load_vtable_entries(new_binary_dir, vtable_class, platform, debug=debug)
    if vtable_entries is None:
        return False
    string_users = await _collect_xref_func_starts_for_string(session, f"FULLMATCH:{twin_string}", debug=debug)
    if string_users is None:
        return False
    slot = select_lowest_string_slot(vtable_entries, string_users, expected_slot_count)
    if slot is None:
        _debug(debug, f"expected {expected_slot_count} {vtable_class} slots referencing {twin_string!r}")
        return False
    return await _write_slot_func_yaml(
        session,
        expected_outputs,
        platform,
        image_base,
        target_name,
        vtable_class,
        vtable_entries,
        slot,
        generate_yaml_desired_fields,
        debug=debug,
    )


async def preprocess_receiver_vcall_vfunc_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    target_name,
    vtable_class,
    caller_string,
    generate_yaml_desired_fields,
    debug=False,
):
    """Resolve the vfunc the unique ``caller_string`` user calls through its first argument."""
    vtable_entries = _load_vtable_entries(new_binary_dir, vtable_class, platform, debug=debug)
    if vtable_entries is None:
        return False
    callers = await _collect_xref_func_starts_for_string(session, f"FULLMATCH:{caller_string}", debug=debug)
    if not callers or len(callers) != 1:
        _debug(debug, f"expected one function referencing {caller_string!r}, got {sorted(callers or [])}")
        return False
    caller_va = next(iter(callers))

    code = (
        inspect.getsource(_probe_receiver_vcall_offsets)
        + f"\nimport json\nresult = json.dumps(_probe_receiver_vcall_offsets({caller_va}))\n"
    )
    try:
        parsed = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
        offsets = json.loads(parsed.get("result") or "null")
    except Exception as exc:
        _debug(debug, f"receiver vcall probe failed for {hex(caller_va)}: {exc}")
        return False
    slot = select_receiver_vcall_slot(vtable_entries, offsets)
    if slot is None:
        _debug(debug, f"expected one receiver vcall slot in {hex(caller_va)}, got offsets {offsets}")
        return False
    return await _write_slot_func_yaml(
        session,
        expected_outputs,
        platform,
        image_base,
        target_name,
        vtable_class,
        vtable_entries,
        slot,
        generate_yaml_desired_fields,
        debug=debug,
    )

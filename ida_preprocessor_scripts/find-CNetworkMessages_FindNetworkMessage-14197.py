#!/usr/bin/env python3
"""Resolve the exact-name lookup preceding the current partial-name lookup in 14197."""

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
PARTIAL_NAME = "CNetworkMessages_FindNetworkMessagePartial"
FIND_SLOT_DELTA = -1
TARGET_FUNCTION_NAMES = ["CNetworkMessages_FindNetworkMessage"]
# Retain the existing lookup's opt-in for traversing alignment padding during signing.
GENERATE_YAML_DESIRED_FIELDS = [
    (name, list(VFUNC_FIELDS) + ["func_sig_allow_across_function_boundary:true"]) for name in TARGET_FUNCTION_NAMES
]


def _probe_network_message_comparisons(func_va, partial_va):
    """Run inside IDA: distinguish equality lookup from its substring-lookup sibling."""
    import re

    import ida_hexrays as hx
    import ida_name

    def comparisons(address):
        cfunc = hx.decompile(address)
        if cfunc is None:
            return None
        found = set()

        class Calls(hx.ctree_visitor_t):
            def __init__(self):
                super().__init__(hx.CV_FAST)

            def visit_expr(self, expr):
                if expr.op != hx.cot_call:
                    return 0
                callee = expr.x
                while callee.op == hx.cot_cast:
                    callee = callee.x
                if callee.op != hx.cot_obj:
                    return 0
                raw = ida_name.get_name(callee.obj_ea) or ""
                if not raw:
                    return 0
                texts = {raw.lstrip("_")}
                # IDA's PLT aliases may add an underscore before an Itanium name.
                for candidate in {raw, raw[1:] if raw.startswith("__Z") else raw}:
                    demangled = ida_name.demangle_name(candidate, 0)
                    if demangled:
                        texts.add(demangled)
                for name in ("V_stricmp_fast", "V_stristr_fast"):
                    pattern = rf"(?<![A-Za-z0-9_]){re.escape(name)}(?:\s*\(|@|$)"
                    if any(re.search(pattern, text) for text in texts):
                        found.add(name)
                return 0

        Calls().apply_to(cfunc.body, None)
        return found

    return comparisons(func_va) == {"V_stricmp_fast"} and comparisons(partial_va) == {"V_stristr_fast"}


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
    """Validate the current sibling anchor and comparison calls before signing the target."""
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    entries = _load_vtable_entries(new_binary_dir, VTABLE_CLASS, platform, debug=debug)
    if entries is None:
        return False
    partial_index = _load_vfunc_anchor_slot(new_binary_dir, platform, PARTIAL_NAME, VTABLE_CLASS, entries, debug=debug)
    if partial_index is None:
        return False
    target_index = partial_index + FIND_SLOT_DELTA
    if target_index < 0 or target_index not in entries or entries[target_index] == entries[partial_index]:
        return False
    code = (
        inspect.getsource(_probe_network_message_comparisons)
        + f"\nimport json\nresult = json.dumps(_probe_network_message_comparisons({entries[target_index]}, {entries[partial_index]}))\n"
    )
    try:
        parsed = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
        if json.loads(parsed.get("result") or "null") is not True:
            if debug:
                print("    Preprocess: exact/partial lookup comparison validation failed")
            return False
    except Exception as exc:
        if debug:
            print(f"    Preprocess: lookup comparison probe failed: {exc}")
        return False
    return await _write_slot_func_yaml(
        session=session,
        expected_outputs=expected_outputs,
        platform=platform,
        image_base=image_base,
        target_name=TARGET_FUNCTION_NAMES[0],
        vtable_class=VTABLE_CLASS,
        vtable_entries=entries,
        slot=target_index,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

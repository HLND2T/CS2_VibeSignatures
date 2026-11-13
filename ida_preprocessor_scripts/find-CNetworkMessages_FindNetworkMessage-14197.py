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


def _resolve_imported_comparison_names(target_va, import_names):
    """Run inside IDA: resolve a direct import, native thunk, or bounded ELF PLT stub."""
    import ida_bytes
    import ida_funcs
    import ida_idp
    import ida_segment
    import ida_ua
    import idautils
    from ida_idaapi import BADADDR

    targets = {target_va} if target_va in import_names else set()
    func = None if targets else ida_funcs.get_func(target_va)
    if func is not None and func.start_ea == target_va:
        if func.flags & ida_funcs.FUNC_THUNK:
            thunk = ida_funcs.calc_thunk_func_target(func)
            destination = thunk[0] if isinstance(thunk, (tuple, list)) and thunk else thunk
            if type(destination) is int and destination not in (0, BADADDR) and destination in import_names:
                targets.add(destination)
        segment = ida_segment.getseg(target_va)
        if segment is not None and ida_segment.get_segm_name(segment) in {".plt", ".plt.sec", ".plt.got"}:
            # Source2's ELF PLT may start with a mov r11d tag, which IDA's
            # generic thunk resolver does not recognize. Prove its terminal
            # unconditional jump and follow only its code/GOT import bindings.
            max_plt_instructions = 4
            items = list(idautils.FuncItems(target_va))
            if not items or len(items) > max_plt_instructions:
                return []
            for index, site in enumerate(items):
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, site) <= 0:
                    return []
                features = insn.get_canon_feature()
                if index < len(items) - 1:
                    if features & (ida_idp.CF_CALL | ida_idp.CF_JUMP):
                        return []
                elif features & (ida_idp.CF_JUMP | ida_idp.CF_STOP) != (ida_idp.CF_JUMP | ida_idp.CF_STOP):
                    return []
            destinations = set(idautils.CodeRefsFrom(items[-1], False))
            for pointer in idautils.DataRefsFrom(items[-1]):
                destinations.add(pointer)
                destinations.add(ida_bytes.get_qword(pointer))
            targets.update(destination for destination in destinations if destination in import_names)
    if len(targets) > 1:
        raise ValueError(f"ambiguous import bindings for {hex(target_va)}: {sorted(targets)}")
    return [{"target_va": hex(target), "name": import_names[target]} for target in sorted(targets)]


def _probe_network_message_comparisons(func_va, partial_va):
    """Run inside IDA: distinguish equality lookup from its substring-lookup sibling."""
    import re

    import ida_hexrays as hx
    import ida_name
    import ida_nalt
    import idaapi

    import_names = {}

    def import_name(address, name, ordinal):
        if isinstance(name, str) and name:
            import_names[int(address)] = name
        return True

    for module_index in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(module_index, import_name)
    bindings_by_target = {}

    def comparisons(address):
        report = {"func_va": hex(address), "comparisons": [], "calls": [], "error": None}
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
                call = {
                    "inst_va": hex(int(getattr(expr, "ea", 0))),
                    "kind": getattr(callee, "opname", str(callee.op)),
                    "target_va": None,
                    "raw_name": "",
                    "demangled": [],
                    "import_bindings": [],
                }
                if len(report["calls"]) < 64:
                    report["calls"].append(call)
                if callee.op != hx.cot_obj:
                    if callee.op == hx.cot_helper:
                        call["raw_name"] = callee.helper or ""
                    return 0
                raw = ida_name.get_name(callee.obj_ea) or ""
                call["target_va"] = hex(int(callee.obj_ea))
                call["raw_name"] = raw
                if callee.obj_ea not in bindings_by_target:
                    bindings_by_target[callee.obj_ea] = _resolve_imported_comparison_names(callee.obj_ea, import_names)
                call["import_bindings"] = bindings_by_target[callee.obj_ea]
                identities = {raw} if raw else set()
                identities.update(binding["name"] for binding in call["import_bindings"])
                if not identities:
                    return 0
                texts = {identity.lstrip("_") for identity in identities}
                # IDA's PLT aliases may add an underscore before an Itanium name.
                for identity in identities:
                    for candidate in {identity, identity[1:] if identity.startswith("__Z") else identity}:
                        demangled = ida_name.demangle_name(candidate, 0)
                        if demangled:
                            if demangled not in call["demangled"]:
                                call["demangled"].append(demangled)
                            texts.add(demangled)
                for name in ("V_stricmp_fast", "V_stristr_fast"):
                    pattern = rf"(?<![A-Za-z0-9_]){re.escape(name)}(?:\s*\(|@|$)"
                    if any(re.search(pattern, text) for text in texts):
                        found.add(name)
                return 0

        try:
            cfunc = hx.decompile(address)
            if cfunc is None:
                report["error"] = "decompile returned no function"
            else:
                Calls().apply_to(cfunc.body, None)
        except Exception as exc:
            report["error"] = f"{type(exc).__name__}: {exc}"
        report["comparisons"] = sorted(found)
        return report

    exact, partial = comparisons(func_va), comparisons(partial_va)
    return {
        "valid": (
            exact["error"] is None
            and partial["error"] is None
            and exact["comparisons"] == ["V_stricmp_fast"]
            and partial["comparisons"] == ["V_stristr_fast"]
        ),
        "context": {
            "ida_version": idaapi.get_kernel_version(),
            "hexrays_version": hx.get_hexrays_version(),
            "input_md5": ida_nalt.retrieve_input_file_md5().hex(),
            "input_path": ida_nalt.get_input_file_path(),
        },
        "exact": exact,
        "partial": partial,
    }


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
        inspect.getsource(_resolve_imported_comparison_names)
        + "\n"
        + inspect.getsource(_probe_network_message_comparisons)
        + f"\nimport json\nresult = json.dumps(_probe_network_message_comparisons({entries[target_index]}, {entries[partial_index]}))\n"
    )
    try:
        parsed = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
        if parsed.get("stderr"):
            raise ValueError(f"IDA Python comparison probe failed: {parsed['stderr']}")
        report = json.loads(parsed.get("result") or "null")
        if debug:
            print(f"    Preprocess: lookup comparison evidence: {json.dumps(report, sort_keys=True)}")
        valid = isinstance(report, dict) and report.get("valid") is True and isinstance(report.get("context"), dict)
        for role, address, comparator in (
            ("exact", entries[target_index], "V_stricmp_fast"),
            ("partial", entries[partial_index], "V_stristr_fast"),
        ):
            detail = report.get(role) if isinstance(report, dict) else None
            valid = valid and (
                isinstance(detail, dict)
                and detail.get("func_va") == hex(address)
                and detail.get("comparisons") == [comparator]
                and detail.get("error") is None
                and isinstance(detail.get("calls"), list)
            )
        if not valid:
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

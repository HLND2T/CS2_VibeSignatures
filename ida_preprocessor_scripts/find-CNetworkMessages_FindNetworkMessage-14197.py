#!/usr/bin/env python3
"""Resolve the exact-name lookup preceding the current partial-name lookup in 14197."""

import inspect
import json

from ida_analyze_util import parse_mcp_result
from ida_preprocessor_scripts._elf_import_common import (
    _read_elf_import_bindings,
    _resolve_imported_comparison_names,
)
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


def _probe_network_message_comparisons(func_va, partial_va, resolve_imports, read_elf_imports):
    """Run inside IDA: distinguish equality lookup from its substring-lookup sibling."""
    import re

    import ida_hexrays as hx
    import ida_loader
    import ida_name
    import ida_nalt
    import idaapi

    import_names = {}

    def import_name(address, name, ordinal):
        if isinstance(name, str) and name:
            import_names[int(address)] = name
        return True

    import_module_count = ida_nalt.get_import_module_qty()
    for module_index in range(import_module_count):
        ida_nalt.enum_import_names(module_index, import_name)
    elf_bindings, elf_error = {}, None
    try:
        elf_bindings = read_elf_imports(
            [ida_loader.get_path(ida_loader.PATH_TYPE_CMD), ida_nalt.get_input_file_path()],
            idaapi.get_imagebase(),
            ida_nalt.retrieve_input_file_md5(),
        )
    except Exception as exc:
        elf_error = f"{type(exc).__name__}: {exc}"
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
                    bindings_by_target[callee.obj_ea] = resolve_imports(callee.obj_ea, import_names, elf_bindings)
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
            "import_module_count": import_module_count,
            "import_symbol_count": len(import_names),
            "elf_relocation_count": len(elf_bindings.get("relocations", {})),
            "elf_import_error": elf_error,
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
        inspect.getsource(_read_elf_import_bindings)
        + "\n"
        + inspect.getsource(_resolve_imported_comparison_names)
        + "\n"
        + inspect.getsource(_probe_network_message_comparisons)
        + f"\nimport json\nresult = json.dumps(_probe_network_message_comparisons({entries[target_index]}, {entries[partial_index]}, _resolve_imported_comparison_names, _read_elf_import_bindings))\n"
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

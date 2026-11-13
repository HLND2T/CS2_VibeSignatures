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


def _read_elf_import_bindings(input_paths, image_base, expected_md5):
    """Read loader bindings from the verified CS2 AMD64 shared object, independently of IDB annotations."""
    import hashlib
    import struct
    from pathlib import Path

    data = None
    for path in dict.fromkeys(input_paths):
        if not path or not Path(path).is_file():
            continue
        candidate = Path(path).read_bytes()
        if not candidate.startswith(b"\x7fELF"):
            return {}
        if hashlib.md5(candidate).digest() == expected_md5:
            data = candidate
            break
    if data is None:
        raise ValueError("ELF input matching the IDB MD5 is unavailable")

    header_format = struct.Struct("<16sHHIQQQIHHHHHH")
    section_format = struct.Struct("<IIQQQQIIQQ")
    rela_format = struct.Struct("<QQq")
    symbol_format = struct.Struct("<IBBHQQ")
    sht_strtab, sht_rela, sht_dynsym = 3, 4, 11
    shn_undef = 0
    stt_notype, stt_func = 0, 2
    r_x86_64_glob_dat, r_x86_64_jump_slot = 6, 7
    symbol_type_mask, relocation_type_mask, symbol_index_shift = 0xF, 0xFFFFFFFF, 32

    def region(offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError("ELF table extends beyond the input file")
        return data[offset : offset + size]

    def string(table, offset):
        end = table.find(b"\0", offset)
        if offset < 0 or offset >= len(table) or end < 0:
            raise ValueError("invalid ELF string offset")
        return table[offset:end].decode("utf-8")

    header = header_format.unpack(region(0, header_format.size))
    elf64_little_endian = b"\x7fELF\x02\x01\x01"
    et_dyn, em_x86_64 = 3, 62
    if not header[0].startswith(elf64_little_endian) or header[1:3] != (et_dyn, em_x86_64):
        raise ValueError("expected an ELF64 little-endian AMD64 shared object")
    section_offset, section_size, section_count, names_index = header[6], header[11], header[12], header[13]
    if section_size != section_format.size or not section_count or names_index >= section_count:
        raise ValueError("unsupported ELF section table")
    table = region(section_offset, section_size * section_count)
    sections = list(section_format.iter_unpack(table))
    names_section = sections[names_index]
    if names_section[1] != sht_strtab:
        raise ValueError("ELF section names do not reference a string table")
    names = region(names_section[4], names_section[5])
    plt_ranges, relocations = [], {}
    for section in sections:
        if string(names, section[0]) in {".plt", ".plt.sec", ".plt.got"}:
            region(section[4], section[5])
            plt_ranges.append((image_base + section[3], image_base + section[3] + section[5]))
        if section[1] != sht_rela:
            continue
        if section[9] != rela_format.size or section[5] % rela_format.size or section[6] >= section_count:
            raise ValueError("invalid ELF relocation table")
        symbols = sections[section[6]]
        if symbols[1] != sht_dynsym:
            continue
        if symbols[9] != symbol_format.size or symbols[5] % symbol_format.size or symbols[6] >= section_count:
            raise ValueError("invalid ELF dynamic symbol table")
        symbol_data = region(symbols[4], symbols[5])
        strings_section = sections[symbols[6]]
        if strings_section[1] != sht_strtab:
            raise ValueError("ELF symbols do not reference a string table")
        strings = region(strings_section[4], strings_section[5])
        for address, info, addend in rela_format.iter_unpack(region(section[4], section[5])):
            if info & relocation_type_mask not in (r_x86_64_glob_dat, r_x86_64_jump_slot):
                continue
            index = info >> symbol_index_shift
            if index >= len(symbol_data) // symbol_format.size:
                raise ValueError("ELF relocation symbol index is out of range")
            symbol = symbol_format.unpack_from(symbol_data, index * symbol_format.size)
            if symbol[3] != shn_undef or symbol[1] & symbol_type_mask not in (stt_notype, stt_func) or addend:
                continue
            name = string(strings, symbol[0])
            if not name:
                continue
            got_va = image_base + address
            if got_va in relocations and relocations[got_va] != name:
                raise ValueError(f"ambiguous ELF import binding at {hex(got_va)}")
            relocations[got_va] = name
    return {"plt_ranges": plt_ranges, "relocations": relocations}


def _resolve_imported_comparison_names(target_va, import_names, elf_bindings=None):
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
    elf_bindings = elf_bindings or {}
    plt_end = next((end for start, end in elf_bindings.get("plt_ranges", []) if start <= target_va < end), None)
    terminal = None
    if func is not None and func.start_ea == target_va:
        if func.flags & ida_funcs.FUNC_THUNK:
            thunk = ida_funcs.calc_thunk_func_target(func)
            destination = thunk[0] if isinstance(thunk, (tuple, list)) and thunk else thunk
            if type(destination) is int and destination not in (0, BADADDR) and destination in import_names:
                targets.add(destination)
        segment = ida_segment.getseg(target_va)
        if (
            plt_end is None
            and segment is not None
            and ida_segment.get_segm_name(segment) in {".plt", ".plt.sec", ".plt.got"}
        ):
            plt_end = func.end_ea
    if plt_end is not None:
        # Source2's tagged PLT stubs are not always recognized as thunks. Decode
        # their short straight-line body without relying on function/xref labels.
        max_plt_instructions = 4
        site = target_va
        for _ in range(max_plt_instructions):
            insn = ida_ua.insn_t()
            size = ida_ua.decode_insn(insn, site)
            if size <= 0 or site + size > plt_end:
                return []
            features = insn.get_canon_feature()
            if features & ida_idp.CF_CALL:
                return []
            if features & (ida_idp.CF_JUMP | ida_idp.CF_STOP):
                if features & (ida_idp.CF_JUMP | ida_idp.CF_STOP) == (ida_idp.CF_JUMP | ida_idp.CF_STOP):
                    terminal = (site, insn)
                break
            site += size
        if terminal is None:
            return []
        site, insn = terminal
        destinations = set(idautils.CodeRefsFrom(site, False))
        pointers = set(idautils.DataRefsFrom(site))
        if insn.ops[0].type == ida_ua.o_mem:
            pointers.add(insn.ops[0].addr)
        for pointer in pointers:
            destinations.add(pointer)
            destinations.add(ida_bytes.get_qword(pointer))
        targets.update(destination for destination in destinations if destination in import_names)
    if len(targets) > 1:
        raise ValueError(f"ambiguous import bindings for {hex(target_va)}: {sorted(targets)}")
    bindings = [{"target_va": hex(target), "name": import_names[target]} for target in sorted(targets)]
    if terminal is not None and insn.ops[0].type == ida_ua.o_mem:
        pointer = insn.ops[0].addr
        name = elf_bindings.get("relocations", {}).get(pointer)
        if name:
            if bindings and bindings[0]["name"] != name:
                raise ValueError(f"conflicting IDB and ELF import bindings for {hex(target_va)}")
            if not bindings:
                bindings.append({"target_va": hex(pointer), "name": name, "binding_kind": "elf_relocation"})
    return bindings


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

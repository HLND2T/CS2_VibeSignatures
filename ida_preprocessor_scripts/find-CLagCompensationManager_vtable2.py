#!/usr/bin/env python3
"""Preprocess script for find-CLagCompensationManager_vtable2 skill."""

import json
import os
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import parse_mcp_result, write_vtable_yaml


TARGET_CLASS_NAME = "CLagCompensationManager"
TARGET_OUTPUT_STEM = "CLagCompensationManager_vtable2"
MAIN_VTABLE_STEM = "CLagCompensationManager_vtable"
CANONICAL_VTABLE_SYMBOL = TARGET_OUTPUT_STEM


_PY_EVAL_TEMPLATE = r"""
import ida_auto, ida_bytes, ida_name, idaapi, ida_segment, idautils, idc, json

class_name = CLASS_NAME_PLACEHOLDER
platform = PLATFORM_PLACEHOLDER
main_vtable_va = MAIN_VTABLE_VA_PLACEHOLDER
image_base = IMAGE_BASE_PLACEHOLDER
debug_enabled = DEBUG_PLACEHOLDER
ptr_size = 8 if idaapi.inf_is_64bit() else 4

debug_trace = []

def _debug(message):
    if debug_enabled:
        debug_trace.append(str(message))

def _read_ptr(ea):
    return ida_bytes.get_qword(ea) if ptr_size == 8 else ida_bytes.get_dword(ea)

def _signed(value, bits):
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value

def _is_vtable_address_point(address_point):
    # RTTI structures reference their own Complete Object Locator (the pSelf
    # field), so DataRefsTo yields matches that are not vtable headers.  A real
    # address point starts with a pointer to executable code.
    if address_point == idaapi.BADADDR:
        return False
    ptr_value = _read_ptr(address_point)
    target_seg = ida_segment.getseg(ptr_value)
    return bool(target_seg) and bool(target_seg.perm & ida_segment.SEGPERM_EXEC)

def _resolve_vtable_func_start(ptr_value):
    func = idaapi.get_func(ptr_value)
    if func is not None and func.start_ea <= ptr_value < func.end_ea:
        return func.start_ea
    flags = ida_bytes.get_full_flags(ptr_value)
    if not ida_bytes.is_code(flags):
        try:
            ida_bytes.del_items(ptr_value, ida_bytes.DELIT_SIMPLE, ptr_size)
        except Exception:
            pass
        try:
            idc.create_insn(ptr_value)
        except Exception:
            pass
    try:
        idaapi.add_func(ptr_value)
        ida_auto.auto_wait()
    except Exception:
        pass
    func = idaapi.get_func(ptr_value)
    if func is None or not (func.start_ea <= ptr_value < func.end_ea):
        return None
    return func.start_ea

globals().update(locals())

# Collect every vtable address point belonging to this class.  A class with
# multiple polymorphic bases emits one vtable group per base sub-object.  The
# primary group is produced by the main vtable skill; the secondary group is
# selected here as "the group that is not the primary", so no sub-object byte
# offset is hardcoded.
address_points = []

if platform == "windows":
    col_prefix = "??_R4" + class_name + "@@6B"
    rdata_seg = ida_segment.get_segm_by_name(".rdata")
    try:
        names = list(idautils.Names())
    except Exception:
        names = []
    for col_addr, col_name in names:
        if not col_name.startswith(col_prefix):
            continue
        offset_to_top = _signed(ida_bytes.get_dword(col_addr + 4), 32)
        for ref in idautils.DataRefsTo(col_addr):
            if rdata_seg and not (rdata_seg.start_ea <= ref < rdata_seg.end_ea):
                continue
            address_points.append((ref + ptr_size, offset_to_top, col_name))
else:
    ti_name = "_ZTI" + str(len(class_name)) + class_name
    ti_addr = ida_name.get_name_ea(idaapi.BADADDR, ti_name)
    if ti_addr != idaapi.BADADDR:
        for ref in idautils.DataRefsTo(ti_addr):
            offset_to_top = _signed(_read_ptr(ref - ptr_size), ptr_size * 8)
            address_points.append((ref + ptr_size, offset_to_top, ti_name))

for address_point, offset_to_top, source in address_points:
    _debug("[group] " + hex(address_point) + " offset_to_top=" + str(offset_to_top) + " via " + source)

candidates = []
seen = set()
for address_point, offset_to_top, source in address_points:
    if address_point == idaapi.BADADDR or address_point == main_vtable_va:
        continue
    if address_point in seen:
        continue
    if not _is_vtable_address_point(address_point):
        _debug("[skip-non-vtable] " + hex(address_point) + " via " + source)
        continue
    seen.add(address_point)
    candidates.append((address_point, offset_to_top))

selected = None
if len(candidates) != 1:
    _debug("[result-none] non_primary_group_count=" + str(len(candidates)))
else:
    vtable_start, offset_to_top = candidates[0]
    vtable_seg = ida_segment.getseg(vtable_start)
    entries = {}
    count = 0
    for i in range(1000):
        ea = vtable_start + i * ptr_size
        if platform != "windows" and i > 0:
            name = ida_name.get_name(ea)
            if name and (name.startswith("_ZTV") or name.startswith("_ZTI")):
                break
        ptr_value = _read_ptr(ea)
        if ptr_value == 0 or ptr_value == 0xFFFFFFFFFFFFFFFF:
            break
        target_seg = ida_segment.getseg(ptr_value)
        if not target_seg:
            break
        if vtable_seg and (vtable_seg.start_ea <= ptr_value < vtable_seg.end_ea):
            break
        if not (target_seg.perm & ida_segment.SEGPERM_EXEC):
            break
        func_start = _resolve_vtable_func_start(ptr_value)
        if func_start is None:
            break
        entries[count] = hex(func_start)
        count += 1

    if count == 0:
        _debug("[result-none] empty secondary vtable at " + hex(vtable_start))
    else:
        _debug(
            "[selected] "
            + hex(vtable_start)
            + " offset_to_top="
            + str(offset_to_top)
            + " entries="
            + str(count)
        )
        selected = {
            "vtable_class": class_name,
            "vtable_symbol": ida_name.get_name(vtable_start) or (class_name + "_vtable2"),
            "vtable_va": hex(vtable_start),
            "vtable_rva": hex(vtable_start - image_base),
            "vtable_size": hex(count * ptr_size),
            "vtable_numvfunc": count,
            "vtable_entries": entries,
        }

result_obj = {"selected": selected}
if debug_enabled:
    result_obj["debug_trace"] = debug_trace
result = json.dumps(result_obj)
"""


def _read_yaml(path):
    if yaml is None:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _parse_int(value):
    return int(str(value), 0)


def _match_output(expected_outputs, platform):
    expected_filename = f"{TARGET_OUTPUT_STEM}.{platform}.yaml"
    matches = [output_path for output_path in expected_outputs if Path(output_path).name == expected_filename]
    return matches[0] if len(matches) == 1 else None


def _build_py_eval(platform, main_vtable_va, image_base, debug):
    return (
        _PY_EVAL_TEMPLATE.replace("CLASS_NAME_PLACEHOLDER", json.dumps(TARGET_CLASS_NAME))
        .replace("PLATFORM_PLACEHOLDER", json.dumps(platform))
        .replace("MAIN_VTABLE_VA_PLACEHOLDER", str(int(main_vtable_va)))
        .replace("IMAGE_BASE_PLACEHOLDER", str(int(image_base)))
        .replace("DEBUG_PLACEHOLDER", "True" if debug else "False")
    )


async def _lookup_vtable2(session, platform, main_vtable_va, image_base, debug):
    py_code = _build_py_eval(platform, main_vtable_va, image_base, debug)
    result = await session.call_tool(name="py_eval", arguments={"code": py_code})
    result_data = parse_mcp_result(result)
    raw = result_data.get("result", "") if isinstance(result_data, dict) else ""
    if not raw:
        return None
    payload = json.loads(raw)
    if debug:
        for line in payload.get("debug_trace", []):
            print(f"    Preprocess {TARGET_OUTPUT_STEM}: {line}")
    return payload.get("selected")


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
    """Generate the secondary (interface sub-object) vtable YAML for the manager."""
    _ = skill_name, old_yaml_map
    output_path = _match_output(expected_outputs, platform)
    main_data = _read_yaml(os.path.join(new_binary_dir, f"{MAIN_VTABLE_STEM}.{platform}.yaml"))
    if not output_path or not isinstance(main_data, dict):
        return False

    main_vtable_va = _parse_int(main_data["vtable_va"])
    selected = await _lookup_vtable2(session, platform, main_vtable_va, image_base, debug)
    if not isinstance(selected, dict):
        return False

    selected = dict(selected)
    selected["vtable_symbol"] = CANONICAL_VTABLE_SYMBOL
    write_vtable_yaml(output_path, selected)
    return True

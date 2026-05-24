#!/usr/bin/env python3
"""Preprocess script for find-CSource2Server_vtable2 skill."""

import json
import os
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import parse_mcp_result, write_vtable_yaml


TARGET_CLASS_NAME = "CSource2Server"
TARGET_OUTPUT_STEM = "CSource2Server_vtable2"
MAIN_VTABLE_STEM = "CSource2Server_vtable"

MANGLED_CLASS_NAMES = {
    "CSource2Server": [
        "??_R4CSource2Server@@6B@_0",
        "_ZTI14CSource2Server",
    ],
}


_PY_EVAL_TEMPLATE = r'''
import ida_auto, ida_bytes, ida_name, idaapi, ida_segment, idautils, idc, json

class_name = CLASS_NAME_PLACEHOLDER
symbol_name = SYMBOL_NAME_PLACEHOLDER
platform = PLATFORM_PLACEHOLDER
main_vtable_va = MAIN_VTABLE_VA_PLACEHOLDER
image_base = IMAGE_BASE_PLACEHOLDER
debug_enabled = DEBUG_PLACEHOLDER
ptr_size = 8 if idaapi.inf_is_64bit() else 4

candidates = []
debug_trace = []

def _debug(message):
    if debug_enabled:
        debug_trace.append(str(message))

def _read_ptr(ea):
    return ida_bytes.get_qword(ea) if ptr_size == 8 else ida_bytes.get_dword(ea)

def _resolve_func_start(ptr_value):
    target_seg = ida_segment.getseg(ptr_value)
    if not target_seg or not (target_seg.perm & ida_segment.SEGPERM_EXEC):
        return None

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

def _append_candidate(address_point, symbol, source):
    if address_point == idaapi.BADADDR:
        return
    if address_point == main_vtable_va:
        _debug("[skip] main vtable " + hex(address_point))
        return

    func_start = _resolve_func_start(_read_ptr(address_point))
    if func_start is None:
        _debug("[reject] " + source + " " + hex(address_point))
        return

    candidates.append({
        "vtable_class": class_name,
        "vtable_symbol": symbol,
        "vtable_va": hex(address_point),
        "vtable_rva": hex(address_point - image_base),
        "vtable_size": hex(ptr_size),
        "vtable_numvfunc": 1,
        "vtable_entries": {0: hex(func_start)},
    })

globals().update(locals())

symbol_addr = ida_name.get_name_ea(idaapi.BADADDR, symbol_name)
if symbol_addr != idaapi.BADADDR:
    for ref in idautils.DataRefsTo(symbol_addr):
        if platform == "windows":
            address_point = ref + ptr_size
            fallback_symbol = symbol_name + " ref " + hex(ref)
        else:
            address_point = ref + ptr_size
            fallback_symbol = symbol_name + " ref " + hex(ref)
        vtable_symbol = ida_name.get_name(address_point) or fallback_symbol
        _append_candidate(address_point, vtable_symbol, platform)

candidates = sorted(candidates, key=lambda item: int(item["vtable_va"], 16))
selected = candidates[0] if len(candidates) == 1 else None
if selected is None:
    _debug("[result-none] candidate_count=" + str(len(candidates)))

result_obj = {"selected": selected}
if debug_enabled:
    result_obj["candidates"] = candidates
    result_obj["debug_trace"] = debug_trace
result = json.dumps(result_obj)
'''


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
    matches = [
        output_path
        for output_path in expected_outputs
        if Path(output_path).name == expected_filename
    ]
    return matches[0] if len(matches) == 1 else None


def _symbol_name_for_platform(platform):
    aliases = MANGLED_CLASS_NAMES[TARGET_CLASS_NAME]
    if platform == "windows":
        return aliases[0]
    if platform == "linux":
        return aliases[1]
    return None


def _build_py_eval(platform, main_vtable_va, image_base, debug):
    symbol_name = _symbol_name_for_platform(platform)
    if not symbol_name:
        return None
    return (
        _PY_EVAL_TEMPLATE
        .replace("CLASS_NAME_PLACEHOLDER", json.dumps(TARGET_CLASS_NAME))
        .replace("SYMBOL_NAME_PLACEHOLDER", json.dumps(symbol_name))
        .replace("PLATFORM_PLACEHOLDER", json.dumps(platform))
        .replace("MAIN_VTABLE_VA_PLACEHOLDER", str(int(main_vtable_va)))
        .replace("IMAGE_BASE_PLACEHOLDER", str(int(image_base)))
        .replace("DEBUG_PLACEHOLDER", "True" if debug else "False")
    )


async def _lookup_vtable2(session, platform, main_vtable_va, image_base, debug):
    py_code = _build_py_eval(platform, main_vtable_va, image_base, debug)
    if not py_code:
        return None
    result = await session.call_tool(name="py_eval", arguments={"code": py_code})
    result_data = parse_mcp_result(result)
    raw = result_data.get("result", "") if isinstance(result_data, dict) else ""
    if not raw:
        return None
    payload = json.loads(raw)
    if debug:
        for line in payload.get("debug_trace", []):
            print(f"    Preprocess CSource2Server_vtable2: {line}")
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
    _ = skill_name, old_yaml_map
    output_path = _match_output(expected_outputs, platform)
    main_data = _read_yaml(os.path.join(new_binary_dir, f"{MAIN_VTABLE_STEM}.{platform}.yaml"))
    if not output_path or not isinstance(main_data, dict):
        return False

    try:
        main_vtable_va = _parse_int(main_data["vtable_va"])
        selected = await _lookup_vtable2(
            session, platform, main_vtable_va, image_base, debug
        )
    except Exception:
        return False

    if not isinstance(selected, dict):
        return False

    write_vtable_yaml(output_path, selected)
    return True

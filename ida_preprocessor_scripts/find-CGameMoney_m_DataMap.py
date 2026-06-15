#!/usr/bin/env python3
"""Preprocess script for find-CGameMoney_m_DataMap skill."""

import json

from ida_analyze_util import _build_ida_strings_enumerator_py_lines, write_gv_yaml
from ida_preprocessor_scripts._define_inputfunc import (
    _call_py_eval_json,
    _normalize_addr,
    _normalize_requested_fields,
    _normalize_segment_names,
    _resolve_output_path,
)

TARGET_NAME = "CGameMoney_m_DataMap"
FIELD_NAME = "m_OnMoneySpent"
DATAMAP_PTR_OFFSET = 0x10
ALLOWED_SEGMENT_NAMES = (".data",)
TARGET_SEGMENT_NAMES = (".data",)
GENERATE_YAML_DESIRED_FIELDS = [(TARGET_NAME, ["gv_name", "gv_va", "gv_rva"])]


def _indent(lines, spaces=4):
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" for line in lines)


def _build_datamap_gv_py_eval(
    field_name,
    datamap_ptr_offset=0x10,
    allowed_segment_names=(".data",),
    target_segment_names=(".data",),
):
    allowed_segments = _normalize_segment_names(allowed_segment_names) or ()
    target_segments = _normalize_segment_names(target_segment_names) or ()
    params = json.dumps(
        {
            "field_name": field_name,
            "datamap_ptr_offset": int(datamap_ptr_offset),
            "allowed_segment_names": list(allowed_segments),
            "target_segment_names": list(target_segments),
        }
    )
    string_setup = _indent(
        _build_ida_strings_enumerator_py_lines(strings_var_name="strings")
    )

    return f"""
import json, traceback
params = json.loads({params!r})

def _collect_candidates(params):
    import idaapi, idautils, idc, ida_bytes

    field_name = params["field_name"]
    datamap_ptr_offset = int(params["datamap_ptr_offset"])
    allowed_segment_names = set(params["allowed_segment_names"])
    target_segment_names = set(params["target_segment_names"])
    string_eas = []
    items = []
    seen_entries = set()

    def _seg_name(ea):
        seg = idaapi.getseg(ea)
        if not seg:
            return None
        return idc.get_segm_name(seg.start_ea)

    def _try_add_entry(entry_ea, string_xref_from=None):
        if entry_ea in seen_entries:
            return
        seen_entries.add(entry_ea)
        entry_seg_name = _seg_name(entry_ea)
        if entry_seg_name not in allowed_segment_names:
            return
        datamap_ptr_ea = entry_ea + datamap_ptr_offset
        datamap_ptr_seg_name = _seg_name(datamap_ptr_ea)
        if datamap_ptr_seg_name not in allowed_segment_names:
            return
        try:
            datamap_va = int(ida_bytes.get_qword(datamap_ptr_ea))
        except Exception:
            return
        datamap_seg_name = _seg_name(datamap_va)
        if datamap_seg_name not in target_segment_names:
            return
        items.append({{
            "string_ea": hex(string_ea),
            "xref_from": hex(entry_ea),
            "xref_seg_name": entry_seg_name,
            "datamap_ptr_ea": hex(datamap_ptr_ea),
            "datamap_ptr_seg_name": datamap_ptr_seg_name,
            "datamap_va": hex(datamap_va),
            "datamap_seg_name": datamap_seg_name,
        }})

{string_setup}
    for item in strings:
        try:
            if str(item) == field_name:
                string_eas.append(hex(int(item.ea)))
        except Exception:
            pass

    if len(string_eas) == 1:
        string_ea = int(string_eas[0], 16)
        for xref in idautils.XrefsTo(string_ea, 0):
            string_xref_from = int(xref.frm)
            _try_add_entry(string_xref_from, string_xref_from)
            if _seg_name(string_xref_from) not in allowed_segment_names:
                continue
            for parent_xref in idautils.XrefsTo(string_xref_from, 0):
                _try_add_entry(int(parent_xref.frm), string_xref_from)

    return {{"string_eas": string_eas, "items": items}}

try:
    collected = _collect_candidates(params)
    result = json.dumps({{
        "ok": True,
        "string_eas": collected["string_eas"],
        "items": collected["items"],
    }})
except Exception:
    result = json.dumps({{
        "ok": False,
        "traceback": traceback.format_exc(),
    }})
"""


async def _collect_datamap_candidates(
    session,
    field_name,
    datamap_ptr_offset=0x10,
    allowed_segment_names=(".data",),
    target_segment_names=(".data",),
    debug=False,
):
    code = _build_datamap_gv_py_eval(
        field_name=field_name,
        datamap_ptr_offset=datamap_ptr_offset,
        allowed_segment_names=allowed_segment_names,
        target_segment_names=target_segment_names,
    )
    parsed = await _call_py_eval_json(
        session=session,
        code=code,
        debug=debug,
        error_label="py_eval collecting DataMap global candidates",
    )
    if not isinstance(parsed, dict) or parsed.get("ok") is not True:
        if debug and isinstance(parsed, dict):
            traceback_text = parsed.get("traceback")
            if isinstance(traceback_text, str) and traceback_text.strip():
                print(traceback_text.rstrip())
        return None

    string_eas = parsed.get("string_eas")
    items = parsed.get("items")
    if not isinstance(string_eas, list) or len(string_eas) != 1:
        if debug:
            count = 0 if not isinstance(string_eas, list) else len(string_eas)
            print(f"    Preprocess: expected one string {field_name}, got {count}")
        return None
    if not isinstance(items, list) or not items:
        if debug:
            print(f"    Preprocess: no DataMap candidates for {field_name}")
        return None

    normalized_items = []
    required_keys = {
        "string_ea",
        "xref_from",
        "xref_seg_name",
        "datamap_ptr_ea",
        "datamap_ptr_seg_name",
        "datamap_va",
        "datamap_seg_name",
    }
    for item in items:
        if not isinstance(item, dict) or not required_keys.issubset(item):
            return None
        normalized = dict(item)
        for key in ("string_ea", "xref_from", "datamap_ptr_ea", "datamap_va"):
            addr = _normalize_addr(normalized.get(key))
            if addr is None:
                return None
            normalized[key] = addr
        if not all(isinstance(normalized.get(key), str) for key in (
            "xref_seg_name",
            "datamap_ptr_seg_name",
            "datamap_seg_name",
        )):
            return None
        normalized_items.append(normalized)

    normalized_string_ea = _normalize_addr(string_eas[0])
    if normalized_string_ea is None:
        return None
    return {"string_eas": [normalized_string_ea], "items": normalized_items}


def _build_gv_payload(target_name, requested_fields, gv_va, image_base):
    base_payload = {
        "gv_name": target_name,
        "gv_va": gv_va,
        "gv_rva": hex(int(str(gv_va), 0) - image_base),
    }
    return {field: base_payload[field] for field in requested_fields}


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Locate CGameMoney_m_DataMap from the m_OnMoneySpent DataMap descriptor."""
    _ = skill_name, old_yaml_map, new_binary_dir
    try:
        datamap_ptr_offset = int(DATAMAP_PTR_OFFSET)
        image_base_int = int(str(image_base), 0)
    except (TypeError, ValueError):
        return False
    if datamap_ptr_offset < 0:
        return False

    allowed_segment_names = _normalize_segment_names(ALLOWED_SEGMENT_NAMES)
    target_segment_names = _normalize_segment_names(TARGET_SEGMENT_NAMES)
    if allowed_segment_names is None or target_segment_names is None:
        return False

    requested_fields = _normalize_requested_fields(
        GENERATE_YAML_DESIRED_FIELDS,
        TARGET_NAME,
        debug=debug,
    )
    if requested_fields is None:
        return False

    output_path = _resolve_output_path(
        expected_outputs,
        TARGET_NAME,
        platform,
        debug=debug,
    )
    if output_path is None:
        return False

    candidates = await _collect_datamap_candidates(
        session=session,
        field_name=FIELD_NAME,
        datamap_ptr_offset=datamap_ptr_offset,
        allowed_segment_names=allowed_segment_names,
        target_segment_names=target_segment_names,
        debug=debug,
    )
    if not isinstance(candidates, dict):
        return False

    items = candidates.get("items")
    if not isinstance(items, list):
        return False
    filtered_items = [
        item
        for item in items
        if item.get("xref_seg_name") in allowed_segment_names
        and item.get("datamap_ptr_seg_name") in allowed_segment_names
        and item.get("datamap_seg_name") in target_segment_names
    ]
    if len(filtered_items) != 1:
        if debug:
            print(
                f"    Preprocess: expected one DataMap xref for {FIELD_NAME}, "
                f"got {len(filtered_items)}"
            )
        return False

    try:
        payload = _build_gv_payload(
            TARGET_NAME,
            requested_fields,
            filtered_items[0].get("datamap_va"),
            image_base_int,
        )
    except (KeyError, TypeError, ValueError):
        return False

    write_gv_yaml(output_path, payload)
    return True

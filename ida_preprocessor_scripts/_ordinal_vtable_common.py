#!/usr/bin/env python3
"""Shared helpers for locating ordinal vtable address points via IDA MCP."""

import json

from ida_analyze_util import parse_mcp_result


_ORDINAL_VTABLE_PY_EVAL_TEMPLATE = r'''
import ida_bytes, ida_name, idaapi, idautils, ida_segment, json

class_name = CLASS_NAME_PLACEHOLDER
candidate_symbols = CANDIDATE_SYMBOLS_PLACEHOLDER
ordinal = ORDINAL_PLACEHOLDER
expected_offset_to_top = EXPECTED_OFFSET_TO_TOP_PLACEHOLDER
debug_trace_enabled = DEBUG_TRACE_ENABLED_PLACEHOLDER
ptr_size = 8 if idaapi.inf_is_64bit() else 4
max_ptr_value = (1 << (ptr_size * 8)) - 1

candidates = []
debug_trace = []

def _debug(message):
    if debug_trace_enabled:
        debug_trace.append(str(message))

def _read_ptr(ea):
    if ptr_size == 8:
        return ida_bytes.get_qword(ea)
    return ida_bytes.get_dword(ea)

def _to_signed_ptr(value):
    if ptr_size == 8:
        sign_bit = 1 << 63
        mask = 1 << 64
    else:
        sign_bit = 1 << 31
        mask = 1 << 32
    if value & sign_bit:
        return value - mask
    return value

def _read_vtable_entries(address_point, is_linux=False):
    vtable_seg = ida_segment.getseg(address_point)
    entries = {}
    count = 0
    stop_reason = "loop_exhausted"
    for i in range(1000):
        ea = address_point + i * ptr_size
        if is_linux and i > 0:
            name = ida_name.get_name(ea)
            if name and (name.startswith("_ZTV") or name.startswith("_ZTI")):
                stop_reason = "encountered_linux_metadata_boundary"
                break
        ptr_value = _read_ptr(ea)
        if ptr_value == 0:
            if is_linux:
                entries[count] = hex(ptr_value)
                count += 1
                continue
            stop_reason = "encountered_null_entry"
            break
        if ptr_value == max_ptr_value:
            stop_reason = "encountered_max_pointer_sentinel"
            break
        target_seg = ida_segment.getseg(ptr_value)
        if not target_seg:
            stop_reason = "target_segment_missing"
            break
        if vtable_seg and vtable_seg.start_ea <= ptr_value < vtable_seg.end_ea:
            stop_reason = "encountered_pointer_into_vtable_segment"
            break
        if not (target_seg.perm & ida_segment.SEGPERM_EXEC):
            stop_reason = "target_segment_not_executable"
            break
        func = idaapi.get_func(ptr_value)
        if func is not None:
            entries[count] = hex(ptr_value)
            count += 1
            continue
        flags = ida_bytes.get_full_flags(ptr_value)
        if ida_bytes.is_code(flags):
            entries[count] = hex(ptr_value)
            count += 1
            continue
        stop_reason = "target_not_marked_as_code"
        break
    return entries, stop_reason

def _append_candidate(
    symbol,
    address_point,
    source,
    offset_to_top=None,
    is_linux=False,
):
    if address_point == idaapi.BADADDR:
        _debug(
            "[reject] source={source} symbol={symbol} address=BADADDR "
            "entry_count=0 reason=bad_address".format(
                source=source,
                symbol=symbol,
            )
        )
        return False
    entries, stop_reason = _read_vtable_entries(address_point, is_linux=is_linux)
    if not entries:
        _debug(
            "[reject] source={source} symbol={symbol} address={address} "
            "entry_count=0 reason={reason}".format(
                source=source,
                symbol=symbol,
                address=hex(address_point),
                reason=stop_reason,
            )
        )
        return False
    _debug(
        "[candidate] source={source} symbol={symbol} address={address} "
        "entry_count={entry_count} offset_to_top={offset_to_top} "
        "stop_reason={reason}".format(
            source=source,
            symbol=symbol,
            address=hex(address_point),
            entry_count=len(entries),
            offset_to_top=offset_to_top,
            reason=stop_reason,
        )
    )
    candidates.append({
        "vtable_class": class_name,
        "vtable_symbol": symbol,
        "vtable_va": hex(address_point),
        "vtable_size": hex(len(entries) * ptr_size),
        "vtable_numvfunc": len(entries),
        "vtable_entries": entries,
        "offset_to_top": offset_to_top,
        "source": source,
    })
    return True

def _symbol_matches_any_alias(symbol):
    if not candidate_symbols:
        return True
    if not symbol:
        return False
    for alias in candidate_symbols:
        if not alias:
            continue
        if symbol == alias or symbol.startswith(alias + " + "):
            return True
    return False

def _try_direct_symbol(symbol_name):
    if not symbol_name:
        return False
    addr = ida_name.get_name_ea(idaapi.BADADDR, symbol_name)
    if addr == idaapi.BADADDR:
        _debug(
            "[direct-miss] symbol={symbol}".format(
                symbol=symbol_name,
            )
        )
        return False
    if symbol_name.startswith("_ZTV"):
        return _append_candidate(
            symbol_name + " + " + hex(2 * ptr_size),
            addr + (2 * ptr_size),
            "alias",
            offset_to_top=0,
            is_linux=True,
        )
    return _append_candidate(symbol_name, addr, "alias")

globals().update(locals())

alias_hit = False
for symbol_name in candidate_symbols:
    if _try_direct_symbol(symbol_name):
        alias_hit = True

if not candidates or (candidate_symbols and not alias_hit):
    win_col_prefix = "??_R4" + class_name + "@@6B@"
    for col_addr, col_name in idautils.Names():
        if col_name == win_col_prefix or col_name.startswith(win_col_prefix + "_"):
            for ref in idautils.DataRefsTo(col_addr):
                symbol = ida_name.get_name(ref + ptr_size)
                if not symbol:
                    symbol = "vftable@" + hex(ref + ptr_size)
                if candidate_symbols and not _symbol_matches_any_alias(symbol):
                    _debug(
                        "[skip] source=windows-rtti symbol={symbol} address={address} "
                        "reason=alias_mismatch".format(
                            symbol=symbol,
                            address=hex(ref + ptr_size),
                        )
                    )
                    continue
                if _append_candidate(
                    symbol,
                    ref + ptr_size,
                    "windows-rtti",
                ):
                    alias_hit = True

if candidate_symbols and not alias_hit:
    _debug(
        "[result-none] reason=no_alias_candidate_matched aliases={aliases}".format(
            aliases=candidate_symbols,
        )
    )
    selected = None
else:
    if not candidates:
        typeinfo_name = "_ZTI" + str(len(class_name)) + class_name
        typeinfo_addr = ida_name.get_name_ea(idaapi.BADADDR, typeinfo_name)
        if typeinfo_addr != idaapi.BADADDR:
            for ref in idautils.DataRefsTo(typeinfo_addr):
                offset_to_top = _to_signed_ptr(_read_ptr(ref - ptr_size))
                address_point = ref + ptr_size
                symbol = ida_name.get_name(address_point)
                if not symbol:
                    symbol = (
                        typeinfo_name
                        + " ref "
                        + hex(ref)
                        + " offset_to_top "
                        + str(offset_to_top)
                    )
                _append_candidate(
                    symbol,
                    address_point,
                    "linux-typeinfo",
                    offset_to_top=offset_to_top,
                    is_linux=True,
                )

    filtered = candidates
    if expected_offset_to_top is not None:
        filtered = [
            candidate
            for candidate in filtered
            if candidate.get("offset_to_top") == expected_offset_to_top
        ]
        _debug(
            "[filter] expected_offset_to_top={expected} before={before} after={after}".format(
                expected=expected_offset_to_top,
                before=len(candidates),
                after=len(filtered),
            )
        )

    filtered = sorted(filtered, key=lambda candidate: int(candidate["vtable_va"], 16))
    if ordinal < 0 or ordinal >= len(filtered):
        _debug(
            "[result-none] reason=ordinal_out_of_range ordinal={ordinal} candidate_count={count}".format(
                ordinal=ordinal,
                count=len(filtered),
            )
        )
        selected = None
    else:
        selected = dict(filtered[ordinal])
        selected.pop("source", None)
        selected.pop("offset_to_top", None)
        _debug(
            "[selected] ordinal={ordinal} symbol={symbol} address={address} entry_count={entry_count}".format(
                ordinal=ordinal,
                symbol=selected.get("vtable_symbol"),
                address=selected.get("vtable_va"),
                entry_count=selected.get("vtable_numvfunc"),
            )
        )

if debug_trace_enabled:
    result = json.dumps({
        "selected": selected,
        "debug_trace": debug_trace,
    })
else:
    result = json.dumps(selected)
'''


def _build_ordinal_vtable_py_eval(
    *,
    class_name,
    ordinal,
    symbol_aliases=None,
    expected_offset_to_top=None,
    debug_trace_enabled=False,
):
    """Build the py_eval script for locating an ordinal vtable candidate."""
    return (
        _ORDINAL_VTABLE_PY_EVAL_TEMPLATE
        .replace("CLASS_NAME_PLACEHOLDER", json.dumps(str(class_name)))
        .replace(
            "CANDIDATE_SYMBOLS_PLACEHOLDER",
            json.dumps(list(symbol_aliases or [])),
        )
        .replace("ORDINAL_PLACEHOLDER", str(int(ordinal)))
        .replace(
            "EXPECTED_OFFSET_TO_TOP_PLACEHOLDER",
            "None" if expected_offset_to_top is None else str(int(expected_offset_to_top)),
        )
        .replace(
            "DEBUG_TRACE_ENABLED_PLACEHOLDER",
            "True" if debug_trace_enabled else "False",
        )
    )


async def preprocess_ordinal_vtable_via_mcp(
    session,
    class_name,
    ordinal,
    image_base,
    platform,
    debug=False,
    symbol_aliases=None,
    expected_offset_to_top=None,
):
    """Resolve an ordinal vtable candidate and normalize it to YAML-like fields."""
    _ = platform
    py_code = _build_ordinal_vtable_py_eval(
        class_name=class_name,
        ordinal=ordinal,
        symbol_aliases=symbol_aliases,
        expected_offset_to_top=expected_offset_to_top,
        debug_trace_enabled=debug,
    )

    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        result_data = parse_mcp_result(result)
    except Exception as exc:
        if debug:
            print(
                f"    Preprocess ordinal vtable: py_eval error for "
                f"{class_name}[{ordinal}]: {exc}"
            )
        return None

    vtable_info = None
    debug_trace = []
    if isinstance(result_data, dict):
        stderr_text = result_data.get("stderr", "")
        if stderr_text and debug:
            print("    Preprocess ordinal vtable py_eval stderr:")
            print(stderr_text.strip())
        stdout_text = result_data.get("stdout", "")
        if stdout_text and debug:
            print("    Preprocess ordinal vtable py_eval stdout:")
            print(stdout_text.strip())
        result_str = result_data.get("result", "")
        if debug and not result_str:
            print(
                f"    Preprocess ordinal vtable: empty py_eval result for "
                f"{class_name}[{ordinal}]"
            )
        if result_str:
            try:
                vtable_info = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                if debug:
                    print(
                        "    Preprocess ordinal vtable: invalid py_eval JSON "
                        f"for {class_name}[{ordinal}]: {result_str[:400]}"
                    )
                vtable_info = None
    elif debug:
        print(
            "    Preprocess ordinal vtable: unexpected py_eval payload type "
            f"for {class_name}[{ordinal}]: {type(result_data).__name__}"
        )
        if result_data is not None:
            print(f"    Preprocess ordinal vtable raw payload: {result_data}")

    if isinstance(vtable_info, dict) and (
        "selected" in vtable_info or "debug_trace" in vtable_info
    ):
        raw_debug_trace = vtable_info.get("debug_trace", [])
        if isinstance(raw_debug_trace, list):
            debug_trace = [str(line) for line in raw_debug_trace]
        vtable_info = vtable_info.get("selected")

    if debug and debug_trace:
        for line in debug_trace:
            print(f"    Preprocess ordinal vtable trace: {line}")

    if not isinstance(vtable_info, dict):
        if debug:
            print(
                f"    Preprocess ordinal vtable: no result for "
                f"{class_name}[{ordinal}]"
            )
        return None

    try:
        vtable_class = vtable_info["vtable_class"]
        vtable_symbol = vtable_info["vtable_symbol"]
        vtable_va = vtable_info["vtable_va"]
        vtable_size = vtable_info["vtable_size"]
        vtable_numvfunc = vtable_info["vtable_numvfunc"]
        vtable_va_int = int(vtable_va, 16)
        raw_entries = vtable_info.get("vtable_entries", {})
        if not isinstance(raw_entries, dict):
            raise TypeError("vtable_entries must be a dict")
        entries = {int(index): value for index, value in raw_entries.items()}
    except (KeyError, TypeError, ValueError):
        if debug:
            print(
                f"    Preprocess ordinal vtable: invalid result for "
                f"{class_name}[{ordinal}]"
            )
        return None

    return {
        "vtable_class": vtable_class,
        "vtable_symbol": vtable_symbol,
        "vtable_va": vtable_va,
        "vtable_rva": hex(vtable_va_int - image_base),
        "vtable_size": vtable_size,
        "vtable_numvfunc": vtable_numvfunc,
        "vtable_entries": entries,
    }

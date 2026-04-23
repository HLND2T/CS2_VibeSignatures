#!/usr/bin/env python3
"""Shared preprocess helpers for RegisterConCommand-like skills."""

import json
import os

from ida_analyze_util import (
    _build_ida_exact_string_index_py_lines,
    parse_mcp_result,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)


def _normalize_requested_fields(generate_yaml_desired_fields, target_name, debug=False):
    if not generate_yaml_desired_fields:
        if debug:
            print("    Preprocess: missing generate_yaml_desired_fields")
        return None

    desired_map = {}
    for symbol_name, fields in generate_yaml_desired_fields:
        desired_map[symbol_name] = list(fields)

    fields = desired_map.get(target_name)
    if not fields:
        if debug:
            print(f"    Preprocess: missing desired fields for {target_name}")
        return None
    return fields


def _resolve_output_path(expected_outputs, target_name, platform, debug=False):
    filename = f"{target_name}.{platform}.yaml"
    matches = [
        path for path in expected_outputs if os.path.basename(path) == filename
    ]
    if len(matches) != 1:
        if debug:
            print(f"    Preprocess: expected exactly one output for {filename}")
        return None
    return matches[0]


def _build_registerconcommand_py_eval(
    platform,
    command_name,
    help_string,
    search_window_before_call,
    search_window_after_xref,
    debug=False,
):
    params = json.dumps(
        {
            "platform": platform,
            "command_name": command_name,
            "help_string": help_string,
            "search_window_before_call": search_window_before_call,
            "search_window_after_xref": search_window_after_xref,
            "debug": bool(debug),
        }
    )
    string_index_lines = _build_ida_exact_string_index_py_lines(
        target_texts_var_name="target_texts",
        result_var_name="string_hits",
    )
    body_lines = [
        "import idaapi, idautils, idc, ida_bytes, ida_nalt",
        "global debug_log",
        "platform = params['platform']",
        f"search_window_before_call = {int(search_window_before_call)}",
        f"search_window_after_xref = {int(search_window_after_xref)}",
        "command_name = params['command_name']",
        "help_string = params['help_string']",
        "debug_enabled = bool(params.get('debug'))",
        "candidates = []",
        "debug_log = []",
        "seen_calls = set()",
        "seen_candidates = set()",
        "handler_slot_addr = None",
        "slot_value_addr = None",
        "reg_names_linux = [('rsi', 'esi'), ('rdx', 'edx'), ('r8', 'r8d')]",
        "reg_names_windows = [('rdx', 'edx'), ('r8', 'r8d'), ('r9', 'r9d')]",
        "def _debug(message):",
        "    if debug_enabled:",
        "        debug_log.append(str(message))",
        "def _fmt_ea(value):",
        "    if value in (None, 0, idaapi.BADADDR):",
        "        return 'None'",
        "    try:",
        "        return hex(int(value))",
        "    except Exception:",
        "        return repr(value)",
        "def _fmt_list(values):",
        "    return '[' + ', '.join(_fmt_ea(value) for value in values) + ']'",
        "def _fmt_line(ea):",
        "    if ea in (None, 0, idaapi.BADADDR):",
        "        return 'None'",
        "    try:",
        "        return (idc.generate_disasm_line(ea, 0) or '').strip()",
        "    except Exception:",
        "        return '<disasm unavailable>'",
        "def _seg_name(ea):",
        "    if ea in (None, 0, idaapi.BADADDR):",
        "        return None",
        "    seg = idaapi.getseg(ea)",
        "    if not seg:",
        "        return None",
        "    try:",
        "        return idc.get_segm_name(seg.start_ea)",
        "    except Exception:",
        "        return None",
        "def _read_string(ea):",
        "    if ea in (None, 0, idaapi.BADADDR):",
        "        return None",
        "    try:",
        "        raw = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)",
        "    except Exception:",
        "        raw = None",
        "    if raw is None:",
        "        return None",
        "    if isinstance(raw, bytes):",
        "        return raw.decode('utf-8', errors='ignore')",
        "    return str(raw)",
        "def _is_registerconcommand_call(ea):",
        "    if idc.print_insn_mnem(ea) not in ('call', 'jmp'):",
        "        return False",
        "    operand = idc.print_operand(ea, 0) or ''",
        "    line = idc.generate_disasm_line(ea, 0) or ''",
        "    return 'RegisterConCommand' in operand or 'RegisterConCommand' in line",
        "def _prev_head_in_window(start_ea, min_ea):",
        "    cur = idc.prev_head(start_ea, min_ea)",
        "    while cur != idaapi.BADADDR and cur >= min_ea:",
        "        yield cur",
        "        next_cur = idc.prev_head(cur, min_ea)",
        "        if next_cur == cur:",
        "            break",
        "        cur = next_cur",
        "def _expand_reg_names(reg_name):",
        "    names = []",
        "    raw = (reg_name or '').lower()",
        "    if raw:",
        "        names.append(raw)",
        "        if raw.startswith('r') and len(raw) == 3 and raw[1:].isdigit():",
        "            names.append(raw + 'd')",
        "        elif raw.startswith('r') and len(raw) == 3 and raw[1].isalpha():",
        "            names.append('e' + raw[1:])",
        "        elif raw.startswith('e') and len(raw) == 3:",
        "            names.append('r' + raw[1:])",
        "    return tuple(dict.fromkeys(names))",
        "def _recover_register_value(call_ea, reg_names):",
        "    min_ea = max(0, call_ea - search_window_before_call)",
        "    for cur in _prev_head_in_window(call_ea, min_ea):",
        "        mnem = idc.print_insn_mnem(cur)",
        "        op0 = (idc.print_operand(cur, 0) or '').lower()",
        "        if mnem not in ('mov', 'lea') or op0 not in reg_names:",
        "            continue",
        "        op_type = int(idc.get_operand_type(cur, 1))",
        "        if op_type in (int(idaapi.o_imm), int(idaapi.o_mem), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_displ)):",
        "            value = idc.get_operand_value(cur, 1)",
        "            if value not in (None, idaapi.BADADDR):",
        "                return value",
        "    return None",
        "def _recover_stack_slot(call_ea, reg_names):",
        "    min_ea = max(0, call_ea - search_window_before_call)",
        "    for cur in _prev_head_in_window(call_ea, min_ea):",
        "        mnem = idc.print_insn_mnem(cur)",
        "        op0 = (idc.print_operand(cur, 0) or '').lower()",
        "        if mnem != 'lea' or op0 not in reg_names:",
        "            continue",
        "        if int(idc.get_operand_type(cur, 1)) == int(idaapi.o_displ):",
        "            value = idc.get_operand_value(cur, 1)",
        "            if value not in (None, idaapi.BADADDR):",
        "                return value",
        "    return None",
        "def _recover_slot_value(call_ea, slot_addr):",
        "    if slot_addr in (None, 0, idaapi.BADADDR):",
        "        return None",
        "    min_ea = max(0, call_ea - search_window_before_call)",
        "    for cur in _prev_head_in_window(call_ea, min_ea):",
        "        if idc.print_insn_mnem(cur) != 'mov':",
        "            continue",
        "        if int(idc.get_operand_type(cur, 0)) != int(idaapi.o_displ):",
        "            continue",
        "        if idc.get_operand_value(cur, 0) != slot_addr:",
        "            continue",
        "        op1_type = int(idc.get_operand_type(cur, 1))",
        "        if op1_type in (int(idaapi.o_imm), int(idaapi.o_mem), int(idaapi.o_near), int(idaapi.o_far)):",
        "            value = idc.get_operand_value(cur, 1)",
        "            if value not in (None, idaapi.BADADDR):",
        "                return value",
        "        reg_name = idc.print_operand(cur, 1) or ''",
        "        if reg_name:",
        "            value = _recover_register_value(cur, _expand_reg_names(reg_name))",
        "            if value not in (None, idaapi.BADADDR):",
        "                return value",
        "    return None",
        "def _append_candidate(command_value, help_value, handler_va):",
        "    if handler_va in (None, 0, idaapi.BADADDR):",
        "        _debug(f\"reject candidate missing handler command={command_value!r} help={help_value!r}\")",
        "        return",
        "    handler_seg_name = _seg_name(handler_va)",
        "    if handler_seg_name != '.text':",
        "        _debug(f\"reject candidate non_text handler={_fmt_ea(handler_va)} seg={handler_seg_name!r} command={command_value!r} help={help_value!r}\")",
        "        return",
        "    key = (command_value, help_value, int(handler_va))",
        "    if key in seen_candidates:",
        "        _debug(f\"skip duplicate candidate handler={_fmt_ea(handler_va)} command={command_value!r} help={help_value!r}\")",
        "        return",
        "    seen_candidates.add(key)",
        "    _debug(f\"accept candidate handler={_fmt_ea(handler_va)} command={command_value!r} help={help_value!r}\")",
        "    candidates.append({'command_name': command_value, 'help_string': help_value, 'handler_va': hex(int(handler_va))})",
        "def _analyze_call(call_ea):",
        "    handler_slot_addr = None",
        "    slot_value_addr = None",
        "    if platform == 'windows':",
        "        command_addr = _recover_register_value(call_ea, reg_names_windows[0])",
        "        handler_slot_addr = _recover_stack_slot(call_ea, reg_names_windows[1])",
        "        help_addr = _recover_register_value(call_ea, reg_names_windows[2])",
        "        slot_value_addr = _recover_slot_value(call_ea, handler_slot_addr)",
        "        handler_va = slot_value_addr",
        "    else:",
        "        command_addr = _recover_register_value(call_ea, reg_names_linux[0])",
        "        handler_va = _recover_register_value(call_ea, reg_names_linux[1])",
        "        help_addr = _recover_register_value(call_ea, reg_names_linux[2])",
        "    command_value = _read_string(command_addr)",
        "    help_value = _read_string(help_addr)",
        "    _debug("
        "f\"call={_fmt_ea(call_ea)} command_addr={_fmt_ea(command_addr)} command_value={command_value!r} "
        "help_addr={_fmt_ea(help_addr)} help_value={help_value!r} "
        "handler_slot={_fmt_ea(handler_slot_addr)} slot_value={_fmt_ea(slot_value_addr)} "
        "handler_va={_fmt_ea(handler_va)}\""
        ")",
        "    if command_name is not None and command_value != command_name:",
        "        _debug(f\"reject call={_fmt_ea(call_ea)} reason=command_mismatch expected={command_name!r} actual={command_value!r}\")",
        "        return",
        "    if help_string is not None and help_value != help_string:",
        "        _debug(f\"reject call={_fmt_ea(call_ea)} reason=help_mismatch expected={help_string!r} actual={help_value!r}\")",
        "        return",
        "    _append_candidate(command_value, help_value, handler_va)",
        "inputs = "
        "f\"platform={platform} command_name={command_name!r} help_string={help_string!r} "
        "before={search_window_before_call} after={search_window_after_xref}\"",
        "_debug(inputs)",
        "target_texts = [command_name, help_string]",
        *string_index_lines,
        "command_string_addrs = string_hits.get(command_name, [])",
        "help_string_addrs = string_hits.get(help_string, [])",
        "_debug(f\"string_hits text={command_name!r} count={len(command_string_addrs)} addrs={_fmt_list(command_string_addrs)}\")",
        "_debug(f\"string_hits text={help_string!r} count={len(help_string_addrs)} addrs={_fmt_list(help_string_addrs)}\")",
        "seed_string_addrs = []",
        "seed_string_addrs.extend(command_string_addrs)",
        "seed_string_addrs.extend(help_string_addrs)",
        "xref_heads = set()",
        "for string_ea in seed_string_addrs:",
        "    for xref in idautils.XrefsTo(string_ea, 0):",
        "        xref_ea = int(xref.frm)",
        "        if not idc.is_code(ida_bytes.get_full_flags(xref_ea)):",
        "            continue",
        "        xref_heads.add(xref_ea)",
        "_debug(f\"xref_heads count={len(xref_heads)} addrs={_fmt_list(sorted(xref_heads))}\")",
        "def _scan_xrefs(require_named):",
        "    named_branch_match = False",
        "    for xref_ea in sorted(xref_heads):",
        "        search_end = xref_ea + search_window_after_xref",
        "        cur = xref_ea",
        "        found_named_register_call = False",
        "        saw_branch = False",
        "        _debug(f\"xref={_fmt_ea(xref_ea)} line={_fmt_line(xref_ea)!r} search_end={_fmt_ea(search_end)} require_named={require_named}\")",
        "        while cur != idaapi.BADADDR and cur <= search_end:",
        "            mnem = idc.print_insn_mnem(cur)",
        "            if mnem in ('call', 'jmp'):",
        "                saw_branch = True",
        "                match = _is_registerconcommand_call(cur)",
        "                _debug(f\"xref={_fmt_ea(xref_ea)} branch={_fmt_ea(cur)} match={match} line={_fmt_line(cur)!r}\")",
        "                if match:",
        "                    named_branch_match = True",
        "                    found_named_register_call = True",
        "                    _debug(f\"xref={_fmt_ea(xref_ea)} register_call={_fmt_ea(cur)} line={_fmt_line(cur)!r}\")",
        "                if ((not require_named) or match) and cur not in seen_calls:",
        "                    seen_calls.add(cur)",
        "                    _analyze_call(cur)",
        "            next_cur = idc.next_head(cur, search_end + 1)",
        "            if next_cur in (idaapi.BADADDR, cur):",
        "                break",
        "            cur = next_cur",
        "        if require_named and not found_named_register_call:",
        "            _debug(f\"xref={_fmt_ea(xref_ea)} no_named_register_call_within_window end={_fmt_ea(search_end)}\")",
        "        elif not saw_branch:",
        "            _debug(f\"xref={_fmt_ea(xref_ea)} no_call_or_jmp_within_window end={_fmt_ea(search_end)}\")",
        "    return named_branch_match",
        "named_branch_match = _scan_xrefs(True)",
        "if not candidates and not named_branch_match:",
        "    _debug('no named RegisterConCommand branches found; fallback to generic call/jmp scan')",
        "    seen_calls.clear()",
        "    _scan_xrefs(False)",
        "_debug(f\"candidate_count={len(candidates)}\")",
        "return candidates",
    ]
    lines = [
        "import json, traceback",
        f"params = json.loads({params!r})",
        "debug_log = []",
        "def _collect_candidates(params):",
    ]
    lines.extend(f"    {line}" for line in body_lines)
    lines.extend(
        [
            "try:",
            "    result = json.dumps({",
            "        'ok': True,",
            "        'candidates': _collect_candidates(params),",
            "        'debug_log': debug_log,",
            "    })",
            "except Exception:",
            "    result = json.dumps({",
            "        'ok': False,",
            "        'traceback': traceback.format_exc(),",
            "        'debug_log': debug_log,",
            "    })",
        ]
    )
    return "\n".join(lines) + "\n"


async def _collect_registerconcommand_candidates(
    session,
    platform,
    command_name,
    help_string,
    search_window_before_call,
    search_window_after_xref,
    debug=False,
):
    code = _build_registerconcommand_py_eval(
        platform=platform,
        command_name=command_name,
        help_string=help_string,
        search_window_before_call=search_window_before_call,
        search_window_after_xref=search_window_after_xref,
        debug=debug,
    )
    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": code},
        )
        payload = parse_mcp_result(result)
    except Exception:
        if debug:
            print("    Preprocess: py_eval collecting RegisterConCommand candidates failed")
        return []

    raw = None
    if isinstance(payload, dict):
        raw = payload.get("result", "")
        if debug:
            stderr_text = payload.get("stderr")
            stdout_text = payload.get("stdout")
            if isinstance(stderr_text, str) and stderr_text.strip():
                print("    Preprocess: py_eval stderr follows")
                print(stderr_text.rstrip())
            if isinstance(stdout_text, str) and stdout_text.strip():
                print("    Preprocess: py_eval stdout follows")
                print(stdout_text.rstrip())
    elif payload is not None:
        raw = str(payload)

    if not raw:
        if debug:
            print("    Preprocess: empty RegisterConCommand py_eval result")
        return []

    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        if debug:
            print("    Preprocess: invalid RegisterConCommand candidate JSON")
        return []

    if not isinstance(parsed, dict):
        return []

    if parsed.get("ok") is False:
        if debug:
            print("    Preprocess: RegisterConCommand py_eval traceback follows")
            traceback_text = parsed.get("traceback")
            if isinstance(traceback_text, str) and traceback_text.strip():
                print(traceback_text.rstrip())
            else:
                print("    Preprocess: missing traceback text in py_eval result")
            debug_log = parsed.get("debug_log", [])
            if isinstance(debug_log, list):
                for line in debug_log:
                    print(f"    Preprocess: py_eval {line}")
        return []

    candidates = parsed.get("candidates", [])
    if not isinstance(candidates, list):
        return []

    if debug:
        debug_log = parsed.get("debug_log", [])
        if isinstance(debug_log, list):
            for line in debug_log:
                print(f"    Preprocess: py_eval {line}")

    required_keys = {"command_name", "help_string", "handler_va"}
    for item in candidates:
        if not isinstance(item, dict):
            return []
        if not required_keys.issubset(item):
            return []
        if not isinstance(item["command_name"], str):
            return []
        if not isinstance(item["help_string"], str):
            return []
        handler_va = item["handler_va"]
        if isinstance(handler_va, bool):
            return []
        if _normalize_handler_va(handler_va) is None:
            return []
    return candidates


async def _query_func_info(session, handler_va, debug=False):
    normalized_handler_va = _normalize_handler_va(handler_va)
    if normalized_handler_va is None:
        return None

    addr_int = int(normalized_handler_va, 16)

    async def _read_func_info_once():
        fi_code = (
            "import idaapi, ida_bytes, idc, json\n"
            f"addr = {addr_int}\n"
            "seg = idaapi.getseg(addr)\n"
            "seg_name = idc.get_segm_name(seg.start_ea) if seg else None\n"
            "flags = ida_bytes.get_full_flags(addr)\n"
            "is_code = bool(ida_bytes.is_code(flags))\n"
            "f = idaapi.get_func(addr)\n"
            "if f and f.start_ea == addr:\n"
            "    result = json.dumps({'status': 'resolved', 'func_va': hex(f.start_ea), "
            "'func_size': hex(f.end_ea - f.start_ea), 'segment_name': seg_name})\n"
            "elif seg_name == '.text' and is_code:\n"
            "    result = json.dumps({'status': 'needs_define', 'entry': hex(addr), "
            "'segment_name': seg_name})\n"
            "else:\n"
            "    result = json.dumps({'status': 'unresolved', 'segment_name': seg_name, "
            "'is_code': is_code})\n"
        )
        try:
            result = await session.call_tool(
                name="py_eval",
                arguments={"code": fi_code},
            )
            result_data = parse_mcp_result(result)
        except Exception:
            if debug:
                print(
                    "    Preprocess: "
                    f"py_eval querying func info failed for {normalized_handler_va}"
                )
            return None

        raw = None
        if isinstance(result_data, dict):
            raw = result_data.get("result", "")
        elif result_data is not None:
            raw = str(result_data)

        if not raw:
            return None

        try:
            data = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            if debug:
                print(
                    "    Preprocess: "
                    f"invalid func info JSON for {normalized_handler_va}"
                )
            return None
        return data

    data = await _read_func_info_once()
    if not isinstance(data, dict):
        return None

    if data.get("status") == "needs_define":
        entry = data.get("entry")
        if not isinstance(entry, str) or not entry:
            return None
        try:
            await session.call_tool(
                name="define_func",
                arguments={"items": {"addr": entry}},
            )
        except Exception:
            if debug:
                print(f"    Preprocess: define_func failed for {entry}")
            return None
        data = await _read_func_info_once()
        if not isinstance(data, dict):
            return None

    if data.get("status") != "resolved":
        if debug:
            print(
                "    Preprocess: "
                f"handler {normalized_handler_va} did not resolve to a .text function start"
            )
        return None

    if "func_va" not in data or "func_size" not in data:
        return None
    return {
        "func_va": data["func_va"],
        "func_size": data["func_size"],
    }


def _build_func_payload(target_name, requested_fields, func_info, extra_fields):
    merged = {"func_name": target_name}
    merged.update(func_info)
    merged.update(extra_fields)

    payload = {}
    for field in requested_fields:
        if field not in merged:
            raise KeyError(field)
        payload[field] = merged[field]
    return payload


def _normalize_handler_va(handler_va):
    if handler_va is None:
        return None
    try:
        if isinstance(handler_va, str):
            raw = handler_va.strip()
            if not raw:
                return None
            return hex(int(raw, 0))
        return hex(int(handler_va))
    except (TypeError, ValueError):
        return None


async def _rename_func_best_effort(session, func_va, func_name, debug=False):
    if not func_va or not func_name:
        return
    try:
        await session.call_tool(
            name="rename",
            arguments={
                "batch": {
                    "func": {"addr": str(func_va), "name": str(func_name)}
                }
            },
        )
    except Exception:
        if debug:
            print(f"    Preprocess: failed to rename {func_name} (non-fatal)")


async def preprocess_registerconcommand_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    target_name,
    generate_yaml_desired_fields,
    command_name=None,
    help_string=None,
    rename_to=None,
    expected_match_count=1,
    search_window_before_call=48,
    search_window_after_xref=24,
    debug=False,
):
    if command_name is None and help_string is None:
        if debug:
            print("    Preprocess: command_name/help_string cannot both be None")
        return False

    if expected_match_count != 1:
        if debug:
            print("    Preprocess: expected_match_count must be 1")
        return False

    requested_fields = _normalize_requested_fields(
        generate_yaml_desired_fields,
        target_name,
        debug=debug,
    )
    if requested_fields is None:
        return False

    output_path = _resolve_output_path(
        expected_outputs,
        target_name,
        platform,
        debug=debug,
    )
    if output_path is None:
        return False

    candidates = await _collect_registerconcommand_candidates(
        session=session,
        platform=platform,
        command_name=command_name,
        help_string=help_string,
        search_window_before_call=search_window_before_call,
        search_window_after_xref=search_window_after_xref,
        debug=debug,
    )

    filtered = [
        item
        for item in candidates
        if (command_name is None or item.get("command_name") == command_name)
        and (help_string is None or item.get("help_string") == help_string)
    ]
    if debug:
        print(
            "    Preprocess: "
            f"RegisterConCommand candidates={len(candidates)} filtered={len(filtered)}"
        )
        if candidates and not filtered:
            for item in candidates:
                print(f"    Preprocess: filtered_out candidate={item!r}")

    handler_values = sorted(
        {
            normalized
            for item in filtered
            for normalized in [_normalize_handler_va(item.get("handler_va"))]
            if normalized
        }
    )
    if len(handler_values) != 1:
        if debug:
            print(
                "    Preprocess: "
                f"expected exactly one handler, got {len(handler_values)}: {handler_values}"
            )
        return False

    func_info = await _query_func_info(session, handler_values[0], debug=debug)
    if not isinstance(func_info, dict):
        if debug:
            print(
                "    Preprocess: "
                f"failed to query function info for handler {handler_values[0]}"
            )
        return False

    extra_fields = {}
    if "func_rva" in requested_fields:
        try:
            extra_fields["func_rva"] = hex(int(func_info["func_va"], 16) - image_base)
        except (KeyError, ValueError, TypeError):
            return False

    if "func_sig" in requested_fields:
        sig_info = await preprocess_gen_func_sig_via_mcp(
            session=session,
            func_va=handler_values[0],
            image_base=image_base,
            debug=debug,
        )
        if not sig_info:
            if debug:
                print(
                    "    Preprocess: "
                    f"failed to generate func_sig for handler {handler_values[0]}"
                )
            return False
        try:
            extra_fields["func_sig"] = sig_info["func_sig"]
            extra_fields["func_rva"] = sig_info["func_rva"]
            extra_fields["func_size"] = sig_info["func_size"]
        except KeyError:
            return False

    try:
        payload = _build_func_payload(
            target_name, requested_fields, func_info, extra_fields
        )
    except KeyError:
        if debug:
            print("    Preprocess: failed to build YAML payload from collected fields")
        return False

    write_func_yaml(output_path, payload)
    await _rename_func_best_effort(
        session=session,
        func_va=handler_values[0],
        func_name=rename_to,
        debug=debug,
    )
    return True

#!/usr/bin/env python3
"""Shared preprocess helpers for GetScriptDescInternal script functions."""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import (
    _normalize_generate_yaml_desired_fields,
    parse_mcp_result,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)


_SUPPORTED_FIELDS = {
    "func_name",
    "func_sig",
    "func_sig_allow_across_function_boundary",
    "func_sig_skip_degenerate",
    "func_va",
    "func_rva",
    "func_size",
}


_SCRIPT_DESC_INTERNAL_PY_EVAL = r"""import idaapi, idautils, idc, json, re
try:
    import ida_hexrays
    import ida_lines
except Exception:
    ida_hexrays = None
    ida_lines = None

func_addr = __FUNC_ADDR__
script_names = set(__SCRIPT_NAMES__)
result_obj = {"entries": []}

def _script_allowed(script_name):
    return not script_names or script_name in script_names

def _func_start(ea):
    if not ea:
        return None
    func = idaapi.get_func(ea)
    if not func:
        idaapi.add_func(ea)
        func = idaapi.get_func(ea)
    return int(func.start_ea) if func else None

def _plain_line(line):
    text = getattr(line, "line", str(line))
    try:
        return ida_lines.tag_remove(text) if ida_lines else str(text)
    except Exception:
        return str(text)

def _normalize_desc(expr):
    text = re.sub(r"\s+", "", expr.strip())
    while text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    return text

def _strip_casts(expr):
    text = expr.strip().lstrip("&").strip()
    while text.startswith("("):
        close = text.find(")")
        if close < 0:
            break
        cast_text = text[1:close]
        if "*" not in cast_text and "__int" not in cast_text and "void" not in cast_text:
            break
        text = text[close + 1:].strip()
    return text.strip().lstrip("&").strip()

def _resolve_func_ea(expr):
    name = _strip_casts(expr)
    if re.fullmatch(r"0x[0-9A-Fa-f]+|\d+", name):
        ea = int(name, 0)
    else:
        ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        return None
    start = _func_start(ea)
    return start if start is not None else ea

def _set_decompiled_field(states, desc, key, value):
    state = states.setdefault(desc, {"desc_expr": desc})
    state[key] = value
    return state

def _append_decompiled_if_complete(state, entries, emitted):
    desc = state.get("desc_expr")
    if desc in emitted:
        return
    if not state.get("script_name") or not state.get("func_va"):
        return
    emitted.add(desc)
    entries.append({
        "script_name": state["script_name"],
        "func_va": state["func_va"],
        "func_expr": state.get("func_expr", ""),
        "desc_expr": desc,
        "order": len(entries),
    })

def _collect_decompiled_entries(func):
    if ida_hexrays is None:
        return [], "unavailable", []
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except Exception as exc:
        return [], "error: " + str(exc), []
    if not cfunc:
        return [], "empty", []
    text = "\n".join(_plain_line(item) for item in cfunc.get_pseudocode())
    script_lines = [
        line.strip()
        for line in text.splitlines()
        if "Script" in line or "+ 64" in line or "+ 8" in line or "m128i_i64[0]" in line
    ][:120]
    direct_name_re = re.compile(
        r'\*\(_QWORD\s*\*\)\((?P<desc>[^;]+?)\s*\+\s*(?:8|8LL|0x8)\)'
        r'\s*=\s*"(?P<script>(?:\\.|[^"\\])*)"\s*;',
        re.S,
    )
    m128_name_re = re.compile(
        r'\*\(__m128i\s*\*\)\s*(?P<desc>[A-Za-z_]\w*)\s*=\s*'
        r'[^;]*?"(?P<script>(?:\\.|[^"\\])*)"[^;]*?;',
        re.S,
    )
    m128_bare_name_re = re.compile(
        r'\*(?P<desc>[A-Za-z_]\w*)\s*=\s*'
        r'[^;]*?"(?P<script>(?:\\.|[^"\\])*)"[^;]*?;',
        re.S,
    )
    m128_temp_re = re.compile(
        r'(?P<temp>[A-Za-z_]\w*)\s*=\s*[^;]*?"(?P<script>(?:\\.|[^"\\])*)"[^;]*?;',
        re.S,
    )
    m128_temp_store_re = re.compile(
        r'\*\((?:__m128i|_OWORD)\s*\*\)\s*(?P<desc>[^;]+?)\s*='
        r'\s*(?P<temp>[A-Za-z_]\w*)\s*;',
        re.S,
    )
    func_re = re.compile(
        r'\*\(_QWORD\s*\*\)\((?P<desc>[^;]+?)\s*\+\s*(?:64|64LL|0x40|40h)\)'
        r'\s*=\s*(?P<rhs>[^;]+);',
        re.S,
    )
    typed_func_re = re.compile(
        r'(?P<desc>[A-Za-z_]\w*)\s*\[\s*4\s*\]\.m128i_\w+\s*\[\s*0\s*\]'
        r'\s*=\s*(?P<rhs>[^;]+);',
        re.S,
    )
    states = {}
    entries = []
    emitted = set()
    temp_scripts = {}
    for match in direct_name_re.finditer(text):
        script_name = match.group("script")
        if not _script_allowed(script_name):
            continue
        desc = _normalize_desc(match.group("desc"))
        state = _set_decompiled_field(states, desc, "script_name", script_name)
        _append_decompiled_if_complete(state, entries, emitted)
    for name_re in (m128_name_re, m128_bare_name_re):
        for match in name_re.finditer(text):
            script_name = match.group("script")
            if not _script_allowed(script_name):
                continue
            desc = _normalize_desc(match.group("desc"))
            state = _set_decompiled_field(states, desc, "script_name", script_name)
            _append_decompiled_if_complete(state, entries, emitted)
    for match in m128_temp_re.finditer(text):
        script_name = match.group("script")
        if _script_allowed(script_name):
            temp_scripts[match.group("temp")] = script_name
    for match in m128_temp_store_re.finditer(text):
        script_name = temp_scripts.get(match.group("temp"))
        if not script_name:
            continue
        desc = _normalize_desc(match.group("desc"))
        state = _set_decompiled_field(states, desc, "script_name", script_name)
        _append_decompiled_if_complete(state, entries, emitted)
    for current_func_re in (func_re, typed_func_re):
        for match in current_func_re.finditer(text):
            target_ea = _resolve_func_ea(match.group("rhs"))
            if target_ea is None:
                continue
            desc = _normalize_desc(match.group("desc"))
            state = _set_decompiled_field(states, desc, "func_va", hex(target_ea))
            state["func_expr"] = match.group("rhs").strip()
            _append_decompiled_if_complete(state, entries, emitted)
    return entries, "ok", script_lines

def _operand_text(ea, index):
    try:
        return idc.print_operand(ea, index).lower()
    except Exception:
        return ""

def _is_xmm_operand(ea, index):
    return _operand_text(ea, index).startswith("xmm")

def _read_string(ea):
    if not ea:
        return None
    try:
        raw = idc.get_strlit_contents(ea)
    except Exception:
        raw = None
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="ignore")
    return str(raw)

def _value_from_operand(ea, op_index, op, reg_values):
    if op.type == idaapi.o_reg:
        return reg_values.get(op.reg)
    value = idc.get_operand_value(ea, op_index)
    text = _read_string(value)
    if text is not None:
        return ("string", text)
    start = _func_start(value)
    if start is not None:
        return ("func", start)
    return None

def _target_func_from_operand(ea, op_index, op, reg_values):
    value = _value_from_operand(ea, op_index, op, reg_values)
    if value and value[0] == "func":
        return value[1]
    return None

def _set_disasm_script(desc_scripts, base_reg, value):
    if not value or value[0] != "string":
        return
    script_name = value[1]
    if _script_allowed(script_name):
        desc_scripts[base_reg] = script_name

def _append_disasm_entry(entries, seen_scripts, script_name, func_start, ea):
    if not script_name or not func_start or script_name in seen_scripts:
        return
    seen_scripts.add(script_name)
    entries.append({
        "script_name": script_name,
        "func_va": hex(func_start),
        "func_expr": hex(func_start),
        "source_ea": hex(ea),
        "order": len(entries),
    })

def _collect_disasm_entries(func):
    reg_values = {}
    xmm_values = {}
    desc_scripts = {}
    seen_scripts = set()
    entries = []
    for ea in idautils.Heads(func.start_ea, func.end_ea):
        mnem = idc.print_insn_mnem(ea).lower()
        insn = idaapi.insn_t()
        if not idaapi.decode_insn(insn, ea):
            continue
        ops = insn.ops
        if mnem in ("xor", "pxor") and ops[0].type == idaapi.o_reg:
            reg_values.pop(ops[0].reg, None)
            xmm_values.pop(ops[0].reg, None)
            continue
        if mnem in ("lea", "mov") and ops[0].type == idaapi.o_reg and not _is_xmm_operand(ea, 0):
            value = _value_from_operand(ea, 1, ops[1], reg_values)
            if value is not None:
                reg_values[ops[0].reg] = value
            else:
                reg_values.pop(ops[0].reg, None)
        if mnem == "movq" and ops[0].type == idaapi.o_reg and _is_xmm_operand(ea, 0):
            value = _value_from_operand(ea, 1, ops[1], reg_values)
            xmm_values[ops[0].reg] = [value, None]
        elif mnem == "pinsrq" and ops[0].type == idaapi.o_reg and _is_xmm_operand(ea, 0):
            value = _value_from_operand(ea, 1, ops[1], reg_values)
            slot = idc.get_operand_value(ea, 2)
            pair = xmm_values.setdefault(ops[0].reg, [None, None])
            if slot in (0, 1):
                pair[int(slot)] = value
        elif mnem == "punpcklqdq" and ops[0].type == idaapi.o_reg:
            pair = xmm_values.get(ops[0].reg)
            if pair:
                pair[1] = pair[0]
        if mnem in ("mov", "movups", "movdqu") and ops[0].type in (idaapi.o_displ, idaapi.o_phrase):
            base_reg = getattr(ops[0], "reg", None)
            offset = int(getattr(ops[0], "addr", 0) or 0)
            if offset == 0 and len(ops) > 1 and ops[1].type == idaapi.o_reg and _is_xmm_operand(ea, 1):
                pair = xmm_values.get(ops[1].reg)
                if pair:
                    _set_disasm_script(desc_scripts, base_reg, pair[1] or pair[0])
            elif offset == 8 and len(ops) > 1:
                _set_disasm_script(desc_scripts, base_reg, _value_from_operand(ea, 1, ops[1], reg_values))
            elif offset == 0x40 and len(ops) > 1:
                func_start = _target_func_from_operand(ea, 1, ops[1], reg_values)
                _append_disasm_entry(entries, seen_scripts, desc_scripts.get(base_reg), func_start, ea)
    return entries

def _merge_entries(primary, secondary):
    merged = []
    seen_scripts = set()
    for source in (primary, secondary):
        for entry in source:
            script_name = entry.get("script_name") if isinstance(entry, dict) else None
            if not script_name or script_name in seen_scripts:
                continue
            seen_scripts.add(script_name)
            copied = dict(entry)
            copied["order"] = len(merged)
            merged.append(copied)
    return merged

# ida_pro_mcp uses separate globals/locals for py_eval; sync helper symbols.
globals().update(locals())

func = idaapi.get_func(func_addr)
if not func:
    idaapi.add_func(func_addr)
    func = idaapi.get_func(func_addr)
if not func:
    result_obj = {"entries": [], "error": "missing_source_func"}
else:
    decompiled_entries, decompile_status, decompiled_script_lines = _collect_decompiled_entries(func)
    disasm_entries = []
    entries = decompiled_entries
    if not script_names or len(entries) < len(script_names):
        disasm_entries = _collect_disasm_entries(func)
        entries = _merge_entries(entries, disasm_entries)
    result_obj = {
        "entries": entries,
        "decompile_status": decompile_status,
        "decompiled_count": len(decompiled_entries),
        "decompiled_script_lines": decompiled_script_lines,
        "disasm_count": len(disasm_entries),
    }
result = json.dumps(result_obj)
"""


def _debug(enabled, message):
    if enabled:
        print(f"    Preprocess: {message}")


def _read_yaml(path):
    if yaml is None or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _parse_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value.strip(), 0)
    return int(value)


async def _call_py_eval_json(session, code, debug=False, error_label="py_eval"):
    try:
        result = await session.call_tool(name="py_eval", arguments={"code": code})
        result_data = parse_mcp_result(result)
    except Exception:
        _debug(debug, f"{error_label} error")
        return None

    raw = None
    if isinstance(result_data, dict):
        stderr_text = result_data.get("stderr", "")
        if stderr_text and debug:
            print("    Preprocess: py_eval stderr:")
            print(str(stderr_text).strip())
        raw = result_data.get("result", "")
    else:
        raw = None
    if raw is None and result_data is not None:
        raw = str(result_data)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        _debug(debug, f"invalid JSON result from {error_label}")
        return None


def _build_script_desc_internal_py_eval(source_func_va, script_names=None):
    normalized_script_names = [] if script_names is None else [str(item) for item in script_names]
    return _SCRIPT_DESC_INTERNAL_PY_EVAL.replace(
        "__FUNC_ADDR__",
        str(_parse_int(source_func_va)),
    ).replace(
        "__SCRIPT_NAMES__",
        json.dumps(normalized_script_names),
    )


def _normalize_target_specs(target_specs, debug=False):
    if not target_specs:
        _debug(debug, "missing target_specs")
        return None
    specs = []
    seen_scripts = set()
    seen_targets = set()
    for item in target_specs:
        if not isinstance(item, dict):
            _debug(debug, "invalid target spec")
            return None
        script_name = item.get("script_name")
        target_name = item.get("target_name")
        if not script_name or not target_name:
            _debug(debug, "target spec requires script_name and target_name")
            return None
        if script_name in seen_scripts or target_name in seen_targets:
            _debug(debug, f"duplicate target spec for {script_name}/{target_name}")
            return None
        seen_scripts.add(script_name)
        seen_targets.add(target_name)
        specs.append({"script_name": str(script_name), "target_name": str(target_name)})
    return specs


def _normalize_desired_fields(generate_yaml_desired_fields, debug=False):
    desired_map = _normalize_generate_yaml_desired_fields(
        generate_yaml_desired_fields,
        debug=debug,
    )
    if desired_map is None:
        return None
    for target_name, config in desired_map.items():
        fields = config.get("desired_output_fields", [])
        for field in fields:
            if field not in _SUPPORTED_FIELDS:
                _debug(debug, f"unsupported requested field for {target_name}: {field}")
                return None
    return desired_map


def _match_output_paths(expected_outputs, specs, platform, debug=False):
    matched = {}
    for spec in specs:
        filename = f"{spec['target_name']}.{platform}.yaml"
        paths = [path for path in expected_outputs if os.path.basename(path) == filename]
        if len(paths) != 1:
            _debug(debug, f"expected exactly one output named {filename}")
            return None
        matched[spec["target_name"]] = paths[0]
    return matched


def _read_source_func_va(new_binary_dir, source_yaml_stem, platform, debug=False):
    source_path = os.path.join(new_binary_dir, f"{source_yaml_stem}.{platform}.yaml")
    source_yaml = _read_yaml(source_path)
    if not isinstance(source_yaml, dict) or not source_yaml.get("func_va"):
        _debug(debug, f"failed to read source function YAML: {source_path}")
        return None
    return str(source_yaml["func_va"])


async def _collect_script_func_entries(
    session,
    source_func_va,
    script_names=None,
    debug=False,
):
    code = _build_script_desc_internal_py_eval(source_func_va, script_names)
    parsed = await _call_py_eval_json(
        session=session,
        code=code,
        debug=debug,
        error_label="py_eval collecting script descriptor functions",
    )
    if not isinstance(parsed, dict) or not isinstance(parsed.get("entries"), list):
        _debug(debug, "failed to collect script descriptor entries")
        return None
    if debug:
        _debug(
            debug,
            "script descriptor collection: "
            f"decompile={parsed.get('decompile_status')} "
            f"decompiled_count={parsed.get('decompiled_count')} "
            f"disasm_count={parsed.get('disasm_count')} "
            f"merged_count={len(parsed['entries'])}",
        )
        found_names = [
            entry.get("script_name")
            for entry in parsed["entries"]
            if isinstance(entry, dict) and entry.get("script_name")
        ]
        _debug(debug, "script descriptor found names: " + ", ".join(found_names))
        script_lines = parsed.get("decompiled_script_lines")
        if script_lines and len(found_names) < len(script_names or []):
            _debug(debug, "script descriptor decompiled sample:")
            for line in script_lines:
                _debug(debug, "  " + str(line))
    return parsed["entries"]


async def _query_func_info(session, func_va, debug=False):
    try:
        func_va_int = _parse_int(func_va)
    except Exception:
        _debug(debug, f"invalid function address: {func_va}")
        return None
    code = (
        "import idaapi, json\n"
        f"target_ea = {func_va_int}\n"
        "func = idaapi.get_func(target_ea)\n"
        "if func and func.start_ea == target_ea:\n"
        "    result = json.dumps({'func_va': hex(func.start_ea), "
        "'func_size': hex(func.end_ea - func.start_ea)})\n"
        "else:\n"
        "    result = json.dumps(None)\n"
    )
    parsed = await _call_py_eval_json(
        session=session,
        code=code,
        debug=debug,
        error_label="py_eval querying script function info",
    )
    return parsed if isinstance(parsed, dict) else None


def _index_entries_by_script_name(entries, expected_count=None, debug=False):
    if expected_count is not None and len(entries) != expected_count:
        _debug(debug, f"unexpected script func count: expected {expected_count}, got {len(entries)}")
        return None
    index = {}
    for entry in entries:
        script_name = entry.get("script_name") if isinstance(entry, dict) else None
        func_va = entry.get("func_va") if isinstance(entry, dict) else None
        if not script_name or not func_va or script_name in index:
            _debug(debug, f"invalid or duplicate script descriptor entry: {script_name}")
            return None
        index[str(script_name)] = entry
    return index


async def _build_requested_payload(session, spec, entry, config, image_base, debug=False):
    func_info = await _query_func_info(session, entry["func_va"], debug=debug)
    if not isinstance(func_info, dict):
        _debug(debug, f"failed to query function info for {spec['target_name']}")
        return None, set()
    func_va = str(func_info["func_va"])
    func_va_int = _parse_int(func_va)
    requested_fields = config["desired_output_fields"]
    options = config["generation_options"]
    skipped_fields = set()
    available = {
        "func_name": spec["target_name"],
        "func_va": func_va,
        "func_size": str(func_info["func_size"]),
    }
    if "func_rva" in requested_fields:
        available["func_rva"] = hex(func_va_int - image_base)
    if "func_sig" in requested_fields:
        sig_info = await preprocess_gen_func_sig_via_mcp(
            session=session,
            func_va=func_va,
            image_base=image_base,
            allow_across_function_boundary=bool(options.get("func_sig_allow_across_function_boundary")),
            debug=debug,
        )
        if not isinstance(sig_info, dict):
            _debug(debug, f"failed to generate func_sig for {spec['target_name']}")
            return None, skipped_fields
        if not sig_info.get("func_sig"):
            # A degenerate body (single jmp/ret) cannot yield a meaningful
            # func_sig. Members carrying func_sig_skip_degenerate emit metadata
            # only rather than failing the whole table.
            if sig_info.get("func_sig_skipped") and options.get("func_sig_skip_degenerate"):
                _debug(
                    debug,
                    f"{spec['target_name']} body is {sig_info['func_sig_skipped']}; omitting func_sig",
                )
                skipped_fields.add("func_sig")
            else:
                _debug(debug, f"failed to generate func_sig for {spec['target_name']}")
                return None, skipped_fields
        else:
            available.update({key: sig_info[key] for key in ("func_sig", "func_rva", "func_size") if key in sig_info})
    if options.get("func_sig_allow_across_function_boundary"):
        available["func_sig_allow_across_function_boundary"] = True
    if options.get("func_sig_skip_degenerate"):
        available["func_sig_skip_degenerate"] = True
    return {field: available[field] for field in requested_fields if field in available}, skipped_fields


async def preprocess_script_desc_internal_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    source_yaml_stem,
    target_specs,
    generate_yaml_desired_fields,
    expected_script_func_count=None,
    debug=False,
):
    if yaml is None:
        _debug(debug, "PyYAML is required")
        return False
    specs = _normalize_target_specs(target_specs, debug=debug)
    desired_map = _normalize_desired_fields(generate_yaml_desired_fields, debug=debug)
    if not specs or desired_map is None:
        return False
    output_paths = _match_output_paths(expected_outputs, specs, platform, debug=debug)
    source_func_va = _read_source_func_va(new_binary_dir, source_yaml_stem, platform, debug=debug)
    if output_paths is None or source_func_va is None:
        return False
    entries = await _collect_script_func_entries(
        session,
        source_func_va,
        script_names=[spec["script_name"] for spec in specs],
        debug=debug,
    )
    if not isinstance(entries, list):
        return False
    entry_index = _index_entries_by_script_name(entries, expected_count=expected_script_func_count, debug=debug)
    if entry_index is None:
        return False
    for spec in specs:
        entry = entry_index.get(spec["script_name"])
        config = desired_map.get(spec["target_name"])
        if entry is None or config is None:
            _debug(debug, f"missing script entry or desired fields for {spec}")
            return False
        payload, skipped_fields = await _build_requested_payload(
            session, spec, entry, config, image_base, debug=debug
        )
        if payload is None or set(payload) != set(config["desired_output_fields"]) - skipped_fields:
            _debug(debug, f"incomplete payload for {spec['target_name']}")
            return False
        write_func_yaml(output_paths[spec["target_name"]], payload)
    return True

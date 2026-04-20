#!/usr/bin/env python3
"""Shared preprocess helpers for slot-only IGameSystem dispatcher skills."""
import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import parse_mcp_result, write_func_yaml

_SLOT_DISPATCH_PY_EVAL = """import idaapi, idautils, idc, json
MAX_WRAPPER_INSTRUCTIONS = 8
func_addr = __FUNC_ADDR__; is_windows = __IS_WINDOWS__
if not idaapi.get_func(func_addr): idaapi.add_func(func_addr)
func = idaapi.get_func(func_addr); result_obj = {'entries': []}
def _call_op(ea):
    insn = idaapi.insn_t()
    if not idaapi.decode_insn(insn, ea): return None, None
    op = insn.ops[0]
    if op.type == idaapi.o_displ and op.addr >= 0 and (op.addr % 8) == 0: return op, op.addr
    return None, None
def _entry(ea, kind, off): return {'source_ea': hex(ea), 'source_kind': kind, 'vfunc_offset': hex(off), 'vfunc_index': off // 8}
if func and is_windows:
    candidate_targets = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.print_insn_mnem(head) in ('call', 'jmp'):
            target = idc.get_operand_value(head, 0)
            if target and target != func.start_ea:
                if not idaapi.get_func(target): idaapi.add_func(target)
                if idaapi.get_func(target): candidate_targets.append((head, target))
    wrapper_entries = []
    for call_ea, target in candidate_targets:
        wrapper = idaapi.get_func(target); found = None
        if not wrapper: continue
        inner_heads = list(idautils.Heads(wrapper.start_ea, wrapper.end_ea))
        if len(inner_heads) > MAX_WRAPPER_INSTRUCTIONS: continue
        for inner in inner_heads:
            if idc.print_insn_mnem(inner) not in ('call', 'jmp'): continue
            op, offset = _call_op(inner)
            if offset is None: continue
            if found is not None: found = None; break
            found = _entry(call_ea, 'wrapper', offset)
        if found is not None: wrapper_entries.append(found)
    result_obj['entries'] = wrapper_entries
elif func:
    call_entries = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.print_insn_mnem(head) != 'call': continue
        op, offset = _call_op(head)
        if offset is None: continue
        prev_ea = idc.prev_head(head, func.start_ea)
        if prev_ea == idaapi.BADADDR or idc.print_insn_mnem(prev_ea) != 'mov': continue
        prev = idaapi.insn_t()
        if not idaapi.decode_insn(prev, prev_ea): continue
        if prev.ops[0].type != idaapi.o_reg: continue
        if prev.ops[0].reg != getattr(op, 'reg', None): continue
        if prev.ops[1].type not in (idaapi.o_phrase, idaapi.o_displ): continue
        call_entries.append(_entry(head, 'inline', offset))
    result_obj['entries'] = call_entries
result = json.dumps(result_obj)
"""
def _debug(debug, message):
    if debug:
        print(f"    Preprocess: {message}")
def _read_yaml(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None
def _parse_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ValueError("empty integer string")
        return int(raw, 0)
    return int(value)
async def _call_py_eval_json(session, code, debug=False, error_label="py_eval"):
    try:
        result = await session.call_tool(name="py_eval", arguments={"code": code})
        result_data = parse_mcp_result(result)
    except Exception:
        _debug(debug, f"{error_label} error")
        return None
    raw = result_data.get("result", "") if isinstance(result_data, dict) else None
    if raw is None and result_data is not None:
        raw = str(result_data)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        _debug(debug, f"invalid JSON result from {error_label}")
        return None
def _build_slot_dispatch_py_eval(source_func_va, platform):
    return _SLOT_DISPATCH_PY_EVAL.replace("__FUNC_ADDR__", str(source_func_va)).replace(
        "__IS_WINDOWS__", "1" if platform == "windows" else "0"
    )
def _normalize_rank(raw_rank, target_name, debug=False):
    if raw_rank is None:
        return None
    try:
        rank = _parse_int(raw_rank)
    except Exception as exc:
        _debug(debug, f"invalid dispatch_rank for {target_name}")
        raise ValueError("invalid dispatch_rank") from exc
    if rank < 0:
        _debug(debug, f"dispatch_rank must be >= 0 for {target_name}")
        raise ValueError("negative dispatch_rank")
    return rank
def _normalize_one_spec(item, debug=False):
    if not isinstance(item, dict):
        _debug(debug, "invalid target spec")
        return None
    target_name = item.get("target_name")
    vtable_name = item.get("vtable_name")
    if not target_name or not vtable_name:
        _debug(debug, "target spec missing target_name or vtable_name")
        return None
    try:
        dispatch_rank = _normalize_rank(item.get("dispatch_rank"), target_name, debug)
    except ValueError:
        return None
    return {"target_name": str(target_name), "vtable_name": str(vtable_name), "dispatch_rank": dispatch_rank}


def _normalize_target_specs(target_specs, debug=False):
    if not isinstance(target_specs, list) or not target_specs:
        _debug(debug, "target_specs must be a non-empty list")
        return None
    specs = []
    for item in target_specs:
        spec = _normalize_one_spec(item, debug=debug)
        if spec is None:
            return None
        specs.append(spec)
    ranks = [spec["dispatch_rank"] for spec in specs]
    has_rank = any(rank is not None for rank in ranks)
    if has_rank and any(rank is None for rank in ranks):
        _debug(debug, "dispatch_rank must be provided for all target_specs")
        return None
    if has_rank and len(set(ranks)) != len(ranks):
        _debug(debug, "dispatch_rank values must be unique")
        return None
    return specs


def _resolve_expected_dispatch_count(specs, expected_dispatch_count, debug=False):
    if expected_dispatch_count is not None:
        try:
            count = _parse_int(expected_dispatch_count)
        except Exception:
            _debug(debug, "invalid expected_dispatch_count")
            return None
        if count <= 0:
            _debug(debug, "expected_dispatch_count must be > 0")
            return None
        return count
    ranks = [spec["dispatch_rank"] for spec in specs if spec["dispatch_rank"] is not None]
    return max(ranks) + 1 if ranks else len(specs)


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


def _prepare_preprocess(expected_outputs, platform, target_specs, count, debug=False):
    specs = _normalize_target_specs(target_specs, debug=debug)
    if not specs:
        return None
    expected_count = _resolve_expected_dispatch_count(specs, count, debug=debug)
    if expected_count is None:
        return None
    matched_outputs = _match_output_paths(expected_outputs, specs, platform, debug)
    return None if matched_outputs is None else (specs, expected_count, matched_outputs)


def _read_dispatcher_func_va(new_binary_dir, dispatcher_yaml_stem, platform, debug=False):
    dispatcher_path = os.path.join(new_binary_dir, f"{dispatcher_yaml_stem}.{platform}.yaml")
    dispatcher_yaml = _read_yaml(dispatcher_path)
    if not isinstance(dispatcher_yaml, dict) or not dispatcher_yaml.get("func_va"):
        _debug(debug, f"missing func_va in {dispatcher_yaml_stem}.{platform}.yaml")
        return None
    return str(dispatcher_yaml["func_va"])


def _collect_unique_slots(entries, debug=False):
    if not isinstance(entries, list) or not entries:
        _debug(debug, "py_eval entries must be a non-empty list")
        return None
    unique = []
    seen = set()
    for entry in entries:
        try:
            offset = _parse_int(entry.get("vfunc_offset"))
            index = _parse_int(entry.get("vfunc_index"))
        except Exception:
            _debug(debug, "invalid slot entry")
            return None
        if offset < 0 or (offset % 8) != 0:
            _debug(debug, "slot offset must be non-negative and 8-byte aligned")
            return None
        if index != offset // 8:
            _debug(debug, "slot index/offset mismatch")
            return None
        if (offset, index) not in seen:
            seen.add((offset, index))
            unique.append({"vfunc_offset": offset, "vfunc_index": index})
    return unique


async def _extract_unique_slots(session, func_va, platform, debug=False):
    parsed = await _call_py_eval_json(
        session=session,
        code=_build_slot_dispatch_py_eval(func_va, platform),
        debug=debug,
        error_label="py_eval extracting slot dispatch entries",
    )
    if not isinstance(parsed, dict):
        _debug(debug, "failed to extract slot dispatch entries")
        return None
    return _collect_unique_slots(parsed.get("entries"), debug=debug)


def _select_entries(specs, unique_entries, multi_order, debug=False):
    ranks = [spec["dispatch_rank"] for spec in specs if spec["dispatch_rank"] is not None]
    if ranks or multi_order == "index":
        ordered = sorted(unique_entries, key=lambda entry: (entry["vfunc_index"], entry["vfunc_offset"]))
    elif multi_order == "scan" or len(specs) == 1:
        ordered = list(unique_entries)
    else:
        _debug(debug, f"invalid multi_order: {multi_order}")
        return None
    if not ranks:
        return ordered[: len(specs)]
    try:
        return [ordered[spec["dispatch_rank"]] for spec in specs]
    except Exception:
        _debug(debug, "dispatch_rank is out of range")
        return None


def _write_slot_outputs(specs, selected_entries, matched_outputs):
    for spec, entry in zip(specs, selected_entries):
        write_func_yaml(
            matched_outputs[spec["target_name"]],
            {"func_name": spec["target_name"], "vtable_name": spec["vtable_name"], "vfunc_offset": hex(entry["vfunc_offset"]), "vfunc_index": entry["vfunc_index"]},
        )


async def preprocess_igamesystem_slot_dispatch_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    dispatcher_yaml_stem,
    target_specs,
    multi_order="index",
    expected_dispatch_count=None,
    debug=False,
):
    if yaml is None:
        _debug(debug, "PyYAML is required")
        return False
    context = _prepare_preprocess(expected_outputs, platform, target_specs, expected_dispatch_count, debug)
    if context is None:
        return False
    specs, expected_count, matched_outputs = context
    func_va = _read_dispatcher_func_va(new_binary_dir, dispatcher_yaml_stem, platform, debug)
    if not func_va:
        return False
    unique_entries = await _extract_unique_slots(session, func_va, platform, debug)
    if unique_entries is None:
        return False
    if len(unique_entries) != expected_count:
        _debug(debug, f"unexpected unique slot count, expected {expected_count}, got {len(unique_entries)}")
        return False
    selected_entries = _select_entries(specs, unique_entries, multi_order, debug)
    if selected_entries is None or len(selected_entries) != len(specs):
        return False
    _write_slot_outputs(specs, selected_entries, matched_outputs)
    return True

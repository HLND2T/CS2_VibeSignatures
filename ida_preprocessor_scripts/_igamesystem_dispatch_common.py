#!/usr/bin/env python3
"""Shared preprocess helpers for IGameSystem dispatch-like skills."""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import normalize_output_name_map, parse_mcp_result, write_func_yaml


def _read_yaml(path):
    """Read YAML file and return parsed object, or None on failure."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _parse_int(value):
    """Parse int from int/str-like values."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ValueError("empty integer string")
        return int(raw, 0)
    return int(value)


def _dedup_entries_by_offset(entries):
    """Collapse dispatch entries that repeat the same ``vfunc_offset``.

    14168 began routing each event's dispatch-index resolution through a
    helper (e.g. ``sub_1719D00(&guard, imm, 0)``) that reuses the exact
    ``mov esi, imm`` + ``call`` shape as the real ``IGameSystem_DispatchCall``,
    so a single dispatched event can surface more than once on Linux. Distinct
    events always map to distinct vtable offsets, so keeping the first
    occurrence per offset is safe and leaves already-unique scans untouched.
    """
    seen = set()
    deduped = []
    for entry in entries:
        if not isinstance(entry, dict):
            deduped.append(entry)
            continue
        try:
            key = _parse_int(entry.get("vfunc_offset"))
        except Exception:
            deduped.append(entry)
            continue
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


async def _rename_func_best_effort(session, func_va, func_name, debug=False):
    """Best-effort function rename in IDA; never raises."""
    if not func_va or not func_name:
        return
    try:
        await session.call_tool(
            name="rename",
            arguments={"batch": {"func": {"addr": str(func_va), "name": str(func_name)}}},
        )
    except Exception:
        if debug:
            print(f"    Preprocess: failed to rename {func_name} (non-fatal)")


async def _call_py_eval_json(session, code, debug=False, error_label="py_eval"):
    """Run py_eval and parse its JSON `result` field."""
    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": code},
        )
        result_data = parse_mcp_result(result)
    except Exception:
        if debug:
            print(f"    Preprocess: {error_label} error")
        return None

    raw = None
    if isinstance(result_data, dict):
        raw = result_data.get("result", "")
    elif result_data is not None:
        raw = str(result_data)

    if not raw:
        return None

    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        if debug:
            print(f"    Preprocess: invalid JSON result from {error_label}")
        return None


def _build_dispatch_py_eval(source_func_va, via_internal_wrapper, platform):
    """Build a platform-aware py_eval script for collecting all vfunc entries.

    Windows uses ``lea rdx, callback`` to pass function-pointer callbacks,
    then each callback contains ``call/jmp [reg+vfunc_offset]``.

    Linux uses ``mov esi/rsi, imm`` (odd immediate > 1) followed by ``call``
    where ``imm - 1`` equals the vfunc byte-offset.

    De-inline fallback (Windows): when the source function yields no entries,
    the per-event ``IGameSystem`` dispatcher may have been split out into
    separate callee functions (observed in 14168: ``CLoopModeGame_On*`` no
    longer inlines the dispatcher). Each de-inlined dispatcher still contains
    the ``mov rax, gs:58h`` TLS access used by the lazy dispatch-index guard,
    so callees carrying that marker are scanned in call order and their
    entries aggregated.
    """
    wrapper_flag = 1 if via_internal_wrapper else 0
    is_windows = 1 if platform == "windows" else 0
    return (
        "import idaapi, idautils, idc, ida_bytes, json\n"
        f"func_addr = {source_func_va}\n"
        f"use_wrapper = {wrapper_flag}\n"
        f"is_windows = {is_windows}\n"
        # `mov rax, gs:58h` marks a de-inlined GameSystem dispatcher (Windows).
        "DISPATCH_MARKER = bytes((0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00))\n"
        "\n"
        "def _has_dispatch_marker(gef):\n"
        "    if not gef:\n"
        "        return False\n"
        "    blob = ida_bytes.get_bytes(gef.start_ea, gef.end_ea - gef.start_ea)\n"
        "    return bool(blob) and DISPATCH_MARKER in blob\n"
        "\n"
        "def _ordered_callees(gef):\n"
        "    ordered = []\n"
        "    seen = set()\n"
        "    for head in idautils.Heads(gef.start_ea, gef.end_ea):\n"
        "        if idc.print_insn_mnem(head) in ('call', 'jmp'):\n"
        "            callee = idc.get_operand_value(head, 0)\n"
        "            sub = idaapi.get_func(callee)\n"
        "            if sub and sub.start_ea == callee and callee != gef.start_ea and callee not in seen:\n"
        "                seen.add(callee)\n"
        "                ordered.append(callee)\n"
        "    return ordered\n"
        "\n"
        "def _scan_entries(gef):\n"
        "    found = []\n"
        "    if not gef:\n"
        "        return found\n"
        "    if is_windows:\n"
        "        lea_targets = []\n"
        "        for head in idautils.Heads(gef.start_ea, gef.end_ea):\n"
        "            if idc.print_insn_mnem(head) == 'lea' and idc.print_operand(head, 0) == 'rdx':\n"
        "                target = idc.get_operand_value(head, 1)\n"
        "                if idaapi.get_func(target):\n"
        "                    lea_targets.append(target)\n"
        "        for t in lea_targets:\n"
        "            cb = idaapi.get_func(t)\n"
        "            if not cb:\n"
        "                continue\n"
        "            for head in idautils.Heads(cb.start_ea, cb.end_ea):\n"
        "                mnem = idc.print_insn_mnem(head)\n"
        "                if mnem in ('call', 'jmp'):\n"
        "                    insn = idaapi.insn_t()\n"
        "                    if idaapi.decode_insn(insn, head):\n"
        "                        op = insn.ops[0]\n"
        "                        if op.type == idaapi.o_displ and op.addr >= 0 and (op.addr % 8) == 0:\n"
        "                            found.append({\n"
        "                                'game_event_addr': hex(t),\n"
        "                                'vfunc_offset': op.addr,\n"
        "                                'vfunc_index': op.addr // 8,\n"
        "                            })\n"
        "                            break\n"
        "    else:\n"
        "        last_esi_imm = None\n"
        "        for head in idautils.Heads(gef.start_ea, gef.end_ea):\n"
        "            mnem = idc.print_insn_mnem(head)\n"
        "            if mnem == 'mov':\n"
        "                op0 = idc.print_operand(head, 0)\n"
        "                if op0 in ('esi', 'rsi'):\n"
        "                    insn = idaapi.insn_t()\n"
        "                    if idaapi.decode_insn(insn, head):\n"
        "                        op = insn.ops[1]\n"
        "                        if op.type == idaapi.o_imm and (op.value & 1) != 0 and op.value > 1:\n"
        "                            last_esi_imm = op.value\n"
        "            elif mnem == 'call' and last_esi_imm is not None:\n"
        "                vfunc_off = last_esi_imm - 1\n"
        "                if vfunc_off >= 0 and (vfunc_off % 8) == 0:\n"
        "                    found.append({\n"
        "                        'vfunc_offset': vfunc_off,\n"
        "                        'vfunc_index': vfunc_off // 8,\n"
        "                    })\n"
        "                last_esi_imm = None\n"
        "    return found\n"
        "\n"
        # Bridge exec_locals into exec_globals so the helpers above resolve
        # imports/constants under py_eval's dual-namespace model.
        "globals().update(locals())\n"
        "\n"
        "if not idaapi.get_func(func_addr):\n"
        "    idaapi.add_func(func_addr)\n"
        "func = idaapi.get_func(func_addr)\n"
        "result_obj = None\n"
        "if func:\n"
        "    search_func = func\n"
        "    internal_addr = None\n"
        "    if use_wrapper:\n"
        "        for head in idautils.Heads(func.start_ea, func.end_ea):\n"
        "            mnem = idc.print_insn_mnem(head)\n"
        "            if mnem in ('call', 'jmp'):\n"
        "                target = idc.get_operand_value(head, 0)\n"
        "                if not idaapi.get_func(target):\n"
        "                    idaapi.add_func(target)\n"
        "                if idaapi.get_func(target) and target != func.start_ea:\n"
        "                    internal_addr = target\n"
        "                    break\n"
        "        if internal_addr:\n"
        "            search_func = idaapi.get_func(internal_addr)\n"
        "        else:\n"
        "            search_func = None\n"
        "\n"
        "    if search_func:\n"
        "        entries = _scan_entries(search_func)\n"
        "        deinlined = []\n"
        "        if not entries:\n"
        "            for callee in _ordered_callees(search_func):\n"
        "                sub = idaapi.get_func(callee)\n"
        "                if _has_dispatch_marker(sub):\n"
        "                    sub_entries = _scan_entries(sub)\n"
        "                    if sub_entries:\n"
        "                        deinlined.append(hex(callee))\n"
        "                        entries.extend(sub_entries)\n"
        "        result_obj = {'entries': entries}\n"
        "        if internal_addr is not None:\n"
        "            result_obj['internal_addr'] = hex(internal_addr)\n"
        "        if deinlined:\n"
        "            result_obj['deinlined_dispatchers'] = deinlined\n"
        "\n"
        "result = json.dumps(result_obj)\n"
    )


async def _query_func_info(session, target_addr_hex, target_name, debug=False):
    """Query function start/size via IDA py_eval."""
    fi_code = (
        "import idaapi, json\n"
        f"addr = {target_addr_hex}\n"
        "f = idaapi.get_func(addr)\n"
        "if f and f.start_ea == addr:\n"
        "    result = json.dumps({'func_va': hex(f.start_ea), "
        "'func_size': hex(f.end_ea - f.start_ea)})\n"
        "else:\n"
        "    result = json.dumps(None)\n"
    )
    data = await _call_py_eval_json(
        session=session,
        code=fi_code,
        debug=debug,
        error_label=f"py_eval querying function info for {target_name}",
    )
    return data if isinstance(data, dict) else None


async def preprocess_igamesystem_dispatch_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    source_yaml_stem,
    target_specs,
    via_internal_wrapper,
    internal_rename_to,
    multi_order,
    expected_dispatch_count=None,
    debug=False,
    output_name_map=None,
):
    """Common preprocess routine for dispatch-like IGameSystem skills.

    Args:
        session: Active MCP session.
        expected_outputs: Output YAML paths for current skill.
        new_binary_dir: Directory containing generated YAML files.
        platform: "windows" or "linux".
        image_base: Binary image base integer.
        source_yaml_stem: Source YAML filename stem (without .{platform}.yaml).
        target_specs: List[dict] with keys:
            - target_name (required)
            - rename_to (optional)
            - dispatch_rank (optional): use sorted-by-vfunc-index rank
              when selecting from all collected dispatch entries.
        via_internal_wrapper: Whether source function first jumps/calls an internal func.
        internal_rename_to: Optional rename for resolved internal wrapper function.
        multi_order: "scan" or "index" for multi-target mapping order.
        expected_dispatch_count: Expected total count of dispatch entries
            collected from source function. If None, defaults to target_count,
            or ``max(dispatch_rank)+1`` when dispatch_rank is provided.
        debug: Enable debug logs.
    """
    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required")
        return False

    if not isinstance(target_specs, list) or not target_specs:
        if debug:
            print("    Preprocess: target_specs must be a non-empty list")
        return False

    normalized_specs = []
    has_dispatch_rank = False
    for item in target_specs:
        if not isinstance(item, dict):
            if debug:
                print("    Preprocess: invalid target spec")
            return False
        target_name = item.get("target_name")
        if not target_name:
            if debug:
                print("    Preprocess: target spec missing target_name")
            return False
        rename_to = item.get("rename_to")
        dispatch_rank = item.get("dispatch_rank")
        if dispatch_rank is not None:
            try:
                dispatch_rank = _parse_int(dispatch_rank)
            except Exception:
                if debug:
                    print(f"    Preprocess: invalid dispatch_rank for {target_name}")
                return False
            if dispatch_rank < 0:
                if debug:
                    print(f"    Preprocess: dispatch_rank must be >= 0 for {target_name}")
                return False
            has_dispatch_rank = True
        normalized_specs.append(
            {
                "target_name": str(target_name),
                "rename_to": str(rename_to) if rename_to else None,
                "dispatch_rank": dispatch_rank,
            }
        )

    target_count = len(normalized_specs)
    output_name_map = normalize_output_name_map(
        output_name_map, {spec["target_name"]: "func" for spec in normalized_specs}, debug=debug
    )
    if output_name_map is None:
        return False
    if has_dispatch_rank and any(spec["dispatch_rank"] is None for spec in normalized_specs):
        if debug:
            print("    Preprocess: dispatch_rank must be provided for all target_specs")
        return False

    if target_count > 1 and multi_order not in ("scan", "index"):
        if debug:
            print(f"    Preprocess: invalid multi_order: {multi_order}")
        return False

    explicit_expected_dispatch_count = expected_dispatch_count is not None
    if explicit_expected_dispatch_count:
        try:
            expected_dispatch_count = _parse_int(expected_dispatch_count)
        except Exception:
            if debug:
                print(f"    Preprocess: invalid expected_dispatch_count: {expected_dispatch_count}")
            return False
        if expected_dispatch_count <= 0:
            if debug:
                print(f"    Preprocess: expected_dispatch_count must be > 0, got {expected_dispatch_count}")
            return False
    else:
        if has_dispatch_rank:
            expected_dispatch_count = max(spec["dispatch_rank"] for spec in normalized_specs) + 1
        else:
            expected_dispatch_count = target_count

    if has_dispatch_rank:
        ranks = [spec["dispatch_rank"] for spec in normalized_specs]
        if len(set(ranks)) != len(ranks):
            if debug:
                print("    Preprocess: dispatch_rank values must be unique")
            return False
        max_rank = max(ranks)
        if expected_dispatch_count <= max_rank:
            if debug:
                print("    Preprocess: expected_dispatch_count is too small for the largest dispatch_rank")
            return False
    elif expected_dispatch_count != target_count:
        if debug:
            print(
                "    Preprocess: expected_dispatch_count differs from target count; "
                "provide dispatch_rank for all targets"
            )
        return False

    matched_outputs = {}
    for spec in normalized_specs:
        target_name = spec["target_name"]
        filename = f"{target_name}.{platform}.yaml"
        matched = [path for path in expected_outputs if os.path.basename(path) == filename]
        if len(matched) != 1:
            if debug:
                print(f"    Preprocess: expected exactly one output named {filename}, got {len(matched)}")
            return False
        matched_outputs[target_name] = matched[0]

    src_path = os.path.join(new_binary_dir, f"{source_yaml_stem}.{platform}.yaml")
    src_data = _read_yaml(src_path)
    if not isinstance(src_data, dict) or not src_data.get("func_va"):
        if debug:
            print(f"    Preprocess: failed to read {source_yaml_stem} YAML")
        return False
    src_func_va = str(src_data["func_va"])

    vtable_path = os.path.join(new_binary_dir, f"IGameSystem_vtable.{platform}.yaml")
    vtable_data = _read_yaml(vtable_path)
    if not isinstance(vtable_data, dict):
        if debug:
            print("    Preprocess: failed to read IGameSystem_vtable YAML")
        return False

    raw_entries = vtable_data.get("vtable_entries", {})
    if not isinstance(raw_entries, dict):
        if debug:
            print("    Preprocess: invalid vtable_entries in IGameSystem_vtable YAML")
        return False

    vtable_entries = {}
    for idx, addr in raw_entries.items():
        try:
            vtable_entries[int(idx)] = str(addr)
        except (TypeError, ValueError):
            if debug:
                print(f"    Preprocess: invalid vtable entry index: {idx}")
            return False

    py_code = _build_dispatch_py_eval(
        source_func_va=src_func_va,
        via_internal_wrapper=via_internal_wrapper,
        platform=platform,
    )

    parsed = await _call_py_eval_json(
        session=session,
        code=py_code,
        debug=debug,
        error_label="py_eval extracting vfunc entries",
    )

    if not isinstance(parsed, dict):
        if debug:
            print(f"    Preprocess: failed to determine vfunc entries from {source_yaml_stem}")
        return False

    entries = parsed.get("entries")
    if not isinstance(entries, list):
        if debug:
            print(
                f"    Preprocess: invalid entry count from {source_yaml_stem}, "
                f"expected {expected_dispatch_count}, got N/A"
            )
        return False

    deinlined_dispatchers = parsed.get("deinlined_dispatchers")
    if debug and deinlined_dispatchers:
        print(f"    Preprocess: {source_yaml_stem} dispatch de-inlined into {deinlined_dispatchers}")

    entries = _dedup_entries_by_offset(entries)
    if len(entries) != expected_dispatch_count:
        if debug:
            print(
                f"    Preprocess: invalid entry count from {source_yaml_stem}, "
                f"expected {expected_dispatch_count}, got {len(entries)}"
            )
        return False

    if debug:
        print(f"    Preprocess: collected {len(entries)} dispatch entries from {source_yaml_stem}")

    internal_addr = parsed.get("internal_addr")
    should_sort_by_index = has_dispatch_rank or (target_count > 1 and multi_order == "index")
    if should_sort_by_index:
        try:
            entries = sorted(
                entries,
                key=lambda e: (
                    _parse_int(e.get("vfunc_index")),
                    _parse_int(e.get("vfunc_offset")),
                ),
            )
        except Exception:
            if debug:
                print("    Preprocess: failed to sort entries by vfunc_index")
            return False

    if has_dispatch_rank:
        try:
            selected_entries = [entries[spec["dispatch_rank"]] for spec in normalized_specs]
        except Exception:
            if debug:
                print("    Preprocess: failed to map entries by dispatch_rank")
            return False
    else:
        selected_entries = entries[:target_count]

    if internal_rename_to and internal_addr:
        await _rename_func_best_effort(
            session=session,
            func_va=internal_addr,
            func_name=internal_rename_to,
            debug=debug,
        )

    for entry, spec in zip(selected_entries, normalized_specs):
        target_name = spec["target_name"]
        rename_to = spec["rename_to"]
        dispatch_rank = spec.get("dispatch_rank")

        try:
            vfunc_offset = _parse_int(entry.get("vfunc_offset"))
            vfunc_index = _parse_int(entry.get("vfunc_index"))
        except Exception:
            if debug:
                print(f"    Preprocess: invalid vfunc entry for {target_name}")
            return False

        game_event_addr = entry.get("game_event_addr")
        if rename_to and game_event_addr:
            await _rename_func_best_effort(
                session=session,
                func_va=game_event_addr,
                func_name=rename_to,
                debug=debug,
            )

        if debug:
            rank_suffix = f", dispatch_rank={dispatch_rank}" if dispatch_rank is not None else ""
            print(
                f"    Preprocess: [{target_name}] "
                f"vfunc_offset=0x{vfunc_offset:X}, vfunc_index={vfunc_index}{rank_suffix}"
            )

        target_addr_hex = vtable_entries.get(vfunc_index)
        if not target_addr_hex:
            if debug:
                print(f"    Preprocess: IGameSystem vtable missing index {vfunc_index}")
            return False

        func_info = await _query_func_info(
            session=session,
            target_addr_hex=target_addr_hex,
            target_name=target_name,
            debug=debug,
        )
        if not isinstance(func_info, dict):
            if debug:
                print(f"    Preprocess: failed to query function info for {target_name}")
            return False

        func_va_hex = func_info.get("func_va")
        func_size_hex = func_info.get("func_size")
        if not func_va_hex or not func_size_hex:
            if debug:
                print(f"    Preprocess: incomplete function info for {target_name}")
            return False

        try:
            func_va_int = int(str(func_va_hex), 16)
        except (TypeError, ValueError):
            if debug:
                print(f"    Preprocess: invalid func_va: {func_va_hex}")
            return False

        payload = {
            "func_name": output_name_map.get(target_name, target_name),
            "func_va": str(func_va_hex),
            "func_rva": hex(func_va_int - image_base),
            "func_size": str(func_size_hex),
            "vtable_name": "IGameSystem",
            "vfunc_offset": hex(vfunc_offset),
            "vfunc_index": vfunc_index,
        }

        output_path = matched_outputs[target_name]
        write_func_yaml(output_path, payload)

        if debug:
            print(f"    Preprocess: written {os.path.basename(output_path)}")

    return True

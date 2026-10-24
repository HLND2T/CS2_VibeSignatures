#!/usr/bin/env python3
"""Resolve the string-key weapon lookup without LLM-dependent chain depth."""

from pathlib import Path

import yaml

import ida_analyze_util
from ida_preprocessor_scripts._direct_branch_target_common import _call_py_eval_json


TARGET_NAME = "GetCSWeaponDataFromKey"
MURMUR_HASH_SEED = 0x31415926
MURMUR_HASH_MULTIPLIER = 0x5BD1E995
WEAPON_DATA_TYPE = 1
MAX_CALL_DEPTH = 2


_LOOKUP_PY_EVAL = """import idaapi, idautils, idc, json
source_va = __SOURCE_VA__
include_source = __INCLUDE_SOURCE__
is_windows = __IS_WINDOWS__
source_func = idaapi.get_func(source_va)
candidates = {}
pending = []
visited = set()
if source_func and source_func.start_ea == source_va:
    pending.append((source_va, 0))
while pending:
    current_va, depth = pending.pop(0)
    if current_va in visited:
        continue
    visited.add(current_va)
    current_func = idaapi.get_func(current_va)
    previous = None
    for head in idautils.Heads(current_func.start_ea, current_func.end_ea):
        mnem = idc.print_insn_mnem(head).lower()
        if mnem == "nop":
            continue
        insn = idaapi.insn_t()
        if mnem == "call" and idaapi.decode_insn(insn, head):
            if insn.ops[0].type in (idaapi.o_near, idaapi.o_far):
                target_va = int(insn.ops[0].addr)
                target_func = idaapi.get_func(target_va)
                if target_func and target_func.start_ea == target_va and target_va != current_va:
                    if depth + 1 < __MAX_CALL_DEPTH__:
                        pending.append((target_va, depth + 1))
                    if previous is not None and idc.print_insn_mnem(previous).lower() == "mov":
                        setup = idaapi.insn_t()
                        if idaapi.decode_insn(setup, previous) and len(setup.ops) >= 2:
                            if (setup.ops[0].type == idaapi.o_reg
                                    and idc.print_operand(previous, 0).lower() == ("ecx" if is_windows else "edi")
                                    and setup.ops[1].type == idaapi.o_imm
                                    and int(setup.ops[1].value) == __WEAPON_DATA_TYPE__):
                                candidates[target_va] = {
                                    "call_va": hex(head),
                                    "caller_va": hex(current_va),
                                    "caller_size": hex(current_func.end_ea - current_func.start_ea),
                                }
        previous = head
if source_func and source_func.start_ea == source_va and include_source:
    candidates[source_va] = {"call_va": None, "caller_va": None}
matches = []
for candidate_va, evidence in candidates.items():
    candidate_func = idaapi.get_func(candidate_va)
    has_string_guard = False
    has_hash_seed = False
    has_hash_multiplier = False
    for head in idautils.Heads(candidate_func.start_ea, candidate_func.end_ea):
        mnem = idc.print_insn_mnem(head).lower()
        if mnem == "test":
            has_string_guard = has_string_guard or (
                idc.print_operand(head, 0).lower() == ("rdx" if is_windows else "rsi")
                and idc.print_operand(head, 1).lower() == ("rdx" if is_windows else "rsi")
            )
        insn = idaapi.insn_t()
        if mnem in ("mov", "xor", "imul") and idaapi.decode_insn(insn, head):
            for op in insn.ops:
                if op.type != idaapi.o_imm:
                    continue
                if mnem == ("mov" if is_windows else "xor") and int(op.value) == __HASH_SEED__:
                    has_hash_seed = True
                if mnem == "imul" and int(op.value) == __HASH_MULTIPLIER__:
                    has_hash_multiplier = True
        if is_windows and mnem == "call" and idaapi.decode_insn(insn, head):
            if insn.ops[0].type in (idaapi.o_near, idaapi.o_far):
                hash_func = idaapi.get_func(int(insn.ops[0].addr))
                if hash_func and hash_func.start_ea == int(insn.ops[0].addr):
                    for hash_head in idautils.Heads(hash_func.start_ea, hash_func.end_ea):
                        if idc.print_insn_mnem(hash_head).lower() != "imul":
                            continue
                        hash_insn = idaapi.insn_t()
                        if idaapi.decode_insn(hash_insn, hash_head):
                            for op in hash_insn.ops:
                                if op.type == idaapi.o_imm and int(op.value) == __HASH_MULTIPLIER__:
                                    has_hash_multiplier = True
    if has_string_guard and has_hash_seed and has_hash_multiplier:
        matches.append({
            "func_va": hex(candidate_va),
            "func_size": hex(candidate_func.end_ea - candidate_func.start_ea),
            **evidence,
        })
result = json.dumps(matches)
"""


def _build_lookup_py_eval(source_va, *, include_source, platform="linux"):
    return (
        _LOOKUP_PY_EVAL.replace("__SOURCE_VA__", str(int(source_va)))
        .replace("__INCLUDE_SOURCE__", repr(bool(include_source)))
        .replace("__IS_WINDOWS__", repr(platform == "windows"))
        .replace("__MAX_CALL_DEPTH__", str(MAX_CALL_DEPTH))
        .replace("__WEAPON_DATA_TYPE__", str(WEAPON_DATA_TYPE))
        .replace("__HASH_SEED__", str(MURMUR_HASH_SEED))
        .replace("__HASH_MULTIPLIER__", str(MURMUR_HASH_MULTIPLIER))
    )


async def preprocess_weapon_data_lookup(
    session,
    expected_outputs,
    new_binary_dir,
    image_base,
    *,
    source_stem,
    artifact_stem,
    include_source=False,
    preserve_wrapper=False,
    platform="linux",
    debug=False,
):
    """Keep legacy dependency keys while emitting the verified lookup's semantic name."""
    if platform not in ("windows", "linux"):
        return False
    outputs = [Path(path) for path in expected_outputs if Path(path).name == f"{artifact_stem}.{platform}.yaml"]
    if len(outputs) != 1:
        return False
    try:
        source = yaml.safe_load((Path(new_binary_dir) / f"{source_stem}.{platform}.yaml").read_text(encoding="utf-8"))
        source_va = int(str(source["func_va"]), 0)
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError):
        return False

    matches = await _call_py_eval_json(
        session,
        _build_lookup_py_eval(source_va, include_source=include_source, platform=platform),
        debug=debug,
        error_label="resolving string-key weapon data lookup",
    )
    if not isinstance(matches, list) or len(matches) != 1:
        if debug:
            print(f"    Preprocess: expected one string-key weapon data lookup, got {matches}")
        return False
    match = matches[0]
    func_va = int(match["func_va"], 0)
    func_size = match["func_size"]
    func_name = TARGET_NAME
    if preserve_wrapper and match.get("caller_va") not in (None, hex(source_va)):
        func_va = int(match["caller_va"], 0)
        func_size = match["caller_size"]
        func_name = artifact_stem
    signature = await ida_analyze_util.preprocess_gen_func_sig_via_mcp(
        session=session,
        func_va=func_va,
        image_base=image_base,
        allow_across_function_boundary=False,
        debug=debug,
    )
    if not isinstance(signature, dict) or not signature.get("func_sig"):
        return False
    payload = {
        "func_name": func_name,
        "func_va": hex(func_va),
        "func_rva": hex(func_va - image_base),
        "func_size": func_size,
        "func_sig": signature["func_sig"],
    }
    ida_analyze_util.write_func_yaml(str(outputs[0]), payload)
    if debug:
        print(f"    Preprocess: written {outputs[0].name} from verified string lookup {hex(func_va)}")
    return True

#!/usr/bin/env python3
"""Resolve the optional command-line gate from verified StartFrame calls.

The two command-line hashes and their virtual dispatches identify the gate,
whether inline or a unique direct callee. Historical Windows output named an
unrelated entity-counting function, so old signatures are deliberately ignored.
"""

import inspect
import json
from pathlib import Path

from ida_analyze_util import parse_mcp_result, preprocess_gen_func_sig_via_mcp, write_func_yaml
from trusted_yaml import load_yaml_file

TARGET_FUNCTION_NAMES = ["CCSBotManager_StartFrame_ShouldUpdate"]
SOURCE_YAML_STEM = "CCSBotManager_StartFrame"
# Parameter hashes from the annotated reference gate, shared by both ABIs.
COMMAND_LINE_HASHES = (0xC53340BC, 0x2237A36D)
GENERATE_YAML_DESIRED_FIELDS = [
    ("CCSBotManager_StartFrame_ShouldUpdate", ["func_name", "func_va", "func_rva", "func_size", "func_sig"]),
]

_SCAN_CODE = """import idaapi, idautils, idc, json
source_va = __SOURCE_VA__

def collect_function(address):
    function = idaapi.get_func(address)
    if function is None or function.start_ea != address:
        return None
    instructions = []
    for ea in idautils.FuncItems(function.start_ea):
        if len(instructions) >= 4096:
            return None
        insn = idaapi.insn_t()
        if not idaapi.decode_insn(insn, ea):
            return None
        operands = []
        for index in range(2):
            operand = insn.ops[index]
            if operand.type == idaapi.o_void:
                break
            kind = {
                idaapi.o_reg: 'reg', idaapi.o_imm: 'imm',
                idaapi.o_displ: 'displ', idaapi.o_phrase: 'phrase',
                idaapi.o_near: 'near', idaapi.o_far: 'far', idaapi.o_mem: 'mem',
            }.get(operand.type, 'other')
            operands.append({
                'kind': kind, 'text': idc.print_operand(ea, index).lower(),
                'value': int(idc.get_operand_value(ea, index)),
            })
        instructions.append({'ea': int(ea), 'mnem': idc.print_insn_mnem(ea).lower(), 'ops': operands})
    return {'func_va': int(function.start_ea), 'instructions': instructions}

# MCP may execute with separate global/local namespaces.
globals().update(locals())
source = collect_function(source_va)
functions = []
if source is not None:
    targets = set()
    for instruction in source['instructions']:
        operands = instruction['ops']
        if instruction['mnem'] == 'call' and operands and operands[0]['kind'] in ('near', 'far'):
            targets.add(operands[0]['value'])
    if len(targets) <= 128:
        for target in sorted(targets - {source_va}):
            candidate = collect_function(target)
            if candidate is not None:
                functions.append(candidate)
    else:
        source = None
reason, target_va = _resolve_gate({'source': source, 'callees': functions}, __PLATFORM__)
# py_eval truncates long strings. Keep the instruction walk inside IDA and
# return only its small proof, never the complete source/callee disassembly.
result = json.dumps({
    'source_va': source['func_va'] if source else None,
    'reason': reason, 'func_va': target_va,
})
"""


def _build_scan_code(source_va, platform):
    # Embed the same pure matcher exercised by unit tests, without requiring
    # the IDA worker to import this repository or duplicate the algorithm.
    matcher = "\n".join(
        inspect.getsource(function)
        for function in (_register_family, _virtual_slot, _query_calls, _has_command_line_gate, _resolve_gate)
    )
    return (
        matcher
        + f"\nCOMMAND_LINE_HASHES = {COMMAND_LINE_HASHES!r}\n"
        + _SCAN_CODE.replace("__SOURCE_VA__", repr(source_va)).replace("__PLATFORM__", repr(platform))
    )


def _register_family(register):
    for family in ("rax eax ax al ah", "rcx ecx cx cl ch", "rdx edx dx dl dh", "rsi esi si sil"):
        aliases = family.split()
        if register in aliases:
            return aliases[0]
    if register.startswith("r") and register[1:2].isdigit():
        return register.rstrip("dwb")
    return register


def _virtual_slot(instructions, call_index):
    operand = instructions[call_index]["ops"][0]
    if operand["kind"] == "reg":
        register = operand["text"]
        # MSVC can load the slot into r8/r9 before setting up the hash.
        for instruction in reversed(instructions[max(0, call_index - 8) : call_index]):
            if instruction["mnem"] == "call" or instruction["mnem"].startswith("j"):
                return None
            ops = instruction["ops"]
            if ops and ops[0]["kind"] == "reg" and _register_family(ops[0]["text"]) == _register_family(register):
                if instruction["mnem"] != "mov" or len(ops) != 2:
                    return None
                operand = ops[1]
                break
        else:
            return None
    if operand["kind"] != "displ":
        return None
    # Stack slots and RIP-relative/import calls are not virtual dispatches.
    if any(register in operand["text"] for register in ("rsp", "rbp", "rip")):
        return None
    slot = operand["value"]
    return slot if 0 < slot < 0x1000 and slot % 8 == 0 else None


def _query_calls(instructions, argument_register, parameter_hash):
    calls = []
    for index, instruction in enumerate(instructions):
        ops = instruction["ops"]
        if not (
            instruction["mnem"] == "mov"
            and len(ops) == 2
            and ops[0]["kind"] == "reg"
            and ops[0]["text"] == argument_register
            and ops[1]["kind"] == "imm"
            and ops[1]["value"] & 0xFFFFFFFF == parameter_hash
        ):
            continue
        for call_index in range(index + 1, min(index + 9, len(instructions))):
            following = instructions[call_index]
            if following["mnem"] == "call":
                slot = _virtual_slot(instructions, call_index)
                if slot is not None:
                    calls.append((index, call_index, slot))
                break
            if following["mnem"].startswith(("j", "ret")):
                break
            following_ops = following["ops"]
            if (
                following_ops
                and following_ops[0]["kind"] == "reg"
                and _register_family(following_ops[0]["text"]) == _register_family(argument_register)
                and following["mnem"] not in {"test", "cmp", "push"}
            ):
                break
    return calls


def _has_command_line_gate(function, platform):
    instructions = function["instructions"]
    register = "edx" if platform == "windows" else "esi"
    check_calls = _query_calls(instructions, register, COMMAND_LINE_HASHES[0])
    has_calls = _query_calls(instructions, register, COMMAND_LINE_HASHES[1])
    # CheckParm and HasParm are consecutive slots. Their absolute offsets can
    # change across versions; no fixed function address or slot is required.
    return any(
        first_call < second_hash and second_slot == first_slot + 8
        for _, first_call, first_slot in check_calls
        for second_hash, _, second_slot in has_calls
    )


def _resolve_gate(scan, platform):
    source = scan.get("source")
    if not source:
        return "invalid source", None
    if _has_command_line_gate(source, platform):
        return "verified inline command-line gate", None
    direct_targets = {
        instruction["ops"][0]["value"]
        for instruction in source["instructions"]
        if instruction["mnem"] == "call" and instruction["ops"] and instruction["ops"][0]["kind"] in {"near", "far"}
    }
    candidates = {
        function["func_va"]
        for function in scan.get("callees", [])
        if function["func_va"] in direct_targets and _has_command_line_gate(function, platform)
    }
    if len(candidates) != 1:
        return f"expected one command-line gate callee, found {len(candidates)}", None
    return "verified command-line gate callee", candidates.pop()


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    module_root = Path(new_binary_dir).resolve()
    filename = f"{TARGET_FUNCTION_NAMES[0]}.{platform}.yaml"
    outputs = [Path(path) for path in expected_outputs if Path(path).name == filename]
    if platform not in {"windows", "linux"} or len(outputs) != 1 or outputs[0].resolve().parent != module_root:
        return False
    try:
        source = load_yaml_file(module_root / f"{SOURCE_YAML_STEM}.{platform}.yaml")
        source_va = int(str(source["func_va"]), 0)
        response = await session.call_tool(name="py_eval", arguments={"code": _build_scan_code(source_va, platform)})
        payload = parse_mcp_result(response)
        scan = json.loads(payload["result"])
        if not isinstance(scan, dict) or scan.get("source_va") != source_va:
            return False
        reason, func_va = scan["reason"], scan["func_va"]
    except (OSError, TypeError, ValueError, KeyError) as exc:
        if debug:
            print(f"    Preprocess: could not scan the current StartFrame call graph: {exc}")
        return False
    if debug:
        print(f"    Preprocess: {reason}" + (f" at {hex(func_va)}" if func_va is not None else ""))
    if func_va is None:
        return False
    generated = await preprocess_gen_func_sig_via_mcp(
        session=session,
        func_va=func_va,
        image_base=image_base,
        allow_across_function_boundary=False,
        debug=debug,
    )
    if not isinstance(generated, dict) or not {"func_va", "func_rva", "func_size", "func_sig"} <= generated.keys():
        return False
    if int(str(generated["func_va"]), 0) != func_va or not generated["func_sig"]:
        return False
    write_func_yaml(str(outputs[0]), {"func_name": TARGET_FUNCTION_NAMES[0], **generated})
    return True

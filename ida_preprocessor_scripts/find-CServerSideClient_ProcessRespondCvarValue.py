#!/usr/bin/env python3
"""Read the RespondCvarValue slot from the client's message registration."""

import json
from pathlib import Path

import yaml

from ida_analyze_util import parse_mcp_result, write_func_yaml
from ida_preprocessor_scripts._define_inputfunc import _resolve_output_path


TARGET_FUNCTION_NAMES = ["CServerSideClient_ProcessRespondCvarValue"]
GENERATE_YAML_DESIRED_FIELDS = [
    (TARGET_FUNCTION_NAMES[0], ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"]),
]
# CLC_Messages.clc_RespondCvarValue from the network protocol, not a vtable slot.
RESPOND_CVAR_MESSAGE_ID = 25
POINTER_SIZE = 8

REGISTRATION_QUERY = r"""
import json, ida_hexrays as h, ida_funcs, ida_ua, idautils, idc

def unwrap(e):
    while e.op in (h.cot_cast, h.cot_ref):
        e = e.x
    return e

class MessageCall(h.ctree_visitor_t):
    def __init__(self):
        super().__init__(h.CV_FAST)
        self.found = False
    def visit_expr(self, e):
        if e.op == h.cot_call and e.a.size() == 7:
            message = unwrap(e.a[1])
            if message.op == h.cot_num and int(message.numval()) == message_id:
                self.found = True
        return 0

def callback_offset(assignment):
    if assignment.op != h.cit_expr or assignment.cexpr.op != h.cot_asg:
        return None
    expr = assignment.cexpr
    rhs = unwrap(expr.y)
    if platform == 'linux':
        # Itanium virtual member pointers encode vtable byte offset + 1.
        insn = idautils.DecodeInstruction(expr.ea)
        if insn and idc.print_insn_mnem(expr.ea) == 'mov' and insn.ops[1].type == ida_ua.o_imm:
            value = int(insn.ops[1].value)
            if 1 <= value <= table_size and (value - 1) % pointer_size == 0:
                return value - 1
    elif rhs.op == h.cot_obj:
        # MSVC stores a virtual-call thunk instead of the Itanium integer.
        func = ida_funcs.get_func(rhs.obj_ea)
        if func and func.start_ea == rhs.obj_ea:
            offsets = set()
            for ea in idautils.FuncItems(func.start_ea):
                insn = idautils.DecodeInstruction(ea)
                if idc.print_insn_mnem(ea) in ('jmp', 'call') and insn and insn.ops[0].type == ida_ua.o_displ:
                    offset = int(insn.ops[0].addr)
                    if 0 <= offset < table_size and offset % pointer_size == 0:
                        offsets.add(offset)
            if len(offsets) == 1:
                return offsets.pop()
    return None

class Blocks(h.ctree_visitor_t):
    def __init__(self):
        super().__init__(h.CV_FAST)
        self.matches = []
    def visit_insn(self, insn):
        if insn.op == h.cit_block:
            statements = list(insn.cblock)
            for index, statement in enumerate(statements):
                if statement.op != h.cit_if:
                    continue
                calls = MessageCall()
                calls.apply_to(statement.cif.ithen, None)
                if not calls.found:
                    continue
                offsets = set()
                # The callback aggregate is initialized immediately before the
                # lazy message-type lookup: this, member pointer, this-adjustment.
                for previous in reversed(statements[:index]):
                    # MSVC can insert a null-this adjustment between callback
                    # initialization and the lazy message-type lookup.
                    if previous.op == h.cit_if:
                        guard = MessageCall()
                        guard.apply_to(previous, None)
                        if guard.found:
                            break
                        continue
                    if previous.op != h.cit_expr or previous.cexpr.op != h.cot_asg:
                        break
                    offset = callback_offset(previous)
                    if offset is not None:
                        offsets.add(offset)
                        break
                if len(offsets) == 1:
                    self.matches.append({'registration': int(insn.ea), 'offset': offsets.pop()})
        return 0

matches = []
for address in functions:
    func = ida_funcs.get_func(address)
    if not func:
        continue
    # Avoid decompiling unrelated table members. The message registration
    # necessarily materializes the protocol ID as an immediate.
    has_message = False
    for ea in idautils.FuncItems(func.start_ea):
        insn = idautils.DecodeInstruction(ea)
        if insn and any(op.type == ida_ua.o_imm and int(op.value) == message_id for op in insn.ops):
            has_message = True
            break
    if not has_message:
        continue
    body = h.decompile(func.start_ea)
    if body:
        visitor = Blocks()
        visitor.apply_to(body.body, None)
        matches.extend(visitor.matches)
result = matches
"""


def unique_slot(matches, table_size):
    """Fail closed unless all registration evidence identifies one valid slot."""
    offsets = {item["offset"] for item in matches}
    if len(offsets) != 1:
        return None
    offset = offsets.pop()
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or offset >= table_size:
        return None
    return offset // POINTER_SIZE if offset % POINTER_SIZE == 0 else None


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
    table = yaml.safe_load(
        (Path(new_binary_dir) / f"CServerSideClient_vtable.{platform}.yaml").read_text(encoding="utf-8")
    )
    params = {
        "functions": sorted({int(ea, 0) for ea in table["vtable_entries"].values()}),
        "table_size": int(table["vtable_numvfunc"]) * POINTER_SIZE,
        "message_id": RESPOND_CVAR_MESSAGE_ID,
        "pointer_size": POINTER_SIZE,
        "platform": platform,
    }
    code = f"import json\nnamespace = {params!r}\nexec({REGISTRATION_QUERY!r}, namespace)\nresult = json.dumps(namespace['result'])"
    response = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if response.get("stderr"):
        raise RuntimeError(response["stderr"])
    matches = json.loads(response.get("result", "null")) or []
    slot = unique_slot(matches, params["table_size"])
    output = _resolve_output_path(expected_outputs, TARGET_FUNCTION_NAMES[0], platform, debug)
    if slot is None or not output:
        if debug:
            print(f"    Preprocess: ambiguous RespondCvarValue registration: {matches}")
        return False
    write_func_yaml(
        output,
        {
            "func_name": TARGET_FUNCTION_NAMES[0],
            "vtable_name": "CServerSideClient",
            "vfunc_offset": hex(slot * POINTER_SIZE),
            "vfunc_index": slot,
        },
    )
    return True

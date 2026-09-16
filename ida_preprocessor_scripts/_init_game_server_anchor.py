"""Anchor InitGameServer's GetFakeLag call to ``g_pNetworkSystem`` data flow."""

import inspect
import json
import os

import yaml

from ida_analyze_util import parse_mcp_result


SYMBOL = "INetworkSystem_GetFakeLag"
SOURCE_SYMBOL = "CSteam3ServerS1_InitGameServer"
GLOBAL_SYMBOL = "g_pNetworkSystem"
VFUNC_OFFSET = 0x118


def _probe_anchor(func_va, global_va):
    """Run inside IDA and return the network-system ``+0x118`` call site."""
    import ida_bytes
    import ida_funcs
    import idaapi
    import ida_lines
    import idautils
    import idc

    function = ida_funcs.get_func(func_va)
    if function is None:
        raise ValueError("InitGameServer function is unavailable")

    candidates = []
    for xref in idautils.XrefsTo(global_va, 0):
        start = int(xref.frm)
        if not (function.start_ea <= start < function.end_ea):
            continue
        ea = start
        # The global load, vtable load, and indirect call are adjacent.  Bound
        # the scan so a later, unrelated use of g_pNetworkSystem cannot match.
        for _ in range(6):
            if not (function.start_ea <= ea < function.end_ea):
                break
            if idc.print_insn_mnem(ea).lower() == "call":
                disasm = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
                instruction = idaapi.insn_t()
                if idaapi.decode_insn(instruction, ea) > 0:
                    has_slot = any(
                        int(operand.type) == int(idaapi.o_displ) and int(operand.addr) == VFUNC_OFFSET
                        for operand in instruction.ops
                        if int(operand.type) != int(idaapi.o_void)
                    )
                    if has_slot:
                        candidates.append({"insn_va": int(ea), "insn_disasm": disasm})
                break
            ea = ida_bytes.next_head(ea + 1, function.end_ea)
            if ea == idaapi.BADADDR:
                break
    return candidates


def select_anchor(candidates):
    if len(candidates) != 1:
        raise ValueError(f"expected one {GLOBAL_SYMBOL} +{hex(VFUNC_OFFSET)} call, found {len(candidates)}")
    return candidates[0]


async def load_anchor(session, artifact_dir, platform):
    def load_address(symbol_name):
        path = os.path.join(artifact_dir, f"{symbol_name}.{platform}.yaml")
        with open(path, encoding="utf-8") as stream:
            payload = yaml.safe_load(stream)
        return int(str(payload["func_va" if symbol_name == SOURCE_SYMBOL else "gv_va"]), 0)

    func_va = load_address(SOURCE_SYMBOL)
    global_va = load_address(GLOBAL_SYMBOL)
    code = (
        inspect.getsource(_probe_anchor)
        + f"\nimport json\nprint(json.dumps(_probe_anchor({func_va}, {global_va})))"
    )
    result = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
    if not isinstance(result, dict):
        raise ValueError("missing InitGameServer anchor probe result")
    candidates = json.loads(result.get("stdout") or result.get("result") or "null")
    if not isinstance(candidates, list):
        raise ValueError("invalid InitGameServer anchor probe result")
    return select_anchor(candidates)


def validate_result(parsed_result, anchor):
    from ida_llm_decompile import _parse_llm_int_value

    entries = [entry for entry in parsed_result.get("found_vcall", []) if entry.get("func_name") == SYMBOL]
    if len(entries) != 1:
        return [f"{SYMBOL}: return exactly one found_vcall entry for the verified network-system call."]
    entry = entries[0]
    if _parse_llm_int_value(entry.get("insn_va")) != anchor["insn_va"]:
        return [
            f"{SYMBOL}: select the {GLOBAL_SYMBOL} call at {hex(anchor['insn_va'])} "
            f"({anchor['insn_disasm']}), not an unrelated virtual call."
        ]
    if _parse_llm_int_value(entry.get("vfunc_offset")) != VFUNC_OFFSET:
        return [f"{SYMBOL}: the verified {GLOBAL_SYMBOL} call uses slot {hex(VFUNC_OFFSET)}."]
    return []

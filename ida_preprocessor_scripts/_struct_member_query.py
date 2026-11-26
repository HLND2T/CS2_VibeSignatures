"""Run a deterministic IDA member query and write the resolved artifact group."""

import json
from pathlib import Path

import yaml

from ida_analyze_util import parse_mcp_result, preprocess_gen_struct_offset_sig_via_mcp, write_struct_offset_yaml
from ida_preprocessor_scripts._define_inputfunc import _resolve_output_path


IDA_OPERANDS = r"""
import re

import ida_funcs
import ida_ua
import idautils
import idc


def instructions(ea):
    func = ida_funcs.get_func(ea)
    if not func or func.start_ea != ea:
        return []
    return [insn for head in idautils.FuncItems(ea) if (insn := idautils.DecodeInstruction(head))]


def mnemonic(insn):
    return idc.print_insn_mnem(insn.ea)


def operand(insn, index):
    return idc.print_operand(insn.ea, index)


def memory(insn, index):
    op = insn.ops[index]
    if op.type not in (ida_ua.o_displ, ida_ua.o_phrase):
        return None
    match = re.search(r'\[([a-z][a-z0-9]*)(?:\+(?:[0-9][0-9a-f]*h|[0-9]+))?\]$', operand(insn, index), re.I)
    if not match:
        return None
    base = match[1]
    return base, (op.addr if op.type == ida_ua.o_displ else 0), ida_ua.get_dtype_size(op.dtype)


def immediate(insn, index, value):
    op = insn.ops[index]
    if op.type != ida_ua.o_imm:
        return False
    mask = (1 << (8 * ida_ua.get_dtype_size(op.dtype))) - 1
    return (op.value & mask) == value


def near_target(insn):
    op = insn.ops[0]
    return op.addr if op.type == ida_ua.o_near else None


def references_text(insn, prefix):
    for ea in idautils.DataRefsFrom(insn.ea):
        value = idc.get_strlit_contents(ea)
        if value and value.startswith(prefix):
            return True
    return False
"""


async def preprocess_member_query(
    session,
    expected_outputs,
    artifact_dir,
    platform,
    image_base,
    *,
    prerequisite=None,
    query,
    targets,
    allow_across_function_boundary=False,
    debug,
):
    if platform != "windows":
        return False

    source = None
    if prerequisite:
        path = Path(artifact_dir) / f"{prerequisite}.{platform}.yaml"
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
            source = int(str(payload["func_va"]), 0)
        except (OSError, TypeError, ValueError, KeyError, yaml.YAMLError) as exc:
            if debug:
                print(f"    Preprocess: cannot load {path}: {exc}")
            return False

    code = (
        f"import json\nnamespace = {{'source': {source!r}}}\n"
        f"exec({IDA_OPERANDS + query!r}, namespace)\nresult = json.dumps(namespace['result'])"
    )
    response = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if response.get("stderr"):
        raise RuntimeError(response["stderr"])
    sites = json.loads(response.get("result") or "null")
    if not sites or len(sites) != len(targets):
        if debug:
            print(f"    Preprocess: could not identify a unique set of member accesses for {targets}")
        return False

    outputs = []
    for (struct, member), (ea, offset, size) in zip(targets, sites, strict=True):
        output = _resolve_output_path(expected_outputs, f"{struct}_{member}", platform, debug)
        if not output:
            return False
        if offset:
            payload = await preprocess_gen_struct_offset_sig_via_mcp(
                session,
                struct,
                member,
                offset,
                ea,
                image_base,
                size=size,
                allow_across_function_boundary=allow_across_function_boundary,
                debug=debug,
            )
            if not payload:
                return False
            if allow_across_function_boundary:
                payload["offset_sig_allow_across_function_boundary"] = True
        else:
            # The reuse decoder cannot recover a displacement from a bare [reg] operand.
            payload = {"struct_name": struct, "member_name": member, "offset": 0, "size": size}
        outputs.append((output, payload))

    for output, payload in outputs:
        write_struct_offset_yaml(output, payload)
    return True

"""Recover the two time fields from the engine's minidump diagnostics."""

from ida_preprocessor_scripts._struct_member_query import preprocess_member_query


QUERY = r"""
FORMAT = b'Curtime( %f )\nRealtime( %f )\n'


def find():
    candidates = []
    for string in idautils.Strings():
        if str(string).encode('utf-8') != FORMAT:
            continue
        for xref in idautils.DataRefsTo(string.ea):
            func = ida_funcs.get_func(xref)
            if not func:
                continue
            body = instructions(func.start_ea)
            index = next((i for i, insn in enumerate(body) if insn.ea == xref), 0)
            if index < 6 or index + 2 >= len(body):
                continue
            rt, rt_convert, ct, ct_convert, rt_arg, ct_arg = body[index - 6:index]
            fmt, this, call = body[index:index + 3]
            if mnemonic(fmt) != 'lea' or operand(fmt, 0) != 'rdx':
                continue
            if mnemonic(this) != 'mov' or operand(this, 0) != 'rcx':
                continue
            if mnemonic(call) != 'call' or 'AppendFormattedComment@CMiniDumpComment' not in operand(call, 0):
                continue
            if not (float_argument(rt, rt_convert, rt_arg, 'r9') and float_argument(ct, ct_convert, ct_arg, 'r8')):
                continue
            realtime, curtime = memory(rt, 1), memory(ct, 1)
            if realtime and curtime and realtime[0] == curtime[0] and realtime[2] == curtime[2] == 4:
                candidates.append([(rt.ea, *realtime[1:]), (ct.ea, *curtime[1:])])
    return candidates[0] if len(candidates) == 1 else None


def float_argument(load, convert, move_arg, reg):
    xmm = operand(load, 0)
    return (
        mnemonic(load) == 'movss'
        and mnemonic(convert) == 'cvtps2pd'
        and operand(convert, 0) == operand(convert, 1) == xmm
        and mnemonic(move_arg) == 'movq'
        and operand(move_arg, 0) == reg
        and operand(move_arg, 1) == xmm
    )


result = find()
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_member_query(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        query=QUERY,
        targets=(("CGlobalVarsBase", "realtime"), ("CGlobalVarsBase", "curtime")),
        debug=debug,
    )

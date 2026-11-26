"""Locate the game client pointer through the service's IsActive check."""

from ida_preprocessor_scripts._struct_member_query import preprocess_member_query


QUERY = r"""
def find():
    body = instructions(source)
    candidates = []
    for index, load in enumerate(body[:-2]):
        field = memory(load, 1)
        reg = operand(load, 0)
        if mnemonic(load) != 'mov' or load.ops[0].type != ida_ua.o_reg or not field:
            continue
        if field[0] != 'rcx' or field[2] != 8:
            continue
        check, jump = body[index + 1:index + 3]
        if mnemonic(check) != 'test' or [operand(check, i) for i in (0, 1)] != [reg, reg]:
            continue
        if mnemonic(jump) != 'jnz':
            continue
        compare = idautils.DecodeInstruction(near_target(jump))
        state = memory(compare, 0) if compare else None
        if state and state[0] == reg and state[2] == 4 and mnemonic(compare) == 'cmp' and immediate(compare, 1, 6):
            candidates.append([(load.ea, field[1], field[2])])
    return candidates[0] if len(candidates) == 1 else None


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
        prerequisite="CNetworkClientService_IsActive",
        query=QUERY,
        targets=(("CNetworkClientService", "m_pGameClient"),),
        allow_across_function_boundary=True,
        debug=debug,
    )

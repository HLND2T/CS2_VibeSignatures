"""Recover the embedded entity list and identity fields from chunk initialization."""

from ida_preprocessor_scripts._struct_member_query import preprocess_member_query


QUERY = r"""
CHUNK_LOG = b'ConcreteEntityList:  approaching limit, allocating entity chu'


def identity_fields(body):
    candidates = []
    indices = {insn.ea: index for index, insn in enumerate(body)}
    for index, jump in enumerate(body):
        if mnemonic(jump) != 'jnz':
            continue
        start = indices.get(near_target(jump), index)
        if start >= index - 2:
            continue
        first = body[start]
        handle = memory(first, 0)
        if not handle or handle[2] != 4 or mnemonic(first) != 'mov' or not immediate(first, 1, 0xffffffff):
            continue
        # The initializer clears consecutive pointer fields, then calls the
        # constructor of another embedded field in the same identity.
        for previous, instance, call in zip(body[start:index - 1], body[start + 1:index], body[start + 2:index + 1]):
            field = memory(instance, 0)
            neighbour = memory(previous, 0)
            if not field or not neighbour or mnemonic(instance) != 'mov' or mnemonic(previous) != 'mov':
                continue
            if field[0] != handle[0] or neighbour != (field[0], field[1] + field[2], 8) or field[2] != 8:
                continue
            if operand(instance, 1) != operand(previous, 1) or mnemonic(call) != 'call' or not near_target(call):
                continue
            # Another dword is initialized immediately before the two pointer slots.
            before = body[indices[previous.ea] - 1]
            preceding_field = memory(before, 0)
            if mnemonic(before) != 'mov' or not preceding_field or preceding_field[::2] != (field[0], 4):
                continue
            step = body[index - 2]
            if mnemonic(step) != 'add' or operand(step, 0) != field[0] or step.ops[1].type != ida_ua.o_imm:
                continue
            # Later in chunk allocation, the handle's index bits are initialized.
            if any(mnemonic(insn) == 'or' and (mem := memory(insn, 0)) and mem[1:] == handle[1:]
                   and immediate(insn, 1, 0x7fff) for insn in body[index + 1:]):
                candidates.append([(instance.ea, *field[1:]), (first.ea, *handle[1:])])
    return candidates[0] if len(candidates) == 1 else None


def find():
    ctor = instructions(source)
    by_callee = {}
    fields_by_callee = {}
    for previous, call in zip(ctor, ctor[1:]):
        if mnemonic(call) != 'call' or mnemonic(previous) != 'lea' or operand(previous, 0) != 'rcx':
            continue
        field = memory(previous, 1)
        callee = near_target(call)
        if not field or not callee:
            continue
        if callee not in fields_by_callee:
            body = instructions(callee)
            fields_by_callee[callee] = (
                identity_fields(body) if any(references_text(insn, CHUNK_LOG) for insn in body) else None
            )
        if fields_by_callee[callee]:
            by_callee.setdefault(callee, []).append((previous.ea, field[0], field[1]))
    if len(by_callee) != 1:
        return None
    callee, direct_sites = next(iter(by_callee.items()))
    # Both constructor calls use the same embedded list, one for each kind
    # of entity. The first may have instructions between the LEA and CALL.
    confirmed = []
    for index, call in enumerate(ctor):
        if mnemonic(call) != 'call' or near_target(call) != callee:
            continue
        for previous in reversed(ctor[max(0, index - 8):index]):
            if mnemonic(previous) == 'call':
                break
            if operand(previous, 0) != 'rcx':
                continue
            field = memory(previous, 1)
            if mnemonic(previous) == 'lea' and field:
                confirmed.append((field[0], field[1]))
            break
    ea, base, offset = direct_sites[-1]
    if len(confirmed) < 2 or set(confirmed) != {(base, offset)}:
        return None
    return [(ea, offset, None), *fields_by_callee[callee]]


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
        prerequisite="CEntitySystem_ctor",
        query=QUERY,
        targets=(
            ("CEntitySystem", "m_EntityList"),
            ("CEntityIdentity", "m_pInstance"),
            ("CEntityIdentity", "m_EHandle"),
        ),
        debug=debug,
    )

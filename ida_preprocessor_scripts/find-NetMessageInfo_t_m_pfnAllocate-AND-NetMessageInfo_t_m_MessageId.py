"""Recover the allocator and message ID fields from descriptor registration."""

from ida_preprocessor_scripts._struct_member_query import preprocess_member_query


QUERY = r"""
def move(insn, destination, source=None):
    return (
        mnemonic(insn) == 'mov'
        and operand(insn, 0) == destination
        and (source is None or operand(insn, 1) == source)
    )


def find():
    body = instructions(source)
    # Identify the incoming allocator's home slot by its register, then use
    # the frame variable name to match the reload after RSP has changed.
    slots = {
        operand(insn, 0).rsplit('+', 1)[-1]
        for insn in body[:4]
        if mnemonic(insn) == 'mov' and operand(insn, 1) == 'r8' and operand(insn, 0).startswith('[rsp+')
    }
    if len(slots) != 1:
        return None
    slot = slots.pop()

    candidates = []
    for index, store in enumerate(body[6:], 6):
        message_id = memory(store, 0)
        if mnemonic(store) != 'mov' or not message_id or message_id[2] != 4:
            continue
        descriptor = message_id[0]
        id_reg = operand(store, 1)
        desc_arg, id_arg, name_arg, registry_arg, call, clear = body[index - 6:index]
        if not (
            move(desc_arg, 'r9', descriptor) and move(id_arg, 'r8d', id_reg)
            and move(name_arg, 'rdx') and move(registry_arg, 'rcx')
            and mnemonic(call) == 'call' and near_target(call)
            and mnemonic(clear) == 'xor' and operand(clear, 0) == operand(clear, 1)
            and any(move(insn, id_reg, 'edx') for insn in body[:16])
        ):
            continue
        allocator_sites = allocator_stores(body[:index], descriptor, slot)
        if len(allocator_sites) == 1:
            candidates.append([allocator_sites[0], (store.ea, *message_id[1:])])
    return candidates[0] if len(candidates) == 1 else None


def allocator_stores(body, descriptor, slot):
    starts = [
        index for index, insn in enumerate(body)
        if move(insn, descriptor, 'rax') and index >= 2
        and mnemonic(body[index - 2]) == 'call' and memory(body[index - 2], 0)
        and any(
            'g_pMemAlloc' in operand(item, 1) for item in body[max(0, index - 8):index - 2]
        )
    ]
    if len(starts) != 1:
        return []
    stores = []
    for index in range(starts[0] + 2, len(body)):
        reload, between, store = body[index - 2:index + 1]
        field = memory(store, 0)
        reg = operand(store, 1)
        if not field or field[0] != descriptor or field[2] != 8 or mnemonic(store) != 'mov':
            continue
        if not move(reload, reg) or not operand(reload, 1).startswith('[rsp+'):
            continue
        if operand(reload, 1).rsplit('+', 1)[-1] != slot:
            continue
        if mnemonic(between) == 'and' and between.ops[0].reg != reload.ops[0].reg:
            stores.append((store.ea, *field[1:]))
    return stores


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
        prerequisite="CNetworkMessages_FindOrCreateNetMessage",
        query=QUERY,
        targets=(("NetMessageInfo_t", "m_pfnAllocate"), ("NetMessageInfo_t", "m_MessageId")),
        debug=debug,
    )

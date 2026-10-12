#!/usr/bin/env python3
"""Preprocess script for find-CNetworkSystem_GetLocalAdr.

Inherits the INetworkSystem::GetLocalAdr slot recovered in the engine module and
resolves the CNetworkSystem override inside networksystem. The override is a
two-instruction member-address getter (``lea rax, [this+30h]; retn``), too short
to sign uniquely, so the vtable slot is the stable locator and func_sig is omitted.
"""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    (
        "CNetworkSystem_GetLocalAdr",
        "CNetworkSystem",
        "../engine/INetworkSystem_GetLocalAdr",
        False,
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkSystem_GetLocalAdr",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
]


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
    """Inherit the GetLocalAdr slot from INetworkSystem (engine module)."""
    _ = skill_name
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

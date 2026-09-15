#!/usr/bin/env python3
"""Preprocess script for find-CNetworkSystem_BufferToBufferCompress skill."""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    (
        "CNetworkSystem_BufferToBufferCompress",
        "CNetworkSystem",
        "../engine/INetworkSystem_BufferToBufferCompress",
        True,
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkSystem_BufferToBufferCompress",
        [
            "func_name", "func_va", "func_rva", "func_size", "func_sig",
            "vtable_name", "vfunc_offset", "vfunc_index",
        ],
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform,
    image_base, debug=False,
):
    """Resolve the CNetworkSystem override at the inherited interface slot."""
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

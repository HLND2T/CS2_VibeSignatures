#!/usr/bin/env python3
"""Resolve INetworkGameServer::SetGameSpawnGroupMgr from its forwarding thunk."""

from ida_preprocessor_scripts._indirect_vcall_target_common import (
    preprocess_indirect_vcall_target_skill,
)


SOURCE_FUNCTION_NAME = "CNetworkServerService_SetGameSpawnGroupMgr"
TARGET_FUNCTION_NAME = "INetworkGameServer_SetGameSpawnGroupMgr"
VTABLE_CLASS = "INetworkGameServer"

GENERATE_YAML_DESIRED_FIELDS = [
    (
        TARGET_FUNCTION_NAME,
        ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"],
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
    _ = skill_name, old_yaml_map, image_base
    return await preprocess_indirect_vcall_target_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        source_yaml_stem=SOURCE_FUNCTION_NAME,
        target_name=TARGET_FUNCTION_NAME,
        vtable_name=VTABLE_CLASS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

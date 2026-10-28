#!/usr/bin/env python3
"""Preprocess script for find-INetworkGameClient_SendStringCmd skill.

INetworkGameClient::SendStringCmd is dispatched by CEngineClient::ServerCmd
(the historical artifact key is ExecuteClientCmd). Windows dispatches directly;
Linux may tail-call a helper whose guarded tail dispatch loads the virtual slot.
"""

from ida_preprocessor_scripts._indirect_vcall_target_common import (
    preprocess_indirect_vcall_target_skill,
)

SOURCE_FUNCTION_NAME = "CEngineClient_ExecuteClientCmd"

TARGET_FUNCTION_NAME = "INetworkGameClient_SendStringCmd"
VTABLE_CLASS = "INetworkGameClient"

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "INetworkGameClient_SendStringCmd",
        [
            "func_name",
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
    """Resolve the ServerCmd dispatch, following one Linux helper when needed."""
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
        # Linux lowers the vtable dispatch to ``mov reg, [reg+disp]`` + ``jmp reg``.
        resolve_load_then_branch=True,
        follow_direct_tail_jump=platform == "linux",
        debug=debug,
    )

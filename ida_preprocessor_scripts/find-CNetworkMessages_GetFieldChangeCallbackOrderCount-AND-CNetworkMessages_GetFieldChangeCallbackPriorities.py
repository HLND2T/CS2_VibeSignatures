#!/usr/bin/env python3
"""Preprocess script for find-CNetworkMessages_GetFieldChangeCallbackOrderCount-AND-CNetworkMessages_GetFieldChangeCallbackPriorities skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkMessages_GetFieldChangeCallbackOrderCount",
    "CNetworkMessages_GetFieldChangeCallbackPriorities",
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class, generate_vfunc_offset)
    ("CNetworkMessages_GetFieldChangeCallbackOrderCount", "CNetworkMessages", True),
    ("CNetworkMessages_GetFieldChangeCallbackPriorities", "CNetworkMessages", True),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        debug=debug,
    )

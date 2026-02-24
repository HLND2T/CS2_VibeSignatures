#!/usr/bin/env python3
"""Preprocess script for find-CCSBotManager_AddBot-AND-g_pCSBotManager-AND-g_pNavMesh skill."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = [
    "CCSBotManager_AddBot",
]

TARGET_GLOBALVAR_NAMES = [
    "g_pCSBotManager",
    "g_pNavMesh",
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever func_sig/gv_sig to locate targets and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        gv_names=TARGET_GLOBALVAR_NAMES,
        debug=debug,
    )

#!/usr/bin/env python3
"""Preprocess script for find-CLoopModeGame_LoopShutdown skill."""

from ida_analyze_util import preprocess_common_skill

# CLoopModeGame_Shutdown has been inlined into CLoopModeGame_LoopShutdown
TARGET_FUNCTION_NAMES_WINDOWS = [
    "CLoopModeGame_LoopShutdown",
]

TARGET_FUNCTION_NAMES_LINUX = [
    "CLoopModeGame_Shutdown",
    "CLoopModeGame_LoopShutdown",
]

FUNC_XREFS_WINDOWS = [
    # (func_name, xref_strings_list, xref_funcs_list, exclude_funcs_list)
    (
        "CLoopModeGame_LoopShutdown",
        ["--CLoopModeGame::SetWorldSession"],
        ["CLoopModeGame_SetGameSystemState", "IGameSystem_DestroyAllGameSystems"],
        ["CLoopModeGame_ReceivedServerInfo", "CLoopModeGame_SetWorldSession"],
    ),
]

FUNC_XREFS_LINUX = [
    # (func_name, xref_strings_list, xref_funcs_list, exclude_funcs_list)
    (
        "CLoopModeGame_Shutdown",
        ["--CLoopModeGame::SetWorldSession"],
        ["CLoopModeGame_SetGameSystemState", "IGameSystem_DestroyAllGameSystems"],
        ["CLoopModeGame_SetWorldSession"],
    ),
    (
        "CLoopModeGame_LoopShutdown",
        [],
        ["CLoopModeGame_Shutdown"],
        ["CLoopModeGame_SetWorldSession"],
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class, generate_vfunc_offset)
    ("CLoopModeGame_LoopShutdown", "CLoopModeGame", True),
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
        func_names=TARGET_FUNCTION_NAMES_WINDOWS if platform == "windows" else TARGET_FUNCTION_NAMES_LINUX,
        func_xrefs=FUNC_XREFS_WINDOWS if platform == "windows" else FUNC_XREFS_LINUX,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Preprocess script for finding CCSPlayerController think functions on Windows.

Decompiles CCSPlayerController_GetThinkFunction and identifies the 4 think function
pointers stored in the schema structure initialization code.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CCSPlayerController_PlayerForceTeamThink",
    "CCSPlayerController_ResetForceTeamThink",
    "CCSPlayerController_ResourceDataThink",
    "CCSPlayerController_InventoryUpdateThink",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CCSPlayerController_PlayerForceTeamThink",
        "prompt/call_llm_decompile.md",
        "references/server/CCSPlayerController_GetThinkFunction.{platform}.yaml",
    ),
    (
        "CCSPlayerController_ResetForceTeamThink",
        "prompt/call_llm_decompile.md",
        "references/server/CCSPlayerController_GetThinkFunction.{platform}.yaml",
    ),
    (
        "CCSPlayerController_ResourceDataThink",
        "prompt/call_llm_decompile.md",
        "references/server/CCSPlayerController_GetThinkFunction.{platform}.yaml",
    ),
    (
        "CCSPlayerController_InventoryUpdateThink",
        "prompt/call_llm_decompile.md",
        "references/server/CCSPlayerController_GetThinkFunction.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CCSPlayerController_PlayerForceTeamThink",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
    ),
    (
        "CCSPlayerController_ResetForceTeamThink",
        ["func_name", "func_va", "func_rva", "func_size"],# too short to have an unique signature
    ),
    (
        "CCSPlayerController_ResourceDataThink",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
    ),
    (
        "CCSPlayerController_InventoryUpdateThink",
        ["func_name", "func_va", "func_rva", "func_size"],# too short to have an unique signature
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
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
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Preprocess script for finding CCSPlayerController think schema globals on Linux.

Decompiles CCSPlayerController_RegisterThink and identifies the 4 global variables
where the schema name results are stored. The actual think function pointers are
at these globals + 0x28, resolved by a separate programmatic script.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBALVAR_NAMES = [
    "g_CCSPlayerController_PlayerForceTeamThink",
    "g_CCSPlayerController_ResetForceTeamThink",
    "g_CCSPlayerController_ResourceDataThink",
    "g_CCSPlayerController_InventoryUpdateThink",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "g_CCSPlayerController_PlayerForceTeamThink",
        "prompt/call_llm_decompile.md",
        "references/server/CCSPlayerController_RegisterThink.{platform}.yaml",
    ),
    (
        "g_CCSPlayerController_ResetForceTeamThink",
        "prompt/call_llm_decompile.md",
        "references/server/CCSPlayerController_RegisterThink.{platform}.yaml",
    ),
    (
        "g_CCSPlayerController_ResourceDataThink",
        "prompt/call_llm_decompile.md",
        "references/server/CCSPlayerController_RegisterThink.{platform}.yaml",
    ),
    (
        "g_CCSPlayerController_InventoryUpdateThink",
        "prompt/call_llm_decompile.md",
        "references/server/CCSPlayerController_RegisterThink.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "g_CCSPlayerController_PlayerForceTeamThink",
        [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
        ],
    ),
    (
        "g_CCSPlayerController_ResetForceTeamThink",
        [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
        ],
    ),
    (
        "g_CCSPlayerController_ResourceDataThink",
        [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
        ],
    ),
    (
        "g_CCSPlayerController_InventoryUpdateThink",
        [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
            "gv_sig_allow_across_function_boundary: true",  # too few insns before func end
        ],
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever gv_sig to locate target global variables and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=TARGET_GLOBALVAR_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

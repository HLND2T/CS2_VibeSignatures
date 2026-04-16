#!/usr/bin/env python3
"""Preprocess script for find-CPlayer_MovementServices_s_pRunCommandPawn skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBALVAR_NAMES = [
    "CPlayer_MovementServices_s_pRunCommandPawn",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CPlayer_MovementServices_s_pRunCommandPawn",
        "prompt/call_llm_decompile.md",
        "references/server/CPlayer_MovementServices_ForceButtons.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CPlayer_MovementServices_s_pRunCommandPawn",
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
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever gv_sig to locate target global variable and write YAML."""
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

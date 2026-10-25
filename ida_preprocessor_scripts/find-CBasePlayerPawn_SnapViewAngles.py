#!/usr/bin/env python3
"""Find SnapViewAngles in the immediate-angle branch of setang_exact."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CBasePlayerPawn_SnapViewAngles"]
LLM_DECOMPILE = [
    {
        "symbol_name": "CBasePlayerPawn_SnapViewAngles",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/server/SetAngExact_CommandHandler.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"SetAngExact_CommandHandler.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CBasePlayerPawn_SnapViewAngles", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
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

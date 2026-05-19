#!/usr/bin/env python3
"""Preprocess script for find-CPhysExplosion_Explode-AND-UTIL_Remove skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CPhysExplosion_Explode",
    "UTIL_Remove",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CPhysExplosion_Explode",
        "prompt/call_llm_decompile.md",
        "references/server/CPhysExplosion_Activate.{platform}.yaml",
    ),
    (
        "UTIL_Remove",
        "prompt/call_llm_decompile.md",
        "references/server/CPhysExplosion_Activate.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CPhysExplosion_Explode",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    # No func_sig: UTIL_Remove is a tiny stub whose head bytes are not unique in the
    # binary. LLM_DECOMPILE is used to locate it each time.
    (
        "UTIL_Remove",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
        ],
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

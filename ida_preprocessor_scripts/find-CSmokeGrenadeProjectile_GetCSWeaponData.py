#!/usr/bin/env python3
"""Preprocess script for find-CSmokeGrenadeProjectile_GetCSWeaponData skill (deinline-fix chain, link 1/3)."""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._weapon_data_from_key_common import preprocess_weapon_data_lookup

TARGET_FUNCTION_NAMES = [
    "CSmokeGrenadeProjectile_GetCSWeaponData",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CSmokeGrenadeProjectile_GetCSWeaponData",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CSmokeGrenadeProjectile_Create.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "CSmokeGrenadeProjectile_Create.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CSmokeGrenadeProjectile_GetCSWeaponData",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
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
    llm_config=None,
    debug=False,
):
    """Resolve the lookup anchor; Linux may inline the old intermediate wrapper."""
    if platform == "linux":
        return await preprocess_weapon_data_lookup(
            session,
            expected_outputs,
            new_binary_dir,
            image_base,
            source_stem="CSmokeGrenadeProjectile_Create",
            artifact_stem="CSmokeGrenadeProjectile_GetCSWeaponData",
            preserve_wrapper=True,
            debug=debug,
        )
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

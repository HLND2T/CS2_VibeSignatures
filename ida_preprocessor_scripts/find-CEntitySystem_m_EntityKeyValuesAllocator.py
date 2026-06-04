#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_m_EntityKeyValuesAllocator skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_STRUCT_MEMBER_NAMES = [
    "CEntitySystem_m_EntityKeyValuesAllocator",
]

LLM_DECOMPILE = [
    (
        "CEntitySystem_m_EntityKeyValuesAllocator",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySpawner_CPlayerSprayDecal_Spawn.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEntitySystem_m_EntityKeyValuesAllocator",
        [
            "struct_name",
            "member_name",
            "offset",
            "offset_sig",
            "offset_sig_disp",
            "offset_sig_max_match:2",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever offset_sig to locate target struct offset and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

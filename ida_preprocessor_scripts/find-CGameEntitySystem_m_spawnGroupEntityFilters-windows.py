#!/usr/bin/env python3
"""Preprocess script for find-CGameEntitySystem_m_spawnGroupEntityFilters-windows skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_STRUCT_MEMBER_NAMES = [
    "CGameEntitySystem_m_spawnGroupEntityFilters",
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CGameEntitySystem_m_spawnGroupEntityFilters",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever offset_sig to locate struct member and write YAML."""
    llm_decompile = [
        (
            "CGameEntitySystem_m_spawnGroupEntityFilters",
            "prompt/call_llm_decompile.md",
            "references/{module_name}/CSpawnGroupEntityFilterRegistrar_RegisterSpawnGroupEntityFilters.{platform}.yaml",
        ),
    ]

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=llm_decompile,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

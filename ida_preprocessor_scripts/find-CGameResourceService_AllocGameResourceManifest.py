#!/usr/bin/env python3
"""Preprocess script for find-CGameResourceService_AllocGameResourceManifest skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameResourceService_AllocGameResourceManifest",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CGameResourceService_AllocGameResourceManifest",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerSpawnGroupCreatePrerequisites_Init.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "instruction_rules": [
            {
                "regex": r"(?i)^(?:call\s+(?:qword ptr\s+)?\[[^\]]+\+160h\]|mov\s+\w+,\s*\[[^\]]+\+160h\])$",
                "text": "the vtable dispatch at offset 0x160 (call [vtable+160h] or mov reg, [vtable+160h])",
            },
        ],
        "dependency_policy": {
            "CNetworkServerSpawnGroupCreatePrerequisites_Init.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    ("CGameResourceService_AllocGameResourceManifest", "CGameResourceService"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CGameResourceService_AllocGameResourceManifest",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
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
    """Locate the vfunc call in the prerequisite initializer and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

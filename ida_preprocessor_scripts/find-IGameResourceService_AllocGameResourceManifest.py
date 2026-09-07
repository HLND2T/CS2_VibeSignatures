#!/usr/bin/env python3
"""Preprocess script for find-IGameResourceService_AllocGameResourceManifest skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IGameResourceService_AllocGameResourceManifest",
]

FUNC_VTABLE_RELATIONS = [
    # IGameResourceService is an abstract interface; vtable_name is metadata only.
    ("IGameResourceService_AllocGameResourceManifest", "IGameResourceService"),
]

LLM_DECOMPILE = [
    {
        # The client Init preserves the interface vtable-slot evidence in the same
        # hoisted form on both platforms: the slot is fetched from the
        # g_pGameResourceServiceClient vtable (mov reg, [vtable+130h]) and later
        # called with (this, bool, name, bool) manifest-allocation semantics.
        # `found_vcall` reports the slot fetch.
        "symbol_name": "IGameResourceService_AllocGameResourceManifest",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkClientSpawnGroupCreatePrerequisites_Init.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkClientSpawnGroupCreatePrerequisites_Init.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "IGameResourceService_AllocGameResourceManifest",
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
    """Find IGameResourceService::AllocGameResourceManifest from prerequisite initialization."""
    _ = skill_name
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

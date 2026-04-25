#!/usr/bin/env python3
"""Preprocess script for find-IEntityResourceManifestBuilder_BuildResourceManifest_ManifestNameOrGroupName skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IEntityResourceManifestBuilder_BuildResourceManifest_ManifestNameOrGroupName",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "IEntityResourceManifestBuilder_BuildResourceManifest_ManifestNameOrGroupName",
        "prompt/call_llm_decompile.md",
        "references/engine/CGameResourceService_LoadGameResourceManifestGroup.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("IEntityResourceManifestBuilder_BuildResourceManifest_ManifestNameOrGroupName", "IEntityResourceManifestBuilder"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IEntityResourceManifestBuilder_BuildResourceManifest_ManifestNameOrGroupName",
        [
            "func_name",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever vfunc slot; fallback to LLM_DECOMPILE of CGameResourceService_LoadGameResourceManifestGroup."""
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

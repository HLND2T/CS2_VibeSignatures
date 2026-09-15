#!/usr/bin/env python3
"""Find the BuildCompressedManifest interface slot from spawn-group code."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["IGameResourceService_BuildCompressedManifest"]

FUNC_VTABLE_RELATIONS = [
    # IGameResourceService is an abstract interface; this is output metadata.
    ("IGameResourceService_BuildCompressedManifest", "IGameResourceService"),
]

LLM_DECOMPILE = [
    {
        "symbol_name": "IGameResourceService_BuildCompressedManifest",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CBaseSpawnGroup_GetEntityPrerequisites.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CBaseSpawnGroup_GetEntityPrerequisites.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "IGameResourceService_BuildCompressedManifest",
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
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir,
    platform, image_base, llm_config=None, debug=False,
):
    """Locate the interface-vtable call recorded in the annotated predecessor."""
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

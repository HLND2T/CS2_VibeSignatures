#!/usr/bin/env python3
"""Find IGameResourceService::LockGameResourceManifest from its helper call."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["IGameResourceService_LockGameResourceManifest"]

FUNC_VTABLE_RELATIONS = [
    ("IGameResourceService_LockGameResourceManifest", "IGameResourceService"),
]

LLM_DECOMPILE = [
    {
        "symbol_name": "IGameResourceService_LockGameResourceManifest",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerSpawnGroup_AllocatePrerequisite_GetPrerequisiteStatus_Internal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkServerSpawnGroup_AllocatePrerequisite_GetPrerequisiteStatus_Internal.{platform}.yaml": "required",
        },
    }
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "IGameResourceService_LockGameResourceManifest",
        ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
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
    """Locate the annotated interface-vtable call."""
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

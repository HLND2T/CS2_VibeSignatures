#!/usr/bin/env python3
"""Preprocess script for find-IGameResourceService_FreeGameResourceManifest-linux skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["IGameResourceService_FreeGameResourceManifest"]

LLM_DECOMPILE = [
    {
        # On Linux the destructor does not carry the interface evidence: its
        # `call qword ptr [rax+118h]` dispatches through the spawn group's own
        # vtable (CNetworkClientSpawnGroup::Shutdown), not through the resource
        # service.  The real g_pGameResourceServiceClient slot fetch lives in
        # the de-inlined helper reached from the destructor tail, so anchor on
        # that helper instead.  `found_vcall` reports the slot.
        "symbol_name": "IGameResourceService_FreeGameResourceManifest",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkClientSpawnGroup_ReleaseManifest.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkClientSpawnGroup_ReleaseManifest.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [("IGameResourceService_FreeGameResourceManifest", "IGameResourceService")]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "IGameResourceService_FreeGameResourceManifest",
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
    """Locate the abstract resource-service free-manifest vcall on Linux."""
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

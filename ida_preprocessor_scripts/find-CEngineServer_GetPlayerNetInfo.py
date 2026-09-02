#!/usr/bin/env python3
"""Preprocess script for find-CEngineServer_GetPlayerNetInfo skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEngineServer_GetPlayerNetInfo",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CEngineServer_GetPlayerNetInfo",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CPlayerCommandQueue_UpdateStats.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CPlayerCommandQueue_UpdateStats.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # The concrete vfunc body is in engine2.dll; this finder anchors on the
    # CPlayerCommandQueue::UpdateStats call site in server.dll.
    ("CEngineServer_GetPlayerNetInfo", "CEngineServer"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEngineServer_GetPlayerNetInfo",
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
    """Find the engine player's network-info vfunc from command-queue stats."""
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

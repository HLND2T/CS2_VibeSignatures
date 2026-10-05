#!/usr/bin/env python3
"""Preprocess script for find-CNetworkGameServerBase_GetGlobals skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkGameServerBase_GetGlobals",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CNetworkGameServerBase_GetGlobals",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CLoopTypeClientServer_AdvanceTime.{platform}.yaml",
        ],
        # Accept a virtual call when the getter is not inlined and a direct
        # function pointer when the compiler devirtualizes the tiny getter.
        "expected_result_sections": ["found_vcall", "found_funcptr"],
        "dependency_policy": {
            "CLoopTypeClientServer_AdvanceTime.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    ("CNetworkGameServerBase_GetGlobals", "CNetworkGameServerBase"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkGameServerBase_GetGlobals",
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
    """Locate GetGlobals from CLoopTypeClientServer::AdvanceTime."""
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

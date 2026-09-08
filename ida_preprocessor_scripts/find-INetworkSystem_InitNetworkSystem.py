#!/usr/bin/env python3
"""Preprocess script for find-INetworkSystem_InitNetworkSystem skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "INetworkSystem_InitNetworkSystem",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "INetworkSystem_InitNetworkSystem",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/InitSteamLogin.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "InitSteamLogin.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # INetworkSystem is an abstract interface; vtable_name is metadata only.
    ("INetworkSystem_InitNetworkSystem", "INetworkSystem"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "INetworkSystem_InitNetworkSystem",
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
    """Find the INetworkSystem slot from InitSteamLogin (steam login init)."""
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

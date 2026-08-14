#!/usr/bin/env python3
"""Preprocess script for find-CNetworkGameServerBase_CheckTimeouts-decompiles skill."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = [
    "CNetworkGameServerBase_IsHLTV",
    "ISource2Server_ShouldTimeoutClient",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CNetworkGameServerBase_IsHLTV",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkGameServerBase_CheckTimeouts.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkGameServerBase_CheckTimeouts.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "ISource2Server_ShouldTimeoutClient",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkGameServerBase_CheckTimeouts.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkGameServerBase_CheckTimeouts.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CNetworkGameServerBase_IsHLTV", "CNetworkGameServerBase"),
    ("ISource2Server_ShouldTimeoutClient", "ISource2Server"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkGameServerBase_IsHLTV",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "ISource2Server_ShouldTimeoutClient",
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
    """Locate vfunc slots reached by CheckTimeouts via LLM decompile."""
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

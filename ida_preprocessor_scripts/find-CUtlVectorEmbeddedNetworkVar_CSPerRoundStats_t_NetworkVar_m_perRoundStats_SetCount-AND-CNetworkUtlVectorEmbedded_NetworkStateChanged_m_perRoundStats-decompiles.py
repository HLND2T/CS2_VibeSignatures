#!/usr/bin/env python3
"""Preprocess script for find-CUtlVectorEmbeddedNetworkVar_CSPerRoundStats_t_NetworkVar_m_perRoundStats_SetCount-AND-CNetworkUtlVectorEmbedded_NetworkStateChanged_m_perRoundStats-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "EntityInstanceAddChangeAccessorPath",
    "EntityInstanceAssignChangeAccessorPathIds",
]

# 14197 inlined CUtlVectorEmbeddedNetworkVar<CSPerRoundStats_t, NetworkVar>::SetCount into
# CNetworkUtlVectorEmbedded<CSPerRoundStats_t>::NetworkStateChanged_m_perRoundStats on Windows,
# so both platforms now host the EntityInstance* calls in NetworkStateChanged.
LLM_DECOMPILE = [
    {
        "symbol_name": "EntityInstanceAddChangeAccessorPath",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CNetworkUtlVectorEmbedded_NetworkStateChanged_m_perRoundStats.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "CNetworkUtlVectorEmbedded_NetworkStateChanged_m_perRoundStats.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "EntityInstanceAssignChangeAccessorPathIds",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CNetworkUtlVectorEmbedded_NetworkStateChanged_m_perRoundStats.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "CNetworkUtlVectorEmbedded_NetworkStateChanged_m_perRoundStats.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Include func_va/func_rva/func_size since these are downstream predecessors for LLM_DECOMPILE scripts.
    (
        "EntityInstanceAddChangeAccessorPath",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "EntityInstanceAssignChangeAccessorPathIds",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
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
    """Locate EntityInstanceAddChangeAccessorPath and EntityInstanceAssignChangeAccessorPathIds via LLM decompile."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

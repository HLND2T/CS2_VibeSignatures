#!/usr/bin/env python3
"""Preprocess script for find-EntityInstanceAddChangeAccessorPath-AND-EntityInstanceAssignChangeAccessorPathIds skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "EntityInstanceAddChangeAccessorPath",
    "EntityInstanceAssignChangeAccessorPathIds",
]

# Windows: found in CUtlVectorEmbeddedNetworkVar_CSPerRoundStats_t_NetworkVar_m_perRoundStats_SetCount
LLM_DECOMPILE_WINDOWS = [
    (
        "EntityInstanceAddChangeAccessorPath",
        "prompt/call_llm_decompile.md",
        "references/server/CUtlVectorEmbeddedNetworkVar_CSPerRoundStats_t_NetworkVar_m_perRoundStats_SetCount.{platform}.yaml",
    ),
    (
        "EntityInstanceAssignChangeAccessorPathIds",
        "prompt/call_llm_decompile.md",
        "references/server/CUtlVectorEmbeddedNetworkVar_CSPerRoundStats_t_NetworkVar_m_perRoundStats_SetCount.{platform}.yaml",
    ),
]

# Linux: found in CNetworkUtlVectorEmbedded_NetworkStateChanged_m_perRoundStats
LLM_DECOMPILE_LINUX = [
    (
        "EntityInstanceAddChangeAccessorPath",
        "prompt/call_llm_decompile.md",
        "references/server/CNetworkUtlVectorEmbedded_NetworkStateChanged_m_perRoundStats.{platform}.yaml",
    ),
    (
        "EntityInstanceAssignChangeAccessorPathIds",
        "prompt/call_llm_decompile.md",
        "references/server/CNetworkUtlVectorEmbedded_NetworkStateChanged_m_perRoundStats.{platform}.yaml",
    ),
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
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Locate EntityInstanceAddChangeAccessorPath and EntityInstanceAssignChangeAccessorPathIds via LLM decompile."""
    llm_decompile = LLM_DECOMPILE_WINDOWS if platform == "windows" else LLM_DECOMPILE_LINUX
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=llm_decompile,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Preprocess script for find-CNetworkMessages_FindNetworkGroup skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkMessages_FindNetworkGroup",
]

LLM_DECOMPILE = [
    (
        "CNetworkMessages_FindNetworkGroup",
        "prompt/call_llm_decompile.md",
        "references/CNetworkMessages_FindNetworkGroup.from-CNetworkGameClient_RecordEntityBandwidth.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    ("CNetworkMessages_FindNetworkGroup", "CNetworkMessages", True),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
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
        debug=debug,
    )

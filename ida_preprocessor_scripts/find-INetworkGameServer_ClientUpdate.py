#!/usr/bin/env python3
"""Preprocess script for find-INetworkGameServer_ClientUpdate skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "INetworkGameServer_ClientUpdate",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "INetworkGameServer_ClientUpdate",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkServerService_OnServerPostAdvanceTick.{platform}.yaml",
    ),
]

# INetworkGameServer is an abstract interface -- no vtable YAML needed; vtable_name is metadata only
FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("INetworkGameServer_ClientUpdate", "INetworkGameServer"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "INetworkGameServer_ClientUpdate",
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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Preprocess script for find-INetworkGameServer_PreWorldUpdate skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "INetworkGameServer_PreWorldUpdate",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "INetworkGameServer_PreWorldUpdate",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerService_OnServerPostAdvanceTick.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkServerService_OnServerPostAdvanceTick.{platform}.yaml": "required",
        },
    },
]

# INetworkGameServer is an abstract interface -- no vtable YAML needed; vtable_name is metadata only
FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("INetworkGameServer_PreWorldUpdate", "INetworkGameServer"),
]

# Artifact keys stay stable; emitted names reflect the verified SDK semantics.
OUTPUT_NAME_MAP = {
    "INetworkGameServer_PreWorldUpdate": "INetworkGameServer_PrepareSendClientUpdatesMainThread",
}

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "INetworkGameServer_PreWorldUpdate",
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
        output_name_map=OUTPUT_NAME_MAP,
    )

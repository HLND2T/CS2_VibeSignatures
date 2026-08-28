#!/usr/bin/env python3
"""Preprocess script for find-CNetworkGameServer_SpawnServer-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "INetworkGameServer_GetMaxClients",
    "CNetworkGameServerBase_GetMaxClients",
    "CEngineServiceMgr_GetAddonsString",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "INetworkGameServer_GetMaxClients",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkGameServer_SpawnServer.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkGameServer_SpawnServer.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkGameServerBase_GetMaxClients",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkGameServer_SpawnServer.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkGameServer_SpawnServer.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEngineServiceMgr_GetAddonsString",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkGameServer_SpawnServer.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkGameServer_SpawnServer.{platform}.yaml": "required",
        },
    },
]

# INetworkGameServer is an abstract interface -- no vtable YAML needed; vtable_name is metadata only
FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("INetworkGameServer_GetMaxClients", "INetworkGameServer"),
    ("CNetworkGameServerBase_GetMaxClients", "CNetworkGameServerBase"),
    ("CEngineServiceMgr_GetAddonsString", "CEngineServiceMgr"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "INetworkGameServer_GetMaxClients",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "CNetworkGameServerBase_GetMaxClients",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "CEngineServiceMgr_GetAddonsString",
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
    """Locate INetworkGameServer_GetMaxClients from CNetworkGameServer_SpawnServer."""
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

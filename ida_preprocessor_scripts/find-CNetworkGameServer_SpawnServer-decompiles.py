#!/usr/bin/env python3
"""Preprocess script for find-CNetworkGameServer_SpawnServer-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "INetworkGameServer_GetMaxClients",
    "IEngineServiceMgr_GetAddonsString",
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
        "symbol_name": "IEngineServiceMgr_GetAddonsString",
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
    ("IEngineServiceMgr_GetAddonsString", "IEngineServiceMgr"),
]

INHERIT_VFUNCS = [
    (
        "CNetworkGameServerBase_GetMaxClients",
        "CNetworkGameServerBase",
        "INetworkGameServer_GetMaxClients",
        False,
    ),
]

INTERFACE_VFUNC_DESIRED_FIELDS = [
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
        "IEngineServiceMgr_GetAddonsString",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
]

INHERIT_VFUNC_DESIRED_FIELDS = [
    (
        "CNetworkGameServerBase_GetMaxClients",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
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
    """Locate SpawnServer interface calls and its GetMaxClients override."""
    found_interface_vfuncs = await preprocess_common_skill(
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
        generate_yaml_desired_fields=INTERFACE_VFUNC_DESIRED_FIELDS,
        debug=debug,
    )
    if not found_interface_vfuncs:
        return False

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        generate_yaml_desired_fields=INHERIT_VFUNC_DESIRED_FIELDS,
        debug=debug,
    )

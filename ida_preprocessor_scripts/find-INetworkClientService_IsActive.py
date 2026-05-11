#!/usr/bin/env python3
"""Preprocess script for find-INetworkClientService_IsActive skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "INetworkClientService_IsActive",
]

# Windows: found in CNetworkGameServerBase_ServerSimulate (the vfunc itself)
LLM_DECOMPILE_WINDOWS = [
    (
        "INetworkClientService_IsActive",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkGameServerBase_ServerSimulate.{platform}.yaml",
    ),
]

# Linux: found in CNetworkGameServerBase_ServerSimulateInternal (internal helper)
LLM_DECOMPILE_LINUX = [
    (
        "INetworkClientService_IsActive",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkGameServerBase_ServerSimulateInternal.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("INetworkClientService_IsActive", "INetworkClientService"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Slim Pattern C: INetworkClientService_IsActive is not a downstream predecessor.
    (
        "INetworkClientService_IsActive",
        [
            "func_name",
            "vfunc_sig",    # REQUIRED for Pattern C
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
    """Locate INetworkClientService_IsActive vfunc via LLM decompile of predecessor."""
    llm_decompile = LLM_DECOMPILE_WINDOWS if platform == "windows" else LLM_DECOMPILE_LINUX
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=llm_decompile,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

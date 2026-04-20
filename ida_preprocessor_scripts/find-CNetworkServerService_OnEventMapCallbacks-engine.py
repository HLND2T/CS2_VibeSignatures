#!/usr/bin/env python3
"""Preprocess script for find-CNetworkServerService_OnEventMapCallbacks-engine skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkServerService_OnServerAdvanceTick",
    "CNetworkServerService_OnServerPollNetworking",
    "CNetworkServerService_OnServerProcessNetworking",
    "CNetworkServerService_OnServerBeginSimulate",
    "CNetworkServerService_OnServerPostSimulate",
    "CNetworkServerService_OnServerPostAdvanceTick",
    "CNetworkServerService_OnFrameBoundary",
    "CNetworkServerService_OnClientPollNetworking",
    "CNetworkServerService_OnSimpleLoopFrameUpdate",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CNetworkServerService_OnServerAdvanceTick",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
    ),
    (
        "CNetworkServerService_OnServerPollNetworking",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
    ),
    (
        "CNetworkServerService_OnServerProcessNetworking",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
    ),
    (
        "CNetworkServerService_OnServerBeginSimulate",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
    ),
    (
        "CNetworkServerService_OnServerPostSimulate",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
    ),
    (
        "CNetworkServerService_OnServerPostAdvanceTick",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
    ),
    (
        "CNetworkServerService_OnFrameBoundary",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
    ),
    (
        "CNetworkServerService_OnClientPollNetworking",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
    ),
    (
        "CNetworkServerService_OnSimpleLoopFrameUpdate",
        "prompt/call_llm_decompile.md",
        "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CNetworkServerService_OnServerAdvanceTick",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CNetworkServerService_OnServerPollNetworking",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CNetworkServerService_OnServerProcessNetworking",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CNetworkServerService_OnServerBeginSimulate",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CNetworkServerService_OnServerPostSimulate",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CNetworkServerService_OnServerPostAdvanceTick",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CNetworkServerService_OnFrameBoundary",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CNetworkServerService_OnClientPollNetworking",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CNetworkServerService_OnSimpleLoopFrameUpdate",
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
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
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

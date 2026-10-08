#!/usr/bin/env python3
"""Preprocess script for find-CNetworkServerService_OnEventMapCallbacks-engine skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkServerService_OnServerAdvanceTick",
    "CNetworkServerService_OnServerPollNetworking",
    "CNetworkServerService_OnServerProcessNetworking",
    "CNetworkServerService_OnServerBeginSimulate",
    "CNetworkServerService_OnServerEndSimulate",
    "CNetworkServerService_OnServerPostSimulate",
    "CNetworkServerService_OnServerPostAdvanceTick",
    "CNetworkServerService_OnFrameBoundary",
    "CNetworkServerService_OnClientPollNetworking",
    "CNetworkServerService_OnSimpleLoopFrameUpdate",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CNetworkServerService_OnServerAdvanceTick",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {
            "CNetworkServerService_RegisterEventMapInternal.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_OnServerPollNetworking",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {
            "CNetworkServerService_RegisterEventMapInternal.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_OnServerProcessNetworking",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {
            "CNetworkServerService_RegisterEventMapInternal.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_OnServerBeginSimulate",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {
            "CNetworkServerService_RegisterEventMapInternal.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_OnServerEndSimulate",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {
            "CNetworkServerService_RegisterEventMapInternal.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_OnServerPostSimulate",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {
            "CNetworkServerService_RegisterEventMapInternal.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_OnServerPostAdvanceTick",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {
            "CNetworkServerService_RegisterEventMapInternal.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_OnFrameBoundary",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {
            "CNetworkServerService_RegisterEventMapInternal.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_OnClientPollNetworking",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {
            "CNetworkServerService_RegisterEventMapInternal.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_OnSimpleLoopFrameUpdate",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkServerService_RegisterEventMapInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {
            "CNetworkServerService_RegisterEventMapInternal.{platform}.yaml": "required",
        },
    },
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
        "CNetworkServerService_OnServerEndSimulate",
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
        # The vtable slot resolves to a single-instruction jmp thunk, so no
        # func_sig is emitted (see _classify_func_body_lead_bytes).
        "CNetworkServerService_OnClientPollNetworking",
        [
            "func_name",
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
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

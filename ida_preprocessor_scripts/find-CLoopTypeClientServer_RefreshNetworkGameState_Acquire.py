#!/usr/bin/env python3
"""Resolve the optional de-inlined acquire helper called by RefreshNetworkGameState.

On inlined builds (Windows) the client/server service re-query and the
INetworkGameServer::AddRef call live directly in RefreshNetworkGameState, so no
helper exists and this producer legitimately yields nothing. On de-inlined
builds (Linux) the helper holds the AddRef vcall; this optional producer
supplies the predecessor for find-CLoopTypeClientServer_RefreshNetworkGameState-decompiles.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CLoopTypeClientServer_RefreshNetworkGameState_Acquire"]
LLM_DECOMPILE = [
    {
        "symbol_name": "CLoopTypeClientServer_RefreshNetworkGameState_Acquire",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/engine/CLoopTypeClientServer_RefreshNetworkGameState.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CLoopTypeClientServer_RefreshNetworkGameState.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CLoopTypeClientServer_RefreshNetworkGameState_Acquire",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
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

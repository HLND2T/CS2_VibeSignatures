#!/usr/bin/env python3
"""Preprocess script for find-CGameEventManager_Shutdown-AND-CLoopModeRegistry_UnregisterLoopModes-AND-CEngineServiceRegistry_UnregisterEngineServices skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameEventManager_Shutdown",
    "CLoopModeRegistry_UnregisterLoopModes",
    "CEngineServiceRegistry_UnregisterEngineServices",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CGameEventManager_Shutdown",
        "prompt/call_llm_decompile.md",
        "references/server/CSource2Server_Shutdown.{platform}.yaml",
    ),
    (
        "CLoopModeRegistry_UnregisterLoopModes",
        "prompt/call_llm_decompile.md",
        "references/server/CSource2Server_Shutdown.{platform}.yaml",
    ),
    (
        "CEngineServiceRegistry_UnregisterEngineServices",
        "prompt/call_llm_decompile.md",
        "references/server/CSource2Server_Shutdown.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CGameEventManager_Shutdown",
        [
            "func_name",
            "func_sig",
            "func_sig_allow_across_function_boundary:true",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CLoopModeRegistry_UnregisterLoopModes",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CEngineServiceRegistry_UnregisterEngineServices",
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

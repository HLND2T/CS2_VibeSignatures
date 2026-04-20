#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_DestroyAllGameSystems-AND-IGameSystem_LoopDestroyAllSystems-AND-IGameSystem_LoopPreShutdownAllSystems skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IGameSystem_DestroyAllGameSystems",
    "IGameSystem_LoopDestroyAllSystems",
    "IGameSystem_LoopPreShutdownAllSystems",
]

LLM_DECOMPILE_WINDOWS = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "IGameSystem_DestroyAllGameSystems",
        "prompt/call_llm_decompile.md",
        "references/client/CLoopModeGame_LoopShutdown.{platform}.yaml",
    ),
    (
        "IGameSystem_LoopDestroyAllSystems",
        "prompt/call_llm_decompile.md",
        "references/client/CLoopModeGame_LoopShutdown.{platform}.yaml",
    ),
    (
        "IGameSystem_LoopPreShutdownAllSystems",
        "prompt/call_llm_decompile.md",
        "references/client/CLoopModeGame_LoopShutdown.{platform}.yaml",
    ),
]

LLM_DECOMPILE_LINUX = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "IGameSystem_DestroyAllGameSystems",
        "prompt/call_llm_decompile.md",
        "references/client/CLoopModeGame_Shutdown.{platform}.yaml",
    ),
    (
        "IGameSystem_LoopDestroyAllSystems",
        "prompt/call_llm_decompile.md",
        "references/client/CLoopModeGame_Shutdown.{platform}.yaml",
    ),
    (
        "IGameSystem_LoopPreShutdownAllSystems",
        "prompt/call_llm_decompile.md",
        "references/client/CLoopModeGame_Shutdown.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IGameSystem_DestroyAllGameSystems",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "IGameSystem_LoopDestroyAllSystems",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "IGameSystem_LoopPreShutdownAllSystems",
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
    """Reuse previous gamever func_sig to locate targets and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=LLM_DECOMPILE_WINDOWS if platform == "windows" else LLM_DECOMPILE_LINUX,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

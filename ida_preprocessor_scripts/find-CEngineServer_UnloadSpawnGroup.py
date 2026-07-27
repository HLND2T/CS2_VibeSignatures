#!/usr/bin/env python3
"""Preprocess script for find-CEngineServer_UnloadSpawnGroup skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEngineServer_UnloadSpawnGroup",
]

# The vcall to CEngineServer::UnloadSpawnGroup lives in a different predecessor
# per platform: on Windows CLoopModeGame_LoopInitInternal is inlined into
# CLoopModeGame_LoopInit, so the vcall is in LoopInit; on Linux LoopInit is a
# thin wrapper that tail-calls the separate CLoopModeGame_LoopInitInternal where
# the vcall actually resides. The reference func_name drives which function is
# decompiled in the new binary, so each platform points at its own predecessor.
LLM_DECOMPILE_WINDOWS = [
    {
        "symbol_name": "CEngineServer_UnloadSpawnGroup",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CLoopModeGame_LoopInit.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopModeGame_LoopInit.{platform}.yaml": "required",
        },
    },
]

LLM_DECOMPILE_LINUX = [
    {
        "symbol_name": "CEngineServer_UnloadSpawnGroup",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CLoopModeGame_LoopInitInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopModeGame_LoopInitInternal.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class) -- vtable_name is metadata only; CEngineServer's
    # concrete body lives in engine2.dll, so no CEngineServer_vtable YAML is
    # consumed here. The vfunc_sig anchors on the vcall instruction inside
    # CLoopModeGame_LoopInit (server), matching the IGameTypes offset pattern.
    ("CEngineServer_UnloadSpawnGroup", "CEngineServer"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Slim Pattern C: not a downstream predecessor, so func_va/rva/size omitted.
    # vfunc_sig is MANDATORY for Pattern C.
    (
        "CEngineServer_UnloadSpawnGroup",
        [
            "func_name",
            "vfunc_sig",
            # Linux CLoopModeGame_LoopInitInternal calls this vfunc from two
            # sites (0x1724CCD and 0x1724D0E), so the caller-anchored vfunc_sig
            # matches 2 locations; allow up to 2 (Windows has 1 site <= 2).
            "vfunc_sig_max_match:2",
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
    """Reuse previous gamever vfunc_sig to locate target; fallback to LLM_DECOMPILE of the platform's LoopInit predecessor."""
    _ = skill_name
    llm_decompile_specs = (
        LLM_DECOMPILE_LINUX if platform == "linux" else LLM_DECOMPILE_WINDOWS
    )
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=llm_decompile_specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

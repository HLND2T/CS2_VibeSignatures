#!/usr/bin/env python3
"""Preprocess script for find-CLoopModeGame_LoopInit-decompiles skill.

Finds three CNetworkServerService virtual functions that are invoked on the
``g_pNetworkServerService`` instance from inside CLoopModeGame::LoopInit:

  * CNetworkServerService_SetGameSpawnGroupMgr
  * CNetworkServerService_AddServerPrerequisites
  * CNetworkServerService_SetFinalSimulationTickThisFrame

They are discovered via LLM_DECOMPILE of the CLoopModeGame::LoopInit predecessor.
The vcall to each lives in a different predecessor per platform: on Windows
CLoopModeGame::LoopInitInternal is inlined into CLoopModeGame::LoopInit, so the
vcalls are in LoopInit; on Linux LoopInit is a thin wrapper that tail-calls the
separate CLoopModeGame::LoopInitInternal where the vcalls actually reside. The
reference func_name drives which function is decompiled in the new binary, so
each platform points at its own predecessor (mirrors find-CEngineServer_UnloadSpawnGroup).

CNetworkServerService's concrete body lives in engine2.dll, so no
CNetworkServerService_vtable YAML is consumed here -- ``vtable_name`` is metadata
only. The vfunc_sig anchors on the vcall instruction inside the server
predecessor, matching the CEngineServer::UnloadSpawnGroup / IGameTypes offset
pattern. Slim Pattern C: not a downstream predecessor, so func_va/rva/size are
omitted; vfunc_sig is mandatory for Pattern C.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkServerService_SetGameSpawnGroupMgr",
    "CNetworkServerService_AddServerPrerequisites",
    "CNetworkServerService_SetFinalSimulationTickThisFrame",
]

LLM_DECOMPILE_WINDOWS = [
    {
        "symbol_name": "CNetworkServerService_SetGameSpawnGroupMgr",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CLoopModeGame_LoopInit.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopModeGame_LoopInit.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_AddServerPrerequisites",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CLoopModeGame_LoopInit.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopModeGame_LoopInit.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_SetFinalSimulationTickThisFrame",
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
        "symbol_name": "CNetworkServerService_SetGameSpawnGroupMgr",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CLoopModeGame_LoopInitInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopModeGame_LoopInitInternal.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_AddServerPrerequisites",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CLoopModeGame_LoopInitInternal.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopModeGame_LoopInitInternal.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkServerService_SetFinalSimulationTickThisFrame",
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
    # (func_name, vtable_class) -- vtable_name is metadata only; the
    # CNetworkServerService body lives in engine2.dll, so no
    # CNetworkServerService_vtable YAML is consumed here.
    ("CNetworkServerService_SetGameSpawnGroupMgr", "CNetworkServerService_vtable"),
    ("CNetworkServerService_AddServerPrerequisites", "CNetworkServerService_vtable"),
    ("CNetworkServerService_SetFinalSimulationTickThisFrame", "CNetworkServerService_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Slim Pattern C: not a downstream predecessor, so func_va/rva/size omitted.
    # vfunc_sig is MANDATORY for Pattern C. Each vfunc is called exactly once in
    # the predecessor with distinct forward context, so the caller-anchored
    # vfunc_sig is unique (default max_match).
    (
        "CNetworkServerService_SetGameSpawnGroupMgr",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "CNetworkServerService_AddServerPrerequisites",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "CNetworkServerService_SetFinalSimulationTickThisFrame",
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
    """Reuse previous gamever vfunc_sig to locate targets; fallback to LLM_DECOMPILE of the platform's LoopInit predecessor."""
    _ = skill_name
    llm_decompile_specs = LLM_DECOMPILE_LINUX if platform == "linux" else LLM_DECOMPILE_WINDOWS
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

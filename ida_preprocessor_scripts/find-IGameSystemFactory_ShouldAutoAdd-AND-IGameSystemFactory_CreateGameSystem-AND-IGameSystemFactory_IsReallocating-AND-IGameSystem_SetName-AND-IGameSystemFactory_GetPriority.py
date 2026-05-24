#!/usr/bin/env python3
"""Preprocess script for find-IGameSystemFactory_ShouldAutoAdd-AND-IGameSystemFactory_CreateGameSystem-AND-IGameSystemFactory_IsReallocating-AND-IGameSystem_SetName-AND-IGameSystemFactory_GetPriority skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IGameSystemFactory_ShouldAutoAdd",
    "IGameSystemFactory_CreateGameSystem",
    "IGameSystemFactory_IsReallocating",
    "IGameSystem_SetName",
    "IGameSystemFactory_GetPriority",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    # All five vfunc offsets found by decompiling IGameSystem_LoopInitAllSystems:
    #   IGameSystemFactory_ShouldAutoAdd    = virtual call through IGameSystemFactory vtable, boolean gate before adding
    #   IGameSystemFactory_CreateGameSystem = virtual call through IGameSystemFactory vtable (*v), allocates a new game system
    #   IGameSystemFactory_IsReallocating   = virtual call through IGameSystemFactory vtable (*v), boolean check
    #   IGameSystem_SetName                 = conditional virtual call through IGameSystem vtable (allocated instance)
    #   IGameSystemFactory_GetPriority      = virtual call through IGameSystemFactory vtable, returns priority int
    (
        "IGameSystemFactory_ShouldAutoAdd",
        "prompt/call_llm_decompile.md",
        "references/client/IGameSystem_LoopInitAllSystems.{platform}.yaml",
    ),
    (
        "IGameSystemFactory_CreateGameSystem",
        "prompt/call_llm_decompile.md",
        "references/client/IGameSystem_LoopInitAllSystems.{platform}.yaml",
    ),
    (
        "IGameSystemFactory_IsReallocating",
        "prompt/call_llm_decompile.md",
        "references/client/IGameSystem_LoopInitAllSystems.{platform}.yaml",
    ),
    (
        "IGameSystem_SetName",
        "prompt/call_llm_decompile.md",
        "references/client/IGameSystem_LoopInitAllSystems.{platform}.yaml",
    ),
    (
        "IGameSystemFactory_GetPriority",
        "prompt/call_llm_decompile.md",
        "references/client/IGameSystem_LoopInitAllSystems.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("IGameSystemFactory_ShouldAutoAdd", "IGameSystemFactory"),
    ("IGameSystemFactory_CreateGameSystem", "IGameSystemFactory"),
    ("IGameSystemFactory_IsReallocating", "IGameSystemFactory"),
    ("IGameSystem_SetName", "IGameSystem"),
    ("IGameSystemFactory_GetPriority", "IGameSystemFactory"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IGameSystemFactory_ShouldAutoAdd",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "IGameSystemFactory_CreateGameSystem",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "IGameSystemFactory_IsReallocating",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_sig_max_match:2",  # Called from both IGameSystem_LoopInitAllSystems and IGameSystem_Add, so signature matches 2 call sites
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "IGameSystem_SetName",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_sig_max_match:2",  # Signature at offset 0x1D8 matches multiple call sites
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "IGameSystemFactory_GetPriority",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_sig_max_match:2",
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
    """Reuse previous gamever vfunc_sig to locate target function(s); fallback to LLM_DECOMPILE of IGameSystem_LoopInitAllSystems."""
    _ = skill_name
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

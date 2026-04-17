#!/usr/bin/env python3
"""Preprocess script for find-IGameSystemFactory_Allocate-AND-IGameSystemFactory_HasName-AND-IGameSystem_SetName skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IGameSystemFactory_Allocate",
    "IGameSystemFactory_HasName",
    "IGameSystem_SetName",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    # All three vfunc offsets found by decompiling IGameSystem_AddByName:
    #   IGameSystemFactory_Allocate = first virtual call through IGameSystemFactory vtable (*v2), allocates a new game system
    #   IGameSystemFactory_HasName  = second virtual call through IGameSystemFactory vtable (*v2), boolean check
    #   IGameSystem_SetName         = conditional virtual call through IGameSystem vtable (v7 = allocated instance)
    (
        "IGameSystemFactory_Allocate",
        "prompt/call_llm_decompile.md",
        "references/client/IGameSystem_AddByName.{platform}.yaml",
    ),
    (
        "IGameSystemFactory_HasName",
        "prompt/call_llm_decompile.md",
        "references/client/IGameSystem_AddByName.{platform}.yaml",
    ),
    (
        "IGameSystem_SetName",
        "prompt/call_llm_decompile.md",
        "references/client/IGameSystem_AddByName.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("IGameSystemFactory_Allocate", "IGameSystemFactory"),
    ("IGameSystemFactory_HasName", "IGameSystemFactory"),
    ("IGameSystem_SetName", "IGameSystem"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IGameSystemFactory_Allocate",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "IGameSystemFactory_HasName",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_sig_max_match:2",  # Called from both IGameSystem_AddByName and IGameSystem_Add, so signature matches 2 call sites
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
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever vfunc_sig to locate target function(s); fallback to LLM_DECOMPILE of IGameSystem_AddByName."""
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

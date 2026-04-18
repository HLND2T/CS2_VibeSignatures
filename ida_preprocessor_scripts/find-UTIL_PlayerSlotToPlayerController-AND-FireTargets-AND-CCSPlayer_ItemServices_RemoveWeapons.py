#!/usr/bin/env python3
"""Preprocess script for find-UTIL_PlayerSlotToPlayerController-AND-FireTargets-AND-CCSPlayer_ItemServices_RemoveWeapons skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "UTIL_PlayerSlotToPlayerController",
    "FireTargets",
    "CCSPlayer_ItemServices_RemoveWeapons",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "UTIL_PlayerSlotToPlayerController",
        "prompt/call_llm_decompile.md",
        "references/server/CMultiplayRules_ClientDisconnected.{platform}.yaml",
    ),
    (
        "FireTargets",
        "prompt/call_llm_decompile.md",
        "references/server/CMultiplayRules_ClientDisconnected.{platform}.yaml",
    ),
    (
        "CCSPlayer_ItemServices_RemoveWeapons",
        "prompt/call_llm_decompile.md",
        "references/server/CMultiplayRules_ClientDisconnected.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CCSPlayer_ItemServices_RemoveWeapons", "CCSPlayer_ItemServices"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "UTIL_PlayerSlotToPlayerController",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "FireTargets",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CCSPlayer_ItemServices_RemoveWeapons",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
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
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

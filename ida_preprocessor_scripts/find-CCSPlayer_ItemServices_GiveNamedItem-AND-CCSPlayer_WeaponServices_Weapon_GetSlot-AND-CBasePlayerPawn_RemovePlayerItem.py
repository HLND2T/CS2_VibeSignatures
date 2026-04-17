#!/usr/bin/env python3
"""Preprocess script for find-CCSPlayer_ItemServices_GiveNamedItem-AND-CCSPlayer_WeaponServices_Weapon_GetSlot-AND-CBasePlayerPawn_RemovePlayerItem skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CCSPlayer_ItemServices_GiveNamedItem",
    "CCSPlayer_WeaponServices_Weapon_GetSlot",
    "CBasePlayerPawn_RemovePlayerItem",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CCSPlayer_ItemServices_GiveNamedItem",
        "prompt/call_llm_decompile.md",
        "references/server/CCSPlayer_ItemServices_GiveDefaultItems.{platform}.yaml",
    ),
    (
        "CCSPlayer_WeaponServices_Weapon_GetSlot",
        "prompt/call_llm_decompile.md",
        "references/server/CCSPlayer_ItemServices_GiveDefaultItems.{platform}.yaml",
    ),
    (
        "CBasePlayerPawn_RemovePlayerItem",
        "prompt/call_llm_decompile.md",
        "references/server/CCSPlayer_ItemServices_GiveDefaultItems.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CCSPlayer_ItemServices_GiveNamedItem", "CCSPlayer_ItemServices"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CCSPlayer_ItemServices_GiveNamedItem",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "CCSPlayer_WeaponServices_Weapon_GetSlot",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CBasePlayerPawn_RemovePlayerItem",
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

    """Reuse previous gamever func_sig/vfunc_sig to locate target function(s) and write YAML."""
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

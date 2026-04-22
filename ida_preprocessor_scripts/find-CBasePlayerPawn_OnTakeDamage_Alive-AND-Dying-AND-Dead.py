#!/usr/bin/env python3
"""Preprocess script for find-CBaseEntity_OnTakeDamage_Alive-AND-Dying-AND-Dead skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CBasePlayerPawn_OnTakeDamage_Alive",
    "CBasePlayerPawn_OnTakeDamage_Dying",
    "CBasePlayerPawn_OnTakeDamage_Dead",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CBasePlayerPawn_OnTakeDamage_Alive",
        "prompt/call_llm_decompile.md",
        "references/server/CBasePlayerPawn_OnTakeDamage.{platform}.yaml",
    ),
    (
        "CBasePlayerPawn_OnTakeDamage_Dying",
        "prompt/call_llm_decompile.md",
        "references/server/CBasePlayerPawn_OnTakeDamage.{platform}.yaml",
    ),
    (
        "CBasePlayerPawn_OnTakeDamage_Dead",
        "prompt/call_llm_decompile.md",
        "references/server/CBasePlayerPawn_OnTakeDamage.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CBasePlayerPawn_OnTakeDamage_Alive", "CBasePlayerPawn"),
    ("CBasePlayerPawn_OnTakeDamage_Dying", "CBasePlayerPawn"),
    ("CBasePlayerPawn_OnTakeDamage_Dead", "CBasePlayerPawn"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CBasePlayerPawn_OnTakeDamage_Alive",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
            "vfunc_sig_allow_across_function_boundary:true",
        ],
    ),
    (
        "CBasePlayerPawn_OnTakeDamage_Dying",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
            "vfunc_sig_allow_across_function_boundary:true",
        ],
    ),
    (
        "CBasePlayerPawn_OnTakeDamage_Dead",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
            "vfunc_sig_allow_across_function_boundary:true",
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

#!/usr/bin/env python3
"""Preprocess script for find-IVPhys2World_GetTouchingList-AND-CBaseEntity_PhysicsDispatchStartTouch-AND-CBaseEntity_PhysicsNotifyOtherOfEndTouch-AND-CBaseEntity_PhysicsDispatchTouch skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IVPhys2World_GetTouchingList",
    "CBaseEntity_PhysicsDispatchStartTouch",
    "CBaseEntity_PhysicsNotifyOtherOfEndTouch",
    "CBaseEntity_PhysicsDispatchTouch",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "IVPhys2World_GetTouchingList",
        "prompt/call_llm_decompile.md",
        "references/server/CPhysicsGameSystem_ProcessContactEvents.{platform}.yaml",
    ),
    (
        "CBaseEntity_PhysicsDispatchStartTouch",
        "prompt/call_llm_decompile.md",
        "references/server/CPhysicsGameSystem_ProcessContactEvents.{platform}.yaml",
    ),
    (
        "CBaseEntity_PhysicsNotifyOtherOfEndTouch",
        "prompt/call_llm_decompile.md",
        "references/server/CPhysicsGameSystem_ProcessContactEvents.{platform}.yaml",
    ),
    (
        "CBaseEntity_PhysicsDispatchTouch",
        "prompt/call_llm_decompile.md",
        "references/server/CPhysicsGameSystem_ProcessContactEvents.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("IVPhys2World_GetTouchingList", "CVPhys2World"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IVPhys2World_GetTouchingList",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "CBaseEntity_PhysicsDispatchStartTouch",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CBaseEntity_PhysicsNotifyOtherOfEndTouch",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CBaseEntity_PhysicsDispatchTouch",
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
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

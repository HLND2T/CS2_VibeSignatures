#!/usr/bin/env python3
"""Preprocess script for find-PolymorphicHelper_t__SetPolymorphicPointer-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntityInstance_AddChangeAccessorPathPolymorphic",
    "CEntityInstance_AssignChangeAccessorPathIdsPolymorphic",
    "CEntityInstance_GetChangeAccessorPathInfo_1",
]

LLM_DECOMPILE = [
    (
        "CEntityInstance_AddChangeAccessorPathPolymorphic",
        "prompt/call_llm_decompile.md",
        "references/server/PolymorphicHelper_t__SetPolymorphicPointer.{platform}.yaml",
    ),
    (
        "CEntityInstance_AssignChangeAccessorPathIdsPolymorphic",
        "prompt/call_llm_decompile.md",
        "references/server/PolymorphicHelper_t__SetPolymorphicPointer.{platform}.yaml",
    ),
    (
        "CEntityInstance_GetChangeAccessorPathInfo_1",
        "prompt/call_llm_decompile.md",
        "references/server/PolymorphicHelper_t__SetPolymorphicPointer.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    ("CEntityInstance_AddChangeAccessorPathPolymorphic", "CEntityInstance"),
    ("CEntityInstance_AssignChangeAccessorPathIdsPolymorphic", "CEntityInstance"),
    ("CEntityInstance_GetChangeAccessorPathInfo_1", "CEntityInstance"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEntityInstance_AddChangeAccessorPathPolymorphic",
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
        "CEntityInstance_AssignChangeAccessorPathIdsPolymorphic",
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
        "CEntityInstance_GetChangeAccessorPathInfo_1",
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
    """Locate CEntityInstance Polymorphic vfuncs via LLM decompile of PolymorphicHelper_t__SetPolymorphicPointer."""
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

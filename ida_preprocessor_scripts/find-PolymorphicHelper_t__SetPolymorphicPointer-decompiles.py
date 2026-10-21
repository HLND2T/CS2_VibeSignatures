#!/usr/bin/env python3
"""Preprocess script for find-PolymorphicHelper_t__SetPolymorphicPointer-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntityInstance_AddChangeAccessorPathPolymorphic",
    "CEntityInstance_AssignChangeAccessorPathIdsPolymorphic",
    "CEntityInstance_GetChangeAccessorPathInfo_2",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CEntityInstance_AddChangeAccessorPathPolymorphic",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/PolymorphicHelper_t__SetPolymorphicPointer.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "PolymorphicHelper_t__SetPolymorphicPointer.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntityInstance_AssignChangeAccessorPathIdsPolymorphic",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/PolymorphicHelper_t__SetPolymorphicPointer.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "PolymorphicHelper_t__SetPolymorphicPointer.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntityInstance_GetChangeAccessorPathInfo_2",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/PolymorphicHelper_t__SetPolymorphicPointer.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "PolymorphicHelper_t__SetPolymorphicPointer.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    ("CEntityInstance_AddChangeAccessorPathPolymorphic", "CEntityInstance"),
    ("CEntityInstance_AssignChangeAccessorPathIdsPolymorphic", "CEntityInstance"),
    ("CEntityInstance_GetChangeAccessorPathInfo_2", "CEntityInstance"),
]

# Artifact keys stay stable; emitted names reflect the verified SDK semantics.
OUTPUT_NAME_MAP = {
    "CEntityInstance_AddChangeAccessorPathPolymorphic": "CEntityInstance_NetworkStateChangedBranch",
    "CEntityInstance_AssignChangeAccessorPathIdsPolymorphic": "CEntityInstance_NetworkStateChangedRemove",
}

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
        "CEntityInstance_GetChangeAccessorPathInfo_2",
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
        output_name_map=OUTPUT_NAME_MAP,
    )

#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_DestroyEntityImmediate-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_OnRemoveEntityFromDatabase",
    "CEntitySystem_DoDestructEntity",
    "CEntitySystem_UpdateOnRemove",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "CEntitySystem_m_nSuppressDestroyImmediateCount",
    "CEntitySystem_m_nSuppressAutoDeletionExecutionCount",
    "CEntitySystem_m_bEnableAutoDeletionExecution",
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CEntitySystem_UpdateOnRemove", "CEntitySystem"),
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CEntitySystem_OnRemoveEntityFromDatabase",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_DestroyEntityImmediate.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "CEntitySystem_DestroyEntityImmediate.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_DoDestructEntity",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_DestroyEntityImmediate.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "CEntitySystem_DestroyEntityImmediate.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_UpdateOnRemove",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_DestroyEntityImmediate.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CEntitySystem_DestroyEntityImmediate.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_m_nSuppressDestroyImmediateCount",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_DestroyEntityImmediate.{platform}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "CEntitySystem_DestroyEntityImmediate.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_m_nSuppressAutoDeletionExecutionCount",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_DestroyEntityImmediate.{platform}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "CEntitySystem_DestroyEntityImmediate.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_m_bEnableAutoDeletionExecution",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_DestroyEntityImmediate.{platform}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "CEntitySystem_DestroyEntityImmediate.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEntitySystem_OnRemoveEntityFromDatabase",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CEntitySystem_DoDestructEntity",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CEntitySystem_UpdateOnRemove",
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
        "CEntitySystem_m_nSuppressDestroyImmediateCount",
        [
            "struct_name",
            "member_name",
            "offset",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "CEntitySystem_m_nSuppressAutoDeletionExecutionCount",
        [
            "struct_name",
            "member_name",
            "offset",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "CEntitySystem_m_bEnableAutoDeletionExecution",
        [
            "struct_name",
            "member_name",
            "offset",
            "offset_sig",
            # Linux has a byte-identical sibling access site (0x22d7c5f) whose
            # whole instruction sequence matches this one, so the offset_sig
            # matches 2 locations; allow up to 2.
            "offset_sig_max_match:2",
            "offset_sig_disp",
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
    """Locate DestroyEntityImmediate helper functions and member offsets via LLM decompile."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_Activate",
    "CEntitySystem_PostDataUpdate",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "CEntitySystem_m_bInRestoreActivation",
    "CEntitySystem_m_queuedPostDataUpdates",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CEntitySystem_Activate",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_PostDataUpdate",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_m_bInRestoreActivation",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates.{platform}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_m_queuedPostDataUpdates",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates.{platform}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CEntitySystem_Activate", "CEntitySystem"),
    ("CEntitySystem_PostDataUpdate", "CEntitySystem"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEntitySystem_Activate",
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
        "CEntitySystem_PostDataUpdate",
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
        "CEntitySystem_m_bInRestoreActivation",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "CEntitySystem_m_queuedPostDataUpdates",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
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
    """Locate the activation vfuncs and queued post-data-update members via LLM decompile."""
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

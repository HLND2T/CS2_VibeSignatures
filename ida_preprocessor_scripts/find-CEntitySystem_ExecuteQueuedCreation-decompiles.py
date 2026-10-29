#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_ExecuteQueuedCreation-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_ExecuteQueuedActivates",
    "CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "CEntitySystem_m_queuedCreations",
    "CEntitySystem_m_bInvokePostDataUpdates",
    "CEntitySystem_m_bPerformDeletionPostCreation",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CEntitySystem_ExecuteQueuedActivates",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_ExecuteQueuedCreation.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "CEntitySystem_ExecuteQueuedCreation.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_ExecuteQueuedCreation.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "CEntitySystem_ExecuteQueuedCreation.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_m_queuedCreations",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_ExecuteQueuedCreation.{platform}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "CEntitySystem_ExecuteQueuedCreation.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_m_bInvokePostDataUpdates",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_ExecuteQueuedCreation.{platform}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "CEntitySystem_ExecuteQueuedCreation.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CEntitySystem_m_bPerformDeletionPostCreation",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CEntitySystem_ExecuteQueuedCreation.{platform}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "CEntitySystem_ExecuteQueuedCreation.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEntitySystem_ExecuteQueuedActivates",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CEntitySystem_ExecuteQueuedPostDataUpdateAndActivates",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CEntitySystem_m_queuedCreations",
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
        "CEntitySystem_m_bInvokePostDataUpdates",
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
        "CEntitySystem_m_bPerformDeletionPostCreation",
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
    """Locate ExecuteQueuedCreation helper functions and member offsets via LLM decompile."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_m_nSuppressDormancyChangeCount-AND-CEntitySystem_ExecuteQueuedSetInPVS skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_ExecuteQueuedSetInPVS",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "CEntitySystem_m_nSuppressDormancyChangeCount",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CEntitySystem_m_nSuppressDormancyChangeCount",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_ForceSetInPVSCallsIntoQueue.{platform}.yaml",
    ),
    (
        "CEntitySystem_ExecuteQueuedSetInPVS",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_ForceSetInPVSCallsIntoQueue.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEntitySystem_m_nSuppressDormancyChangeCount",
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
        "CEntitySystem_ExecuteQueuedSetInPVS",
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
    """Reuse previous gamever sigs to locate struct members and function, write YAMLs."""
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

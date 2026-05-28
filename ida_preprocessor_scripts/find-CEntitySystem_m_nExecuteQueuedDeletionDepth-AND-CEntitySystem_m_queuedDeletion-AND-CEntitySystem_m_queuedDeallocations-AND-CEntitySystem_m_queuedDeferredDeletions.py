#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_m_nExecuteQueuedDeletionDepth-AND-CEntitySystem_m_queuedDeletion-AND-CEntitySystem_m_queuedDeallocations-AND-CEntitySystem_m_queuedDeferredDeletions skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_STRUCT_MEMBER_NAMES = [
    "CEntitySystem_m_nExecuteQueuedDeletionDepth",
    "CEntitySystem_m_queuedDeletion",
    "CEntitySystem_m_queuedDeallocations",
    "CEntitySystem_m_queuedDeferredDeletions",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CEntitySystem_m_nExecuteQueuedDeletionDepth",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_ExecuteQueuedDeletion.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_queuedDeletion",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_ExecuteQueuedDeletion.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_queuedDeallocations",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_ExecuteQueuedDeletion.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_queuedDeferredDeletions",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_ExecuteQueuedDeletion.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEntitySystem_m_nExecuteQueuedDeletionDepth",
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
        "CEntitySystem_m_queuedDeletion",
        [
            "struct_name",
            "member_name",
            "offset",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "CEntitySystem_m_queuedDeallocations",
        [
            "struct_name",
            "member_name",
            "offset",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "CEntitySystem_m_queuedDeferredDeletions",
        [
            "struct_name",
            "member_name",
            "offset",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Locate CEntitySystem struct member offsets from CEntitySystem_ExecuteQueuedDeletion via LLM decompile."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

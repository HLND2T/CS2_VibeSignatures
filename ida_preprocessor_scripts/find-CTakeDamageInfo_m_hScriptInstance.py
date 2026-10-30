#!/usr/bin/env python3
"""Preprocess script for find-CTakeDamageInfo_m_hScriptInstance."""

from functools import partial
from pathlib import Path

import yaml

from ida_analyze_util import preprocess_common_skill

TARGET_STRUCT_MEMBER_NAMES = ["CTakeDamageInfo_m_hScriptInstance"]

LLM_DECOMPILE = [
    {
        "symbol_name": "CTakeDamageInfo_m_hScriptInstance",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/server/CTakeDamageInfo_GetScriptInstance.{platform}.yaml"],
        "expected_result_sections": ["found_struct_offset"],
        "instruction_rules": [{"regex": r"(?i)^mov\s+.+$", "text": "8-byte script handle read or write"}],
        "expected_size": 8,
        "dependency_policy": {"CTakeDamageInfo_GetScriptInstance.{platform}.yaml": "required"},
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CTakeDamageInfo_m_hScriptInstance",
        ["struct_name", "member_name", "offset", "size", "offset_sig", "offset_sig_disp"],
    ),
]


def _validate_linux_getter_result(result, entry_va):
    """Reject the generic early-return entry in favor of the slow-path read."""
    for entry in result.get("found_struct_offset", []):
        try:
            instruction_va = int(str(entry.get("insn_va")), 0)
        except (TypeError, ValueError):
            return ["Report the current instruction address of the script-instance field read."]
        if instruction_va == entry_va:
            return [
                "The getter entry read belongs to a generic early-return sequence and cannot yield a unique "
                "offset signature. Select the later read of the same script-instance member, after VM "
                "registration and before releasing the previous handle. Do not select the final write-back."
            ]
    return []


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
    """Resolve the target from its current predecessor or a previous signature."""
    llm_specs = LLM_DECOMPILE
    validator = None
    if platform == "linux":
        source = Path(new_binary_dir) / "CTakeDamageInfo_GetScriptInstance.linux.yaml"
        try:
            metadata = yaml.safe_load(source.read_text(encoding="utf-8"))
            entry_va = int(str(metadata["func_va"]), 0)
        except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError):
            return False
        llm_specs = [
            {
                **spec,
                "instruction_rules": [
                    {
                        "regex": r"(?i)^mov\s+r(?:[abcd]x|[sd]i|[bs]p|[89]|1[0-5])\s*,\s*"
                        r"(?:qword ptr\s+)?\[[^\]]+\]$",
                        "text": "read the script-instance handle after VM registration, before old-handle release",
                    }
                ],
            }
            for spec in LLM_DECOMPILE
        ]
        validator = partial(_validate_linux_getter_result, entry_va=entry_va)
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=llm_specs,
        llm_result_validator=validator,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

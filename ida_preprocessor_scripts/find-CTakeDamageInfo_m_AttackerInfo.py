#!/usr/bin/env python3
"""Preprocess script for find-CTakeDamageInfo_m_AttackerInfo."""

from ida_analyze_util import preprocess_common_skill

TARGET_STRUCT_MEMBER_NAMES = ["CTakeDamageInfo_m_AttackerInfo"]

LLM_DECOMPILE = [
    {
        "symbol_name": "CTakeDamageInfo_m_AttackerInfo",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/server/CTakeDamageInfo_Init.{platform}.yaml"],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {"CTakeDamageInfo_Init.{platform}.yaml": "required"},
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CTakeDamageInfo_m_AttackerInfo",
        ["struct_name", "member_name", "offset", "offset_sig", "offset_sig_disp"],
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
    """Resolve the target from its current predecessor or a previous signature."""
    # Linux locates the embedded structure with lea, which does not establish its size.
    desired_fields = [
        (name, fields + (["size"] if platform == "windows" else [])) for name, fields in GENERATE_YAML_DESIRED_FIELDS
    ]
    # Select the embedded structure's address on Linux, its first-byte write on Windows.
    llm_specs = [
        {
            **spec,
            "instruction_rules": [
                {
                    "regex": r"(?i)^mov\s+(?:byte ptr\s+)?\[[^\]]+\]\s*,\s*.+$"
                    if platform == "windows"
                    else r"(?i)^lea\s+.+$",
                    "text": "attacker-info first-byte store" if platform == "windows" else "attacker-info address",
                }
            ],
            **({"expected_size": 1} if platform == "windows" else {}),
        }
        for spec in LLM_DECOMPILE
    ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=llm_specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=desired_fields,
        debug=debug,
    )

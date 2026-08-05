#!/usr/bin/env python3
"""Preprocess script for find-SmokeVolume_BuildSmokeSimulation-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_STRUCT_MEMBER_NAMES = [
    "SmokeVolume_m_vecCenterOrigin",
    "SmokeVolume_m_pStorage",
    "SmokeVolume_m_flStartTime",
]


# Windows writes these fields directly in BuildSmokeSimulation. Linux de-inlines
# that initialization into SmokeVolume_BuildSmokeSimulation_Initialize.
LLM_DECOMPILE_WINDOWS = [
    {
        "symbol_name": symbol_name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/SmokeVolume_BuildSmokeSimulation.{platform}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "SmokeVolume_BuildSmokeSimulation.{platform}.yaml": "required",
        },
    }
    for symbol_name in TARGET_STRUCT_MEMBER_NAMES
]
LLM_DECOMPILE_LINUX = [
    {
        "symbol_name": symbol_name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/SmokeVolume_BuildSmokeSimulation_Initialize.{platform}.yaml",
        ],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {
            "SmokeVolume_BuildSmokeSimulation_Initialize.{platform}.yaml": "required",
        },
    }
    for symbol_name in TARGET_STRUCT_MEMBER_NAMES
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "SmokeVolume_m_vecCenterOrigin",
        [
            "struct_name",
            "member_name",
            "offset",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "SmokeVolume_m_pStorage",
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
        "SmokeVolume_m_flStartTime",
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
    """Locate SmokeVolume center-origin, storage, and start-time offsets via LLM decompile."""
    llm_decompile = LLM_DECOMPILE_WINDOWS if platform == "windows" else LLM_DECOMPILE_LINUX
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=llm_decompile,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Locate CCSPlayer_MovementServices_AirAccelerate and generate a unique function signature."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CCSPlayer_MovementServices_AirAccelerate"]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CCSPlayer_MovementServices_AirAccelerate", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]
SIGNATURES = {
    "windows": "F3 0F 11 5C 24 20 53 56 57 48 83 EC 60",
    "linux": "55 48 89 E5 41 55 49 89 D5 41 54 49 89 FC 53 48 89 F3 48 83 EC 18 48 8B 7F 38",
}


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=[{"func_name": TARGET_FUNCTION_NAMES[0], "xref_signatures": [SIGNATURES[platform]]}],
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Locate CCSPlayer_MovementServices_OnJumpModern and generate a unique function signature."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CCSPlayer_MovementServices_OnJumpModern"]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CCSPlayer_MovementServices_OnJumpModern", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]
SIGNATURES = {
    "windows": "40 55 56 57 41 56 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 4C 8B 71",
    "linux": "55 48 89 E5 41 57 41 56 41 55 49 89 F5 41 54 53 48 89 FB 48 81 EC ?? ?? ?? ?? 4C 8B 77 ?? 4D 8B 66",
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

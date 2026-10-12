#!/usr/bin/env python3
"""Locate CCSPlayer_MovementServices_OnJumpLegacy and generate a unique function signature."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CCSPlayer_MovementServices_OnJumpLegacy"]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CCSPlayer_MovementServices_OnJumpLegacy", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]
FUNC_XREFS = [{"func_name": "CCSPlayer_MovementServices_OnJumpLegacy", "xref_strings": ["FULLMATCH:player_jump"]}]


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
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

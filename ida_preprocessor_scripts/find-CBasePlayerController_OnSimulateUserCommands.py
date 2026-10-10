#!/usr/bin/env python3
"""Locate CBasePlayerController_OnSimulateUserCommands and generate a unique function signature."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CBasePlayerController_OnSimulateUserCommands"]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CBasePlayerController_OnSimulateUserCommands", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]
FUNC_XREFS = [
    {
        "func_name": "CBasePlayerController_OnSimulateUserCommands",
        "xref_strings": ["FULLMATCH:CBasePlayerController::OnSimulateUserCommands"],
    }
]
LINUX_SIGNATURE = (
    "55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 E5 41 57 41 56 41 55 41 54 53 "
    "48 89 FB 48 8D 3D ?? ?? ?? ?? 48 81 EC ?? 00 00 00"
)


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
        func_xrefs=FUNC_XREFS
        if platform == "windows"
        else [{"func_name": TARGET_FUNCTION_NAMES[0], "xref_signatures": [LINUX_SIGNATURE]}],
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

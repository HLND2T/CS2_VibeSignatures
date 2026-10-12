#!/usr/bin/env python3
"""Locate CCSPlayer_MovementServices_Duck through the bot_crouch ConVar."""

from ida_preprocessor_scripts._convar_function import preprocess_convar_function

TARGET_FUNCTION_NAMES = ["CCSPlayer_MovementServices_Duck"]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CCSPlayer_MovementServices_Duck",
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
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    return await preprocess_convar_function(
        session,
        expected_outputs,
        old_yaml_map,
        new_binary_dir,
        platform,
        image_base,
        convar_name="bot_crouch",
        target_name=TARGET_FUNCTION_NAMES[0],
        desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

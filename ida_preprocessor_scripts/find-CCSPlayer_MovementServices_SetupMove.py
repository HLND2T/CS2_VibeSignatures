#!/usr/bin/env python3
"""Locate CCSPlayer_MovementServices_SetupMove through the dev_create_move_report ConVar."""

from ida_preprocessor_scripts._convar_function import preprocess_convar_function

TARGET_FUNCTION_NAMES = ["CCSPlayer_MovementServices_SetupMove"]
FUNC_VTABLE_RELATIONS = [("CCSPlayer_MovementServices_SetupMove", "CCSPlayer_MovementServices")]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CCSPlayer_MovementServices_SetupMove",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
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
        convar_name="dev_create_move_report",
        target_name=TARGET_FUNCTION_NAMES[0],
        desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        vtable_name=FUNC_VTABLE_RELATIONS[0][1],
        debug=debug,
    )

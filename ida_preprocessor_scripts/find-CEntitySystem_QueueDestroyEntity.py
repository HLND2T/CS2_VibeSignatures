#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_QueueDestroyEntity skill."""

from ida_preprocessor_scripts._direct_branch_target_common import (
    preprocess_direct_branch_target_skill,
)


SOURCE_FUNCTION_NAME = "UTIL_Remove"

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_QueueDestroyEntity",
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEntitySystem_QueueDestroyEntity",
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
    _ = skill_name, old_yaml_map
    return await preprocess_direct_branch_target_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        source_yaml_stem=SOURCE_FUNCTION_NAME,
        target_name=TARGET_FUNCTION_NAMES[0],
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        rename_to=TARGET_FUNCTION_NAMES[0],
        debug=debug,
    )

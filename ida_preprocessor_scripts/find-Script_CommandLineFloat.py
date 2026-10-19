#!/usr/bin/env python3
"""Resolve the registered VScript CommandLineFloat callback."""

from ida_preprocessor_scripts._script_desc_internal_common import (
    preprocess_script_desc_internal_skill,
)

SOURCE_YAML_STEM = "Script_RegisterCommandLineFunctions"
TARGET_SCRIPT_FUNCTIONS = [{"script_name": "CommandLineFloat", "target_name": "Script_CommandLineFloat"}]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "Script_CommandLineFloat",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
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
    """Read the callback from its named script descriptor, without guessing a slot."""
    return await preprocess_script_desc_internal_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        source_yaml_stem=SOURCE_YAML_STEM,
        target_specs=TARGET_SCRIPT_FUNCTIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        expected_script_func_count=1,
        debug=debug,
    )

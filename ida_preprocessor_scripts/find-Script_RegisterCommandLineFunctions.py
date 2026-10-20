#!/usr/bin/env python3
"""Locate the VScript registration of the command-line accessor functions."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Script_RegisterCommandLineFunctions"]

FUNC_XREFS = [
    {
        "func_name": "Script_RegisterCommandLineFunctions",
        "xref_strings": [
            "FULLMATCH:CommandLineFloat(name) : returns the command line param as a float.",
        ],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "Script_RegisterCommandLineFunctions",
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
    """Find the registration function from the float accessor's help text."""
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

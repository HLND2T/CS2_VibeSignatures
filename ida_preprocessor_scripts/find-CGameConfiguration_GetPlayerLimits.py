#!/usr/bin/env python3
"""Locate the Linux player-limit computation used by the command-line finder."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CGameConfiguration_GetPlayerLimits"]

FUNC_XREFS = [
    {
        "func_name": "CGameConfiguration_GetPlayerLimits",
        "xref_strings": [
            "GetPlayerLimits:  min maxplayers must be >= 1 (%i)",
            "GetPlayerLimits:  max players limited to %i",
        ],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CGameConfiguration_GetPlayerLimits",
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
    """Find the predecessor from its player-limit validation messages."""
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

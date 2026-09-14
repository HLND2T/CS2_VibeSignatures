#!/usr/bin/env python3
"""Locate CLagCompensationManager::StartLagCompensation from its diagnostic."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CLagCompensationManager_StartLagCompensation"]

FUNC_XREFS = [
    {
        "func_name": "CLagCompensationManager_StartLagCompensation",
        "xref_strings": ["CLagCompensationManager::StartLagCompensation with NULL CUserCmd!!!"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        # Linux also contains a distinct overload that shares this diagnostic.
        # Its prologue does not occur in the Windows target implementation.
        "exclude_signatures": ["55 48 89 E5 41 57 41 56 41 55 41 54 49 89 F4"],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CLagCompensationManager_StartLagCompensation",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
        ],
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Locate StartLagCompensation from its diagnostic string."""
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

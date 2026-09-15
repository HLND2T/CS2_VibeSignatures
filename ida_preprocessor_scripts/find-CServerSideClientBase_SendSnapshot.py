#!/usr/bin/env python3
"""Preprocess script for find-CServerSideClientBase_SendSnapshot skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CServerSideClientBase_SendSnapshot"]

FUNC_XREFS = [
    {
        "func_name": "CServerSideClientBase_SendSnapshot",
        "xref_strings": ["SendSnapshot_BeforeJobRuns"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("CServerSideClientBase_SendSnapshot", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Find SendSnapshot from its job profiler marker."""
    _ = skill_name
    return await preprocess_common_skill(
        session=session, expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map, new_binary_dir=new_binary_dir, platform=platform,
        image_base=image_base, func_names=TARGET_FUNCTION_NAMES, func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS, debug=debug,
    )

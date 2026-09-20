#!/usr/bin/env python3
"""Resolve the RequestHS_PlayBroadcast string owner."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CHostStateMgr_RequestHS_PlayBroadcastInternal"]
FUNC_XREFS = [
    {
        "func_name": "CHostStateMgr_RequestHS_PlayBroadcastInternal",
        "xref_strings": ["Playing Broadcast (%s)"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CHostStateMgr_RequestHS_PlayBroadcastInternal", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
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

#!/usr/bin/env python3
"""Locate the de-inlined remote-connect host-state request helper."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CHostStateRequest_Connect"]
FUNC_XREFS = [{"func_name": "CHostStateRequest_Connect", "xref_strings": ["Remote Connect (%s)"]}]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CHostStateRequest_Connect", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
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

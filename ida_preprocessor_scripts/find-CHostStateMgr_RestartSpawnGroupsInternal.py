#!/usr/bin/env python3
"""Resolve the standalone restart-spawn-groups diagnostic owner."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CHostStateMgr_RestartSpawnGroupsInternal"]
FUNC_XREFS = [
    {
        "func_name": "CHostStateMgr_RestartSpawnGroupsInternal",
        "xref_strings": ["No previous spawn group\n"],
    }
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CHostStateMgr_RestartSpawnGroupsInternal",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
    )
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

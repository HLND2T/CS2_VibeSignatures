#!/usr/bin/env python3
"""Find CreateWorld_Internal from its blocking-load diagnostic."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CWorldRendererMgr_CreateWorld_Internal"]
FUNC_XREFS = [
    {
        "func_name": "CWorldRendererMgr_CreateWorld_Internal",
        "xref_strings": [
            "CWorldRendererMgr::CreateWorld_Internal( %s ):  Blocking load because marked for deletion during load",
        ],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CWorldRendererMgr_CreateWorld_Internal", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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

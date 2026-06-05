#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_AddComponentFieldUnserializer skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_AddComponentFieldUnserializer",
]

FUNC_XREFS_WINDOWS = [
    {
        "func_name": "CEntitySystem_AddComponentFieldUnserializer",
        "xref_strings": [
            "Field %s::%s cannot have sub-keyfields since it is an atomic type!\n",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_XREFS_LINUX = [
    {
        "func_name": "CEntitySystem_AddComponentFieldUnserializer",
        "xref_strings": [
            "Field %s::%s cannot have sub-keyfields since it is an atomic type!\n",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        # Two funcs reference the string on Linux; exclude the wrong one by its prologue bytes
        "exclude_signatures": ["55 4D 89 C2 48 89"],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEntitySystem_AddComponentFieldUnserializer",
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
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS_WINDOWS if platform == "windows" else FUNC_XREFS_LINUX,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

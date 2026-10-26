#!/usr/bin/env python3
"""Find CaptureCubemap_Static_Init by its "Capture Cubemap" xref string."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CaptureCubemap_Static_Init"]

FUNC_XREFS = [
    {
        "func_name": "CaptureCubemap_Static_Init",
        "xref_strings": ["Capture Cubemap"],
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
    # (symbol_name, generate_yaml_fields)
    # Include func_va/func_rva/func_size: this function is a predecessor for downstream LLM_DECOMPILE
    (
        "CaptureCubemap_Static_Init",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
    ),
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

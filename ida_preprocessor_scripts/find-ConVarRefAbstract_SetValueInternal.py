#!/usr/bin/env python3
"""Find ConVarRefAbstract_SetValueInternal from its diagnostic string."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["ConVarRefAbstract_SetValueInternal"]
FUNC_XREFS = [
    {
        "func_name": "ConVarRefAbstract_SetValueInternal",
        "xref_strings": ["Can't change '%s' right now.\n"],
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
    ("ConVarRefAbstract_SetValueInternal", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
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

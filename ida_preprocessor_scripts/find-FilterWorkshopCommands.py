#!/usr/bin/env python3
"""Find the workshop command filter or its inlined owner from its rejection log."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["FilterWorkshopCommands"]
FUNC_XREFS = [
    {
        "func_name": "FilterWorkshopCommands",
        "xref_strings": ["FULLMATCH:WORKSHOP COMMAND: %s does not exist, ignoring\n"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("FilterWorkshopCommands", ["func_name", "func_va", "func_rva", "func_size", "func_sig"]),
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

#!/usr/bin/env python3
"""Preprocess script for find-CPlayer_MovementServices_ForceButtonState skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CPlayer_MovementServices_ForceButtonState",
]

FUNC_XREFS = [
                 {
                     "func_name": 'CPlayer_MovementServices_ForceButtonState',
                     "xref_strings": ['[%s] Force State: %s = %d, Next: %s'],
                     "xref_gvs": [],
                     "xref_signatures": ["31 C9 31 C0"],
                     "xref_funcs": [],
                     "exclude_funcs": [],
                     "exclude_strings": [],
                     "exclude_gvs": [],
                     "exclude_signatures": [],
                 },
             ]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CPlayer_MovementServices_ForceButtonState",
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
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

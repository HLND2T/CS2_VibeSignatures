#!/usr/bin/env python3
"""Preprocess script for find-CSource2EntitySystem_StaticInit skill."""

import os

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CSource2EntitySystem_StaticInit",
]

FUNC_XREFS_SERVER = [
    {
        "func_name": "CSource2EntitySystem_StaticInit",
        "xref_strings": [
            "FULLMATCH:server_entities",
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

FUNC_XREFS_CLIENT = [
    {
        "func_name": "CSource2EntitySystem_StaticInit",
        "xref_strings": [
            "FULLMATCH:client_entities",
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

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CSource2EntitySystem_StaticInit",
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
    module_name = os.path.basename(os.path.normpath(new_binary_dir)) if new_binary_dir else "server"
    func_xrefs = FUNC_XREFS_CLIENT if module_name == "client" else FUNC_XREFS_SERVER

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

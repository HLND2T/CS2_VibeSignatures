#!/usr/bin/env python3
"""Preprocess script for find-CServerSideClient_ProcessMove."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CServerSideClient_ProcessMove",
]

FUNC_XREFS = [
    {
        "func_name": "CServerSideClient_ProcessMove",
        "xref_strings": [
            "SV: ProcessMove %s on tick %d, packet had too many Move messages (expected only 1, this is %d), disconnecting user",
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

# CServerSideClient_ProcessMove is a vfunc of CServerSideClient
FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CServerSideClient_ProcessMove", "CServerSideClient_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CServerSideClient_ProcessMove",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
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
    """Locate the target vfunc from its diagnostic string and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

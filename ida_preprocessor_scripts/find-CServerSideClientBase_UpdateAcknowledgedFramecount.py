#!/usr/bin/env python3
"""Preprocess script for find-CServerSideClientBase_UpdateAcknowledgedFramecount skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CServerSideClientBase_UpdateAcknowledgedFramecount",
]

FUNC_XREFS = [
    {
        "func_name": "CServerSideClientBase_UpdateAcknowledgedFramecount",
        "xref_strings": [
            "'%s' already awaiting full update",
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

# CServerSideClientBase_UpdateAcknowledgedFramecount is a vfunc of CServerSideClientBase
FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CServerSideClientBase_UpdateAcknowledgedFramecount", "CServerSideClientBase_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CServerSideClientBase_UpdateAcknowledgedFramecount",
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

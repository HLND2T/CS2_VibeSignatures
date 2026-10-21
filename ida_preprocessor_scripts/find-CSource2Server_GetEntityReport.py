#!/usr/bin/env python3
"""Preprocess script for find-CSource2Server_GetEntityReport skill."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = [
    "CSource2Server_GetEntityReport",
]

FUNC_XREFS = [
    {
        "func_name": "CSource2Server_GetEntityReport",
        "xref_strings": [
            "FULLMATCH:[-1] -> empty",
            "FULLMATCH:%d (s/n %d)",
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

FUNC_VTABLE_RELATIONS = [
    ("CSource2Server_GetEntityReport", "CSource2Server_vtable"),
]

# Artifact keys stay stable; emitted names reflect the verified SDK semantics.
OUTPUT_NAME_MAP = {
    "CSource2Server_GetEntityReport": "CSource2Server_FormatSerializerFieldValue",
}

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CSource2Server_GetEntityReport",
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
    """Locate CSource2Server::GetEntityReport from its exact debug strings."""
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
        output_name_map=OUTPUT_NAME_MAP,
    )

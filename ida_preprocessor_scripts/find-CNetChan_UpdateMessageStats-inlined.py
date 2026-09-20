#!/usr/bin/env python3
"""Preprocess script for the UpdateMessageStats inlined vfunc path."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CNetChan_UpdateMessageStats"]

FUNC_XREFS = [
    {
        "func_name": "CNetChan_UpdateMessageStats",
        "xref_strings": [
            "CNetChan::UpdateMessageStats, bit counter about to roll over with addition of %d bits, resetting to zero",
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
        "func_name": "CNetChan_UpdateMessageStats",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": ["55 48 89 E5 41 54 53 48 89 FB 48 83 EC 10 80 BF ?? ?? ?? ?? ??"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [("CNetChan_UpdateMessageStats", "CNetChan_vtable")]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetChan_UpdateMessageStats",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "vtable_name", "vfunc_offset", "vfunc_index"],
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
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS_LINUX if platform == "linux" else FUNC_XREFS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Resolve RemoveAllTables by intersecting its debug-string xrefs with the container vtable.

The string anchor alone is not unique: inline call sites accumulate in unrelated functions
(the server-side mirror installer and static initializers, for instance). Intersecting the
string-xref candidate set with ``CNetworkStringTableContainer_vtable`` leaves exactly one
function, and the same query covers both build shapes -- body inlined into the vfunc, or
de-inlined behind a helper that the vtable slot still points at.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CNetworkStringTableContainer_RemoveAllTables"]

FUNC_XREFS = [
    {
        "func_name": "CNetworkStringTableContainer_RemoveAllTables",
        "xref_strings": [
            "%s: CNetworkStringTableContainer::RemoveAllTables:  removing %d tables\n",
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
    ("CNetworkStringTableContainer_RemoveAllTables", "CNetworkStringTableContainer_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkStringTableContainer_RemoveAllTables",
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
    """Resolve the vfunc by intersecting the debug-string xrefs with the container vtable."""
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

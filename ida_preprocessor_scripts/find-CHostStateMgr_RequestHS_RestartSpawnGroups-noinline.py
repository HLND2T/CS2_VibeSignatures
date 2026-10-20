#!/usr/bin/env python3
"""Resolve RequestHS_RestartSpawnGroups through the shared LoadSpawnGroup fill.

`CHostStateRequest_LoadSpawnGroup` is out-of-line on Linux and is called by BOTH
the slot-15 sibling (RequestHS_LoadSpawnGroup) and this slot-22 vfunc. Intersecting
its callers with the "No previous spawn group" message — owned only by this
vfunc — picks the slot-22 sibling. (The sibling relies on the mirror-image
exclusion, so the two finders stay symmetric.)

On Windows this vfunc inlines that fill, so the `xref_funcs` dependency has no
caller to match and this finder legitimately degenerates; `...-inlined` handles
Windows.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CHostStateMgr_RequestHS_RestartSpawnGroups"]

FUNC_XREFS = [
    {
        "func_name": "CHostStateMgr_RequestHS_RestartSpawnGroups",
        "xref_strings": ["No previous spawn group\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CHostStateRequest_LoadSpawnGroup"],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]

FUNC_VTABLE_RELATIONS = [
    ("CHostStateMgr_RequestHS_RestartSpawnGroups", "CHostStateMgr_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CHostStateMgr_RequestHS_RestartSpawnGroups",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "vtable_name", "vfunc_offset", "vfunc_index"],
    )
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
    """Resolve the de-inlined implementation and its vtable slot."""
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

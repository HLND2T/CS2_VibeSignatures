#!/usr/bin/env python3
"""Resolve RequestHS_ReloadLastSaveGame through the fill it delegates to.

`CHostStateRequest_LoadSaveGame` is out-of-line on Linux and is called by BOTH the
slot-16 sibling (RequestHS_LoadSaveGame) and this slot-21 wrapper. Intersecting its
callers with the "No previous save" message — owned only by this wrapper — picks
the slot-21 sibling. (The sibling relies on the mirror-image exclusion, so the two
finders stay symmetric.)

On Windows that fill has no artifact of its own, so the `xref_funcs` dependency is
unavailable and this finder legitimately degenerates; `...-inlined` handles Windows.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CHostStateMgr_RequestHS_ReloadLastSaveGame"]

FUNC_XREFS = [
    {
        "func_name": "CHostStateMgr_RequestHS_ReloadLastSaveGame",
        "xref_strings": ["No previous save"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CHostStateRequest_LoadSaveGame"],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]

FUNC_VTABLE_RELATIONS = [
    ("CHostStateMgr_RequestHS_ReloadLastSaveGame", "CHostStateMgr_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CHostStateMgr_RequestHS_ReloadLastSaveGame",
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

#!/usr/bin/env python3
"""Resolve RequestHS_RestartSpawnGroups from its dialog.

On Windows the vfunc inlines the shared `CHostStateRequest_LoadSpawnGroup` fill,
so there is no out-of-line caller for `xref_funcs` to match; the "No previous
spawn group" message — owned only by this vfunc — resolves it uniquely. (The
`...-noinline` sibling handles Linux, where the fill is a real call.)
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CHostStateMgr_RequestHS_RestartSpawnGroups"]

FUNC_XREFS = [
    {
        "func_name": "CHostStateMgr_RequestHS_RestartSpawnGroups",
        "xref_strings": ["No previous spawn group\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
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
    """Resolve the inline implementation and its vtable slot."""
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

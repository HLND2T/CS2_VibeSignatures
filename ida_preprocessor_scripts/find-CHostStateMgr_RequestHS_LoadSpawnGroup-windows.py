#!/usr/bin/env python3
"""Find the Windows LoadSpawnGroup vfunc from its request function."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CHostStateMgr_RequestHS_LoadSpawnGroup"]
FUNC_XREFS = [
    {
        "func_name": "CHostStateMgr_RequestHS_LoadSpawnGroup",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CHostStateRequest_LoadSpawnGroup"],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]
FUNC_VTABLE_RELATIONS = [("CHostStateMgr_RequestHS_LoadSpawnGroup", "CHostStateMgr_vtable")]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CHostStateMgr_RequestHS_LoadSpawnGroup",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "vtable_name", "vfunc_offset", "vfunc_index"],
    )
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    """Resolve the Windows vfunc and retain its vtable slot."""
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

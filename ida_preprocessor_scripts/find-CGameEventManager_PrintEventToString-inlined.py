#!/usr/bin/env python3
"""Resolve PrintEventToString from its format string."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CGameEventManager_PrintEventToString"]

FUNC_XREFS = [
    {
        "func_name": "CGameEventManager_PrintEventToString",
        "xref_strings": ['"%s" "%.2f"'],
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
    ("CGameEventManager_PrintEventToString", "CGameEventManager_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CGameEventManager_PrintEventToString",
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

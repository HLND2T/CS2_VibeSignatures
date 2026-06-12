#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_InvokePrecacheCallback skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_InvokePrecacheCallback",
]

# xref_funcs finds callers of CEntitySystem_PrecacheEntity.
# FUNC_VTABLE_RELATIONS automatically intersects those callers with CEntitySystem vtable
# entries, eliminating non-vtable callers (e.g. save-restore helpers).
# exclude_strings then removes vtable[3] and vtable[5], which also call PrecacheEntity
# but reference the string "classname", leaving only vtable[6] = InvokePrecacheCallback.
FUNC_XREFS = [
    {
        "func_name": "CEntitySystem_InvokePrecacheCallback",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CEntitySystem_PrecacheEntity"],
        "exclude_funcs": [],
        "exclude_strings": ["classname"],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    # Uses artifact stem so preprocess_common_skill reads CEntitySystem_vtable YAML
    # for the candidate intersection set instead of doing a live IDA vtable lookup.
    ("CEntitySystem_InvokePrecacheCallback", "CEntitySystem_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEntitySystem_InvokePrecacheCallback",
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
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Locate via CEntitySystem_PrecacheEntity callee xref + vtable intersection + string exclusion."""
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

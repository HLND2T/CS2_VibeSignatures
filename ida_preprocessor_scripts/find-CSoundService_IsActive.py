#!/usr/bin/env python3
"""Preprocess script for find-CSoundService_IsActive skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CSoundService_IsActive"]

FUNC_XREFS = [
    {
        "func_name": "CSoundService_IsActive",
        "xref_strings": ["FULLMATCH:game"],
        "xref_gvs": ["g_pEngineServiceMgr"],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_XREFS_IDA_COMPAT = [
    {
        **FUNC_XREFS[0],
        "xref_strings": ["game"],
    },
]

FUNC_VTABLE_RELATIONS = [("CSoundService_IsActive", "CSoundService_vtable")]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CSoundService_IsActive",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
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
    """Reuse previous gamever func_sig to locate the target function and write YAML."""
    preprocess_kwargs = {
        "session": session,
        "expected_outputs": expected_outputs,
        "old_yaml_map": old_yaml_map,
        "new_binary_dir": new_binary_dir,
        "platform": platform,
        "image_base": image_base,
        "func_names": TARGET_FUNCTION_NAMES,
        "func_xrefs": FUNC_XREFS,
        "func_vtable_relations": FUNC_VTABLE_RELATIONS,
        "generate_yaml_desired_fields": GENERATE_YAML_DESIRED_FIELDS,
        "debug": debug,
    }
    if await preprocess_common_skill(**preprocess_kwargs):
        return True

    preprocess_kwargs["func_xrefs"] = FUNC_XREFS_IDA_COMPAT
    return await preprocess_common_skill(**preprocess_kwargs)

#!/usr/bin/env python3
"""Preprocess script for the inlined CreateLoopMode finder."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CLoopModeFactory_CLoopModeGame_CreateLoopMode",
]

FUNC_XREFS = [
    {
        "func_name": "CLoopModeFactory_CLoopModeGame_CreateLoopMode",
        "xref_strings": [
            "%s:  CLoopModeGame constructed\n",
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
    (
        "CLoopModeFactory_CLoopModeGame_CreateLoopMode",
        "CLoopModeFactory_CLoopModeGame_vtable",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CLoopModeFactory_CLoopModeGame_CreateLoopMode",
        [
            "func_name",
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
    """Resolve the vfunc when CLoopModeGame_ctor is inlined into it."""
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

#!/usr/bin/env python3
"""Resolve the \"Game Event Fired\" string owner (de-inlined helper, link 1/3 of the FireEvent chain).

On builds where the helper is inlined into the vfunc this resolves to the vfunc itself;
harmless because the helper symbol is not registered."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CGameEventManager_FireEventInternal"]

FUNC_XREFS = [
    {
        "func_name": "CGameEventManager_FireEventInternal",
        "xref_strings": ["Game Event Fired: %s\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CGameEventManager_FireEventInternal",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
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
    """Locate target function(s) and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

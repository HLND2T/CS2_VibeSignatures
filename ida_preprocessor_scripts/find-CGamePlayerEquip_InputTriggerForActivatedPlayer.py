#!/usr/bin/env python3
"""Preprocess script for find-CGamePlayerEquip_InputTriggerForActivatedPlayer skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGamePlayerEquip_InputTriggerForActivatedPlayer",
]

# Legacy CGamePlayerEquip::InputTriggerForActivatedPlayer body, which is also the
# CGamePlayerEquip vtable slot holding it. Entity inputs moved to `_API` registration in
# 14182 (issue #1061), so the registration descriptor and the bare
# "TriggerForActivatedPlayer" string no longer reach this symbol; the `_API` wrapper
# (find-CGamePlayerEquip_API_TriggerForActivatedPlayer) forwards to it. Signatures come
# from CS2Fixes' maintained entries of the same name.
FUNC_XREFS_WINDOWS = [
    {
        "func_name": "CGamePlayerEquip_InputTriggerForActivatedPlayer",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": ["48 89 5C 24 ? 56 48 83 EC ? 48 8B 1A"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_XREFS_LINUX = [
    {
        "func_name": "CGamePlayerEquip_InputTriggerForActivatedPlayer",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": ["55 48 89 E5 41 56 41 55 41 54 53 48 8B 1E 48 85 DB 74"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CGamePlayerEquip_InputTriggerForActivatedPlayer",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
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
    """Locate the legacy CGamePlayerEquip::InputTriggerForActivatedPlayer body."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS_WINDOWS if platform == "windows" else FUNC_XREFS_LINUX,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

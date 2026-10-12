#!/usr/bin/env python3
"""Preprocess script for find-CGamePlayerEquip_InputTriggerForAllPlayers skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGamePlayerEquip_InputTriggerForAllPlayers",
]

# Legacy CGamePlayerEquip::InputTriggerForAllPlayers body. Entity inputs moved to `_API`
# registration in 14182 (issue #1061), so the registration descriptor and the bare
# "TriggerForAllPlayers" string no longer reach this symbol; the `_API` wrapper
# (find-CGamePlayerEquip_API_TriggerForAllPlayers) calls it instead. Signatures come from
# CS2Fixes' maintained entries of the same name.
FUNC_XREFS_WINDOWS = [
    {
        "func_name": "CGamePlayerEquip_InputTriggerForAllPlayers",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": ["48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8B EC 48 83 EC ? 4C 8B F1"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_XREFS_LINUX = [
    {
        "func_name": "CGamePlayerEquip_InputTriggerForAllPlayers",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [
            "55 48 89 E5 41 57 41 56 41 55 41 54 49 89 FC 53 48 83 EC ? E8 ? ? ? ? "
            "C7 45 ? ? ? ? ? 89 C7 66 89 45 ? 66 83 F8 ? 75 ? 48 C7 45 ? ? ? ? ? 66 83 FF ? "
            "0F 84 ? ? ? ? 0F B7 7D ? E8 ? ? ? ? 66 89 45 ? 66 83 F8 ? 0F 84 ? ? ? ? 89 C7 "
            "E8 ? ? ? ? 0F B7 7D ? 48 89 C3 48 85 C0 74 ? 48 89 C7 E8 ? ? ? ? 48 8D 7D ? "
            "48 89 C6 E8 ? ? ? ? 0F B7 7D ? 84 C0 0F 85 ? ? ? ? EB ? 66 0F 1F 44 00 ? "
            "E8 ? ? ? ? 48 89 C3 48 85 C0 0F 84 ? ? ? ? 48 89 C7 E8 ? ? ? ? 48 8D 7D ? "
            "48 89 C6 E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 0F B7 7D ? 48 89 5D ? 66 83 FF"
        ],
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
        "CGamePlayerEquip_InputTriggerForAllPlayers",
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
    """Locate the legacy CGamePlayerEquip::InputTriggerForAllPlayers body."""
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

#!/usr/bin/env python3
"""Preprocess script for find-CBasePlayerPawn_PrePhysicsSimulate skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CBasePlayerPawn_PrePhysicsSimulate"]
FUNC_XREFS_WINDOWS = [
    {
        "func_name": "CBasePlayerPawn_PrePhysicsSimulate",
        "xref_strings": [
            "FULLMATCH:C:\\buildworker\\csgo_rel_win64\\build\\src\\game\\shared\\baseplayerpawn_shared.cpp",
            "FULLMATCH:PrePhysicsSimulate",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]

FUNC_XREFS_LINUX = [
    {
        "func_name": "CBasePlayerPawn_PrePhysicsSimulate",
        "xref_strings": [
            "FULLMATCH:../../game/shared/baseplayerpawn_shared.cpp",
            "FULLMATCH:PrePhysicsSimulate",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": ["BA FF FF FF 7F"],
    }
]
FUNC_VTABLE_RELATIONS = [("CBasePlayerPawn_PrePhysicsSimulate", "CBasePlayerPawn_vtable")]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CBasePlayerPawn_PrePhysicsSimulate",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "vtable_name", "vfunc_offset", "vfunc_index"],
    )
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    """Resolve the CBasePlayerPawn vfunc from its platform source and scope strings."""
    _ = skill_name
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS_WINDOWS if platform == "windows" else FUNC_XREFS_LINUX,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

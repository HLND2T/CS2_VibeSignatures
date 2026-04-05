#!/usr/bin/env python3
"""Preprocess script for find-CNetworkServerService_Init skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkServerService_Init",
]

FUNC_XREFS = [
    # (func_name, xref_strings_list, xref_funcs_list)
    (
        "CNetworkServerService_Init",
        [
            "ServerToClient",
            "Entities",
            "Local Player",
            "Other Players",
        ],
        [],
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class, generate_vfunc_offset)
    ("CNetworkServerService_Init", "CNetworkServerService", True),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
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
        debug=debug,
    )

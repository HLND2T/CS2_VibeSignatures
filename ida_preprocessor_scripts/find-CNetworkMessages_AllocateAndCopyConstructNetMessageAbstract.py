#!/usr/bin/env python3
"""Preprocess script for find-CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract",
]

FUNC_XREF_STRINGS = [
    # (func_name, xref_strings_list)
    ( "CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract",
    [
    "CNetworkMessages::AllocateAndCopyConstructNetMessageAbstract unable to allocate unknown message type!"
    ] ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class, generate_vfunc_offset)
    ("CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract", "CNetworkMessages", True),
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
        func_xref_strings=FUNC_XREF_STRINGS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        debug=debug,
    )

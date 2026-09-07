#!/usr/bin/env python3
"""Preprocess script for find-ParseNetadrList skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "ParseNetadrList",
]

FUNC_XREFS = [
    {
        "func_name": "ParseNetadrList",
        # FULLMATCH: plain substring matching would also pull in every
        # "loopback:%d" / "voice_loopback" / "cl_usesocketsforloopback"
        # reference. Three unrelated functions still reference the exact
        # literal and are excluded by prologue bytes
        # (CNetworkClientService_AllocateRemoteConnectionClient, sub_180055880,
        # sub_1801CBAB0 on 14178b).
        "xref_strings": ["FULLMATCH:loopback"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [
            "48 89 5C 24 10 48 89 6C",
            "44 88 44 24 18 53 55 41",
            "48 89 54 24 10 56 41 57",
        ],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "ParseNetadrList",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
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
    """Find the netadr string-list parser that handles the 'loopback' keyword."""
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

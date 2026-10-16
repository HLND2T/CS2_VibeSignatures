#!/usr/bin/env python3
"""Preprocess script for the UpdateMessageStats de-inlined helper."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CNetChan_UpdateMessageStatsInternal"]

FUNC_XREFS = [
    {
        "func_name": "CNetChan_UpdateMessageStatsInternal",
        "xref_strings": [
            "CNetChan::UpdateMessageStats, bit counter about to roll over with addition of %d bits, resetting to zero",
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

# Linux resolves the internal helper by the same diagnostic string as Windows.
# The former per-platform prologue signature
# ("55 48 89 E5 41 54 53 48 89 FB 48 83 EC 10 80 BF ?? ?? ?? ?? ??") is a
# generic frame template: on the 14191 libnetworksystem.so it matches only
# CNetChan_CanPacket (0x286b20), while the real helper (sub_287380) shares the
# "41 57 41 56 49 89 FE" prologue of its sibling. Anchoring on the string keeps
# the search semantic instead of depending on a prologue the compiler moves.
FUNC_XREFS_LINUX = FUNC_XREFS

GENERATE_YAML_DESIRED_FIELDS = [
    ("CNetChan_UpdateMessageStatsInternal", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS_LINUX if platform == "linux" else FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

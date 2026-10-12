#!/usr/bin/env python3
"""Preprocess script for find-CNetworkGameClient_OnSource1Source1LegacyGameEvent skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkGameClient_OnSource1Source1LegacyGameEvent",
]

FUNC_XREFS_WINDOWS = [
    {
        "func_name": "CNetworkGameClient_OnSource1Source1LegacyGameEvent",
        "xref_strings": [
            "CNetworkGameClient::OnSource1Source1LegacyGameEvent: UnserializeKeyValue failed.",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": ["56 57 48 83 EC 28 48 8B"],
    },
]

FUNC_XREFS_LINUX = [
    {
        "func_name": "CNetworkGameClient_OnSource1Source1LegacyGameEvent",
        "xref_strings": [
            "CNetworkGameClient::OnSource1Source1LegacyGameEvent: UnserializeKeyValue failed.",
        ],
        "xref_gvs": [],
        # Discriminates the target from the sibling that logs the same message.
        "xref_signatures": [
            "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 89 F3 48 83 EC 38 48 8B 05",
        ],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkGameClient_OnSource1Source1LegacyGameEvent",
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
    """Reuse a previous func_sig or find the unique legacy-event error-string xref."""
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

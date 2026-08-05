#!/usr/bin/env python3
"""Preprocess script for find-CNetworkGameServer_GetFreeClientCreatePath skill.

This is the "create a new client" branch of CNetworkGameServer::GetFreeClient.
On Windows the whole find-or-create logic lives in a single function
(the same body as CNetworkGameServer_GetFreeClient), while on Linux the
compiler split the create path into its own function. Both bodies uniquely
reference the debug string "Kicked to free up slot" and call
CNetworkGameServerBase::CreateNewClient on `this`, so this function serves as
the predecessor for locating that virtual call.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkGameServer_GetFreeClientCreatePath",
]

FUNC_XREFS = [
    {
        "func_name": "CNetworkGameServer_GetFreeClientCreatePath",
        "xref_strings": ["Kicked to free up slot"],
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
    # (symbol_name, generate_yaml_fields)
    (
        "CNetworkGameServer_GetFreeClientCreatePath",
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
    """Locate the GetFreeClient create path via its unique debug string."""
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

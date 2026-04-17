#!/usr/bin/env python3
"""Preprocess script for find-CNetworkGameServerBase_ConnectClient skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkGameServerBase_ConnectClient",
]

FUNC_XREFS = [
    {
        "func_name": "CNetworkGameServerBase_ConnectClient",
        "xref_strings": [
            "CNetworkGameServerBase::ConnectClient( name='%s', remote='%s' )",
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

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # No func_sig: ConnectClient is a large function whose head bytes are not
    # unique in the binary. func_va/func_rva/func_size are sufficient as
    # LLM_DECOMPILE predecessor for find-CNetworkGameServer_GetFreeClient.
    (
        "CNetworkGameServerBase_ConnectClient",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

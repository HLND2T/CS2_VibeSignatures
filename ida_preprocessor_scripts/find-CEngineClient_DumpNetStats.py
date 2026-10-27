#!/usr/bin/env python3
"""Preprocess script for find-CEngineClient_DumpNetStats skill.

Resolves the parameterless ``CEngineClient::PrintNetworkSummaryReport``, which
only delegates to the network client's PrintNetStats. The artifact key and the
slot are historical: index 184 is not the ``DumpNetStats( void *, void (
* )( const char * ) )`` that the SDK declares at index 29.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEngineClient_DumpNetStats",
]

# The artifact key is historical; the body takes no arguments and returns void.
OUTPUT_NAME_MAP = {
    "CEngineClient_DumpNetStats": "CEngineClient_PrintNetworkSummaryReport",
}

FUNC_XREFS = [
    {
        "func_name": "CEngineClient_DumpNetStats",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CNetworkGameClient_PrintNetStats"],
        "exclude_funcs": ["CL_NET_PrintSummary_CommandHandler"],
        "exclude_strings": [
            "For packet-level statistics, see net_connections_stats.",
        ],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CEngineClient_DumpNetStats", "CEngineClient_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEngineClient_DumpNetStats",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
        output_name_map=OUTPUT_NAME_MAP,
    )

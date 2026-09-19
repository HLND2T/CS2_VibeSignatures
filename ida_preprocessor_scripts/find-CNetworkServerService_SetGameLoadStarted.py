#!/usr/bin/env python3
"""Preprocess script for find-CNetworkServerService_SetGameLoadStarted skill.

``CNetworkServerService::SetGameLoadStarted`` releases the pending changelevel
state: when a network game server is still attached it notifies the server to
stop loading, otherwise it destroys the pending
``CServerChangelevelState`` through ``~CServerChangelevelState``.

The vfunc is only reachable through ``CNetworkServerService_vtable``, so it is
discovered as the caller of the already-known destructor symbol
``CServerChangelevelState_dtor``. Intersecting that caller set with the
``CNetworkServerService_vtable`` entries yields the single target and lets the
preprocessor derive the concrete ``vfunc_offset`` / ``vfunc_index`` from the
vtable itself, so no slot index is hardcoded and Windows/Linux layouts may
differ.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkServerService_SetGameLoadStarted",
]

FUNC_XREFS = [
    {
        "func_name": "CNetworkServerService_SetGameLoadStarted",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CServerChangelevelState_dtor"],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CNetworkServerService_SetGameLoadStarted", "CNetworkServerService_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CNetworkServerService_SetGameLoadStarted",
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
    """Locate SetGameLoadStarted as the CNetworkServerService caller of ~CServerChangelevelState."""
    _ = skill_name
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
    )

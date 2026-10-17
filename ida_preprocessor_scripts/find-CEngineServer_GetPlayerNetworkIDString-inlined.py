#!/usr/bin/env python3
"""Preprocess script for find-CEngineServer_GetPlayerNetworkIDString-inlined skill.

Inline/noinline fallback chain (deinline-fix), inlined link. Covers builds where
CNetworkGameServer::GetPlayerNetworkIDString is inlined into
CEngineServer::GetPlayerNetworkIDString (e.g. Windows 14168): the
CServerSideClientBase_GetNetworkIDString call lives directly inside the CEngineServer
vfunc, so this original xref_funcs + CEngineServer_vtable finder resolves it. On
de-inlined builds (Linux 14168) the anchor call has left the vfunc, so this skill
soft-skips (via skip_if_exists) and find-CEngineServer_GetPlayerNetworkIDString-noinline
resolves the target instead.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEngineServer_GetPlayerNetworkIDString",
]

FUNC_XREFS = [
    {
        "func_name": "CEngineServer_GetPlayerNetworkIDString",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [
            "CServerSideClientBase_GetNetworkIDString",
        ],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CEngineServer_GetPlayerNetworkIDString", "CEngineServer_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEngineServer_GetPlayerNetworkIDString",
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
    """Resolve the inlined wrapper from its current call and vtable membership."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        # Short wrapper signatures can uniquely match a different sibling in a
        # new build. Require the current-version callee instead of reusing one.
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Preprocess script for find-CEngineServer_GetPlayerNetworkIDString-noinline skill.

Inline/noinline fallback chain (deinline-fix), noinline link. Covers builds where
CNetworkGameServer::GetPlayerNetworkIDString is compiled as a standalone function and
CEngineServer::GetPlayerNetworkIDString merely calls it (e.g. Linux 14168): the
CServerSideClientBase_GetNetworkIDString call has moved out of the CEngineServer vfunc,
so the -inlined finder no longer resolves it. Here the target is instead found as the
CEngineServer_vtable entry that calls the (already renamed) standalone helper
CNetworkGameServer_GetPlayerNetworkIDString.

On inlined builds (Windows 14168) CEngineServer::GetPlayerNetworkIDString does not call
the standalone helper, so the xref intersection is empty and this skill soft-skips
(optional_output); find-CEngineServer_GetPlayerNetworkIDString-inlined then resolves the
target. The helper CNetworkGameServer_GetPlayerNetworkIDString is a full standalone
symbol on both platforms (its own finder runs earlier in this late engine pass), so it
is listed in expected_input to guarantee it is renamed in IDA before this script runs.
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
            "CNetworkGameServer_GetPlayerNetworkIDString",
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
    """Resolve the wrapper from its current helper call and vtable membership."""
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

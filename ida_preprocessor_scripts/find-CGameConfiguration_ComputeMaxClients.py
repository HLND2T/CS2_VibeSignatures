#!/usr/bin/env python3
"""Preprocess script for find-CGameConfiguration_ComputeMaxClients skill
(deinline-fix chain, inlined path / Windows).

Resolves ``CGameConfiguration::ComputeMaxClients`` directly from the
``"GetPlayerLimits:  min maxplayers must be >= 1 (%i)"`` string, which is *inlined*
into the vfunc on ``server.dll``.  On ``libserver.so`` the body is de-inlined into
``CGameConfiguration::GetPlayerLimits``, so this skill is scoped to ``platform:
windows`` in ``configs/<GAMEVER>.yaml`` and the Linux side is handled by the
``-deinlined-linux`` / ``-inlined-linux`` chain.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameConfiguration_ComputeMaxClients",
]

FUNC_XREFS = [
    {
        "func_name": "CGameConfiguration_ComputeMaxClients",
        "xref_strings": [
            "GetPlayerLimits:  min maxplayers must be >= 1 (%i)",
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

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CGameConfiguration_ComputeMaxClients", "CGameConfiguration"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CGameConfiguration_ComputeMaxClients",
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
    )

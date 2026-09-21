#!/usr/bin/env python3
"""Preprocess script for find-CGameConfiguration_ComputeMaxClients-inlined-linux
skill (deinline-fix chain, link 3/3).

Resolves ``CGameConfiguration_ComputeMaxClients`` directly from the
``"GetPlayerLimits:  min maxplayers must be >= 1 (%i)"`` string.  This path is
correct whenever ``CGameConfiguration::GetPlayerLimits`` (the body that owns the
player-limits log strings) is *inlined* into the ``ComputeMaxClients`` vfunc -- i.e.
``ComputeMaxClients`` is the single fused function that both holds the strings and
sits in ``CGameConfiguration`` vtable.

When the body is *de-inlined* (``libserver.so``), the strings move out of the vfunc
into the standalone ``CGameConfiguration::GetPlayerLimits``, so this finder would
resolve to ``GetPlayerLimits`` -- which is not a vtable member, so the intersection
collapses to nothing.  In that case ``find-CGameConfiguration_ComputeMaxClients-deinlined-linux``
runs first and produces the correct vfunc address, and this skill is skipped via
``skip_if_exists``.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CGameConfiguration_ComputeMaxClients"]

FUNC_XREFS = [
    {
        "func_name": "CGameConfiguration_ComputeMaxClients",
        "xref_strings": ["GetPlayerLimits:  min maxplayers must be >= 1 (%i)"],
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
    """Find the CGameConfiguration::ComputeMaxClients virtual function (inlined fallback)."""
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

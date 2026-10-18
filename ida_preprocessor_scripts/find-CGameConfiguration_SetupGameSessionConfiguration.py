#!/usr/bin/env python3
"""Preprocess script for find-CGameConfiguration_SetupGameSessionConfiguration skill
(inlined path / Windows).

Resolves the ``CGameConfiguration::SetupGameSessionConfiguration`` vfunc directly
from the ``"GetPlayerLimits:  min maxplayers must be >= 1 (%i)"`` string.  On
``server.dll`` the compiler inlines ``CGameConfiguration::ComputeMaxClients`` into
this vfunc, so the string ends up inside ``SetupGameSessionConfiguration`` and the
vtable intersection identifies it uniquely.

On ``libserver.so`` the max-clients body stays de-inlined, so the same string
selects the standalone non-virtual ``CGameConfiguration::ComputeMaxClients`` and
``find-CGameConfiguration_SetupGameSessionConfiguration-linux`` recovers the vfunc
as its caller.  This skill is therefore scoped to ``platform: windows``.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameConfiguration_SetupGameSessionConfiguration",
]

FUNC_XREFS = [
    {
        "func_name": "CGameConfiguration_SetupGameSessionConfiguration",
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
    ("CGameConfiguration_SetupGameSessionConfiguration", "CGameConfiguration"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CGameConfiguration_SetupGameSessionConfiguration",
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
    """Find CGameConfiguration::SetupGameSessionConfiguration with the max-clients body inlined."""
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

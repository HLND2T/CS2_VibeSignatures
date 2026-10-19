#!/usr/bin/env python3
"""Preprocess script for find-CGameConfiguration_ComputeMaxClients-linux skill
(de-inlined path / Linux).

On ``libserver.so`` the compiler keeps ``CGameConfiguration::ComputeMaxClients`` as
a standalone non-virtual function instead of fusing it into
``CGameConfiguration::SetupGameSessionConfiguration``.  Unlike the latter, it is not
a ``CGameConfiguration`` vtable member, so this finder anchors on the
``"GetPlayerLimits:  min maxplayers must be >= 1 (%i)"`` log string it owns and
emits only function fields (no ``vtable_*`` metadata).

``find-CGameConfiguration_SetupGameSessionConfiguration-linux`` then resolves the
vfunc as this function's vtable-filtered caller.

On ``server.dll`` the body is inlined into the vfunc and the anchor string selects
``SetupGameSessionConfiguration`` instead, so this skill is scoped to
``platform: linux`` and the Windows side uses
``find-CGameConfiguration_SetupGameSessionConfiguration``.
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

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    ("CGameConfiguration_ComputeMaxClients", ["func_name", "func_va", "func_rva", "func_size", "func_sig"]),
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
    """Find the standalone CGameConfiguration::ComputeMaxClients body."""
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

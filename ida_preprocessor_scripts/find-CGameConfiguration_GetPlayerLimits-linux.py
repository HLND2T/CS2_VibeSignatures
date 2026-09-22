#!/usr/bin/env python3
"""Preprocess script for find-CGameConfiguration_GetPlayerLimits-linux skill
(deinline-fix chain, link 1/3).

Resolves the standalone ``CGameConfiguration::GetPlayerLimits`` body that owns the
four ``GetPlayerLimits: ...`` log strings on ``libserver.so``, where the compiler
keeps it out of the ``CGameConfiguration::ComputeMaxClients`` vfunc::

    CGameConfiguration::ComputeMaxClients(this, ...):   ; the vfunc we want
        ... read levelname/savegame/... config keys ...
        CGameConfiguration::GetPlayerLimits(this, ...); ; the de-inlined body
        ...

    CGameConfiguration::GetPlayerLimits(this, ...):     ; the body we want
        ... get min/max/default maxplayers ...
        Log(..., "GetPlayerLimits:  min maxplayers must be >= 1 (%i)"); ; anchor
        ...

``find-CGameConfiguration_ComputeMaxClients-deinlined-linux`` then picks the vfunc
back up as the vtable-filtered caller of this body.

This is an intermediate helper, not a published symbol -- it is deliberately NOT
registered under ``symbols:`` in ``configs/<GAMEVER>.yaml``.

``platform: linux`` scoping (see the ``configs/<GAMEVER>.yaml`` entry): on
``server.dll`` the body is fused into the vfunc, so the anchor string lives inside
``ComputeMaxClients`` itself and this finder would hand ``-deinlined`` the vfunc's
own address as its "callee".  Scoping the helper to Linux keeps Windows on the
proven ``find-CGameConfiguration_ComputeMaxClients`` (inlined) path instead.

``GetPlayerLimits`` is a regular function (not a vfunc), so ``func_sig`` is its only
stable locator and is retained.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CGameConfiguration_GetPlayerLimits"]

FUNC_XREFS = [
    {
        "func_name": "CGameConfiguration_GetPlayerLimits",
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
    ("CGameConfiguration_GetPlayerLimits", ["func_name", "func_va", "func_rva", "func_size", "func_sig"]),
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
    """Find the de-inlined CGameConfiguration::GetPlayerLimits body."""
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

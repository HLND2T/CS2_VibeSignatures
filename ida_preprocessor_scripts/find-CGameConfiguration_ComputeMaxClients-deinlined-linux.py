#!/usr/bin/env python3
"""Preprocess script for find-CGameConfiguration_ComputeMaxClients-deinlined-linux
skill (deinline-fix chain, link 2/3).

Resolves ``CGameConfiguration_ComputeMaxClients`` as the vtable member that calls
the standalone ``CGameConfiguration::GetPlayerLimits`` body.  This path only applies
when the string-owning player-limits body is *de-inlined* out of the vfunc
(``libserver.so``)::

    CGameConfiguration::ComputeMaxClients(this, ...):   ; the vfunc we want
        ... read levelname/savegame/landmarkname/... config keys ...
        CGameConfiguration::GetPlayerLimits(this, ...);
        ...

There the ``"GetPlayerLimits:  min maxplayers must be >= 1 (%i)"`` anchor used by
``find-CGameConfiguration_ComputeMaxClients`` (Windows, inlined) no longer selects the
vfunc -- it selects the standalone body instead.  Two candidate sources are combined:

  * ``xref_funcs: [CGameConfiguration_GetPlayerLimits]`` -- callers of the body.
  * ``FUNC_VTABLE_RELATIONS`` on ``CGameConfiguration`` -- only vtable members
    survive, which drops any non-virtual callers of the body.

On libserver.so 14181 the body has exactly one caller, ``ComputeMaxClients`` itself,
so the intersection resolves to a single vtable member with no string exclusions
required.

On ``server.dll`` the body is fused into the vfunc, so the
``find-CGameConfiguration_GetPlayerLimits`` helper is ``platform: linux`` and does not
run: no ``CGameConfiguration_GetPlayerLimits.windows.yaml`` exists, the ``xref_funcs``
callee cannot be resolved, and this skill legitimately produces nothing
(``optional_output``, so it soft-skips).  ``find-CGameConfiguration_ComputeMaxClients``
then resolves the fused vfunc directly from the anchor string.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CGameConfiguration_ComputeMaxClients"]

FUNC_XREFS = [
    {
        "func_name": "CGameConfiguration_ComputeMaxClients",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CGameConfiguration_GetPlayerLimits"],
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
    """Find the CGameConfiguration::ComputeMaxClients vfunc as the caller of the de-inlined body."""
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

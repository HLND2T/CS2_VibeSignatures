#!/usr/bin/env python3
"""Preprocess script for find-CGameConfiguration_SetupGameSessionConfiguration-linux
skill (de-inlined path / Linux).

Resolves the ``CGameConfiguration::SetupGameSessionConfiguration`` vfunc as the
``CGameConfiguration`` vtable member that calls the standalone non-virtual
``CGameConfiguration::ComputeMaxClients`` body produced by
``find-CGameConfiguration_ComputeMaxClients-linux``.

Two candidate sources are intersected:

  * ``xref_funcs: [CGameConfiguration_ComputeMaxClients]`` -- callers of the body.
  * ``FUNC_VTABLE_RELATIONS`` on ``CGameConfiguration`` -- only vtable members
    survive, which drops any non-virtual callers of the body.

On ``libserver.so`` the body has exactly one caller, the vfunc itself, so the
intersection resolves without string exclusions.

This skill is scoped to ``platform: linux``: on ``server.dll`` the body is inlined
into the vfunc, so there is no ``CGameConfiguration_ComputeMaxClients.windows.yaml``
to use as the ``xref_funcs`` dependency and the Windows side is handled by
``find-CGameConfiguration_SetupGameSessionConfiguration``.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CGameConfiguration_SetupGameSessionConfiguration"]

FUNC_XREFS = [
    {
        "func_name": "CGameConfiguration_SetupGameSessionConfiguration",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CGameConfiguration_ComputeMaxClients"],
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
    """Find the SetupGameSessionConfiguration vfunc as the caller of the de-inlined body."""
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

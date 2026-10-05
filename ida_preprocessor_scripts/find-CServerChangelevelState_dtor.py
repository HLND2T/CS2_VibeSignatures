#!/usr/bin/env python3
"""Preprocess script for find-CServerChangelevelState_dtor skill.

Locates ``CServerChangelevelState::~CServerChangelevelState`` from its unique
changelevel-failure log string. This symbol is not registered as gamedata; it
only serves as the ``xref_funcs`` anchor for
``find-CNetworkServerService_SetGameLoadStarted`` (the vfunc that releases the
changelevel state through this destructor).
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CServerChangelevelState_dtor",
]

FUNC_XREFS = [
    {
        "func_name": "CServerChangelevelState_dtor",
        "xref_strings": [
            "~CServerChangelevelState with non empty m_Clients, failed change level to %s!!!\n",
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

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CServerChangelevelState_dtor",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
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
    """Locate the CServerChangelevelState destructor from its debug string."""
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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

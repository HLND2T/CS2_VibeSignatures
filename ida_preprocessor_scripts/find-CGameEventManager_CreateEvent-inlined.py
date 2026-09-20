#!/usr/bin/env python3
"""Preprocess script for find-CGameEventManager_CreateEvent-inlined skill.

Resolves ``CGameEventManager_CreateEvent`` (a vfunc of ``CGameEventManager_vtable``)
directly from the ``"CreateEvent: event '%s' not registered.\\n"`` debug string reference.
This applies when ``CGameEventManager_CreateEventInternal`` is inlined into
``CGameEventManager_CreateEvent`` so the string lives inside the vfunc body.  It is the
fallback for the ``find-CGameEventManager_CreateEvent-noinline`` path (which handles the
de-inlined case) and is skipped whenever ``CGameEventManager_CreateEvent.{platform}.yaml``
already exists.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameEventManager_CreateEvent",
]

FUNC_XREFS = [
    {
        "func_name": "CGameEventManager_CreateEvent",
        "xref_strings": [
            "FULLMATCH:CreateEvent: event '%s' not registered.\n",
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
    ("CGameEventManager_CreateEvent", "CGameEventManager"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CGameEventManager_CreateEvent",
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

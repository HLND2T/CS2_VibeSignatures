#!/usr/bin/env python3
"""Preprocess script for find-CGameEventManager_CreateEvent-noinline skill.

Resolves ``CGameEventManager_CreateEvent`` (a vfunc of ``CGameEventManager_vtable``)
as the caller of the standalone ``CGameEventManager_CreateEventInternal`` helper.  This
path only applies when the helper is NOT inlined into the vfunc (the de-inlined case,
where ``CGameEventManager_CreateEvent`` merely calls the outlined error-reporting helper
that owns the ``"CreateEvent: event '%s' not registered.\\n"`` string).  When it is
inlined the helper YAML resolves to the vfunc's own address and the ``func_xrefs``
vtable-self fallback re-selects it; either way the ``CGameEventManager`` relation
collapses the caller set to the single vtable member.  Its output is optional, so when
the caller cannot be resolved (e.g. the helper YAML is absent) the
``find-CGameEventManager_CreateEvent-inlined`` fallback runs instead.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameEventManager_CreateEvent",
]

FUNC_XREFS = [
    {
        "func_name": "CGameEventManager_CreateEvent",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [
            "CGameEventManager_CreateEventInternal",
        ],
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

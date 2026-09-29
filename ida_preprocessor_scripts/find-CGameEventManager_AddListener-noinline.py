#!/usr/bin/env python3
"""Preprocess script for find-CGameEventManager_AddListener-noinline skill.

Resolves ``CGameEventManager_AddListener`` (a vfunc of ``CGameEventManager_vtable``) as the
caller of the standalone ``CGameEventManager_AddListenerInternal`` helper.  This path only
applies when the single-listener add helper is NOT inlined into the vfunc, so the vfunc merely
calls the helper after its own descriptor lookup.  When the helper is inlined the helper YAML
resolves to the vfunc's own address and the ``func_xrefs`` vtable-self fallback re-selects it;
either way the ``CGameEventManager_vtable`` relation collapses the caller set to the single
vtable member.  Its output is optional, so when the caller cannot be resolved (e.g. the helper
YAML is absent) the ``find-CGameEventManager_AddListener-inlined`` fallback runs instead.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameEventManager_AddListener",
]

FUNC_XREFS = [
    {
        "func_name": "CGameEventManager_AddListener",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [
            "CGameEventManager_AddListenerInternal",
        ],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CGameEventManager_AddListener", "CGameEventManager"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CGameEventManager_AddListener",
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

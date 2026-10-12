#!/usr/bin/env python3
"""Preprocess script for find-CGameEventManager_LoadEventsFromFileInternal skill.

Resolves the standalone ``CGameEventManager_LoadEventsFromFileInternal`` helper from the
``"Event System loaded %i events from file: %s."`` debug string it owns.

This is the first link of the inline/noinline fallback chain.  On builds where the
single-file load path is de-inlined out of the ``CGameEventManager_LoadEventsFromFile``
vfunc the string lives inside the standalone helper body, so this skill resolves it
directly.  On builds where the helper is inlined into the vfunc the string lives inside
that vfunc instead, so this skill resolves to the vfunc's own address; that is harmless
because the helper symbol is deliberately NOT registered in the active version config and
the YAML is used only as an intermediate for the
``find-CGameEventManager_LoadEventsFromFile-noinline`` xref_funcs lookup (whose
vtable-self fallback then re-selects the same vfunc).  The skill's output is optional and
is skipped whenever ``CGameEventManager_LoadEventsFromFile.{platform}.yaml`` already
exists.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameEventManager_LoadEventsFromFileInternal",
]

FUNC_XREFS = [
    {
        "func_name": "CGameEventManager_LoadEventsFromFileInternal",
        "xref_strings": [
            "Event System loaded %i events from file: %s.",
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
    # (symbol_name, generate_yaml_fields)
    (
        "CGameEventManager_LoadEventsFromFileInternal",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

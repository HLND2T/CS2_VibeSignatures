#!/usr/bin/env python3
"""Preprocess script for find-IVEngineServer2_IsUserIDInUse skill.

IVEngineServer2::IsUserIDInUse is an abstract-interface vfunc with no exported
name, no string anchor, and no signable call site: both platforms dispatch it
through a bare register (``call rbp`` on Windows, ``call rcx`` on Linux), a
2-byte encoding that can never be unique.

Its one stable anchor is that CLagCompensationManager::StartLagCompensation
calls it on the ``g_engine`` singleton. That function is not a thunk, so the
generic indirect-vcall scan cannot be used: it holds three unrelated indirect
vtable calls, and on Linux the slot is spilled to the stack and reloaded across
an intervening call, which defeats a backward walk from the branch. Anchoring on
the ``g_engine`` reference and walking the dereference chain forward resolves
the slot deterministically on both platforms -- see
``preprocess_vcall_on_global_skill``.

The engine-side counterpart CEngineServer_IsUserIDInUse inherits this slot via
INHERIT_VFUNCS, matching the IsDedicatedServer layering.
"""

from ida_preprocessor_scripts._indirect_vcall_target_common import (
    preprocess_vcall_on_global_skill,
)

SOURCE_FUNCTION_NAME = "CLagCompensationManager_StartLagCompensation"
GLOBAL_VARIABLE_NAME = "g_engine"

TARGET_FUNCTION_NAME = "IVEngineServer2_IsUserIDInUse"
VTABLE_CLASS = "IVEngineServer2"

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields) -- slot-only output for an abstract interface vfunc
    (
        "IVEngineServer2_IsUserIDInUse",
        [
            "func_name",
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
    """Resolve the IsUserIDInUse slot from the g_engine vcall in StartLagCompensation."""
    _ = skill_name, old_yaml_map, image_base

    return await preprocess_vcall_on_global_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        source_yaml_stem=SOURCE_FUNCTION_NAME,
        global_yaml_stem=GLOBAL_VARIABLE_NAME,
        target_name=TARGET_FUNCTION_NAME,
        vtable_name=VTABLE_CLASS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

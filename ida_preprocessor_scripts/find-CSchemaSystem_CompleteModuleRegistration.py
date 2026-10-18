#!/usr/bin/env python3
"""Preprocess script for find-CSchemaSystem_CompleteModuleRegistration skill.

``CSchemaSystem::CompleteModuleRegistration(const char *pszModuleName)`` is a
thin vfunc that owns no string, and its prologue embeds a ``m_TypeScopes``
struct offset, so a byte signature would only hold for one build. Every
module's exported ``InstallSchemaBindings`` hands its ``ISchemaSystem *`` to the
schema registration routine (the unique user of ``"unable to register all
schema data: %s\\n"``), which ends by calling
``pSchemaSystem->CompleteModuleRegistration(moduleName)``. The slot is read from
that decompiled vcall -- the only one whose vtable and ``this`` both come from
the routine's first argument -- and the function is taken from the current
CSchemaSystem vtable.
"""

from ida_preprocessor_scripts._vtable_slot_anchor_common import (
    preprocess_receiver_vcall_vfunc_skill,
)

TARGET_FUNCTION_NAME = "CSchemaSystem_CompleteModuleRegistration"
VTABLE_CLASS = "CSchemaSystem"
CALLER_STRING = "unable to register all schema data: %s\n"

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CSchemaSystem_CompleteModuleRegistration",
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
    """Resolve the slot the schema registration routine calls on its ISchemaSystem argument."""
    _ = skill_name, old_yaml_map

    return await preprocess_receiver_vcall_vfunc_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        target_name=TARGET_FUNCTION_NAME,
        vtable_class=VTABLE_CLASS,
        caller_string=CALLER_STRING,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Preprocess script for find-CSchemaSystem_GetClassModuleName skill.

``GetClassModuleName`` and ``GetEnumModuleName`` are ISchemaSystem twins with
byte-identical lookup bodies: Windows folds both slots into one function, Linux
emits two copies that differ only in RIP-relative displacements, so no byte
signature can tell them apart across builds. ``"<No schema binary for
binding>"`` is referenced by exactly that pair of CSchemaSystem slots, and the
interface declares the Class accessor before the Enum accessor, so the target
is the lower of the two slots.
"""

from ida_preprocessor_scripts._vtable_slot_anchor_common import (
    preprocess_string_twin_vfunc_skill,
)

TARGET_FUNCTION_NAME = "CSchemaSystem_GetClassModuleName"
VTABLE_CLASS = "CSchemaSystem"
TWIN_STRING = "<No schema binary for binding>"
# GetClassModuleName + GetEnumModuleName
TWIN_SLOT_COUNT = 2

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CSchemaSystem_GetClassModuleName",
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
    """Resolve the first-declared twin slot referencing the module-name fallback string."""
    _ = skill_name, old_yaml_map

    return await preprocess_string_twin_vfunc_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        target_name=TARGET_FUNCTION_NAME,
        vtable_class=VTABLE_CLASS,
        twin_string=TWIN_STRING,
        expected_slot_count=TWIN_SLOT_COUNT,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

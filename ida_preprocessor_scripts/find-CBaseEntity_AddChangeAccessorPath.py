#!/usr/bin/env python3
"""Preprocess script for find-CBaseEntity_AddChangeAccessorPath skill.

CBaseEntity::AddChangeAccessorPath is the CBaseEntity override of the
CEntityInstance::AddChangeAccessorPath vfunc slot. The base vfunc is already
found (slot-only) by find-CEntityInstance_AddChangeAccessorPath, so this script
inherits that vtable slot index and looks up the same slot in CBaseEntity's
vtable to resolve CBaseEntity's distinct override body and sign it.
"""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    (
        "CBaseEntity_AddChangeAccessorPath",
        "CBaseEntity",
        "CEntityInstance_AddChangeAccessorPath",
        True,
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CBaseEntity_AddChangeAccessorPath",
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
    """Reuse old func_sig first; fallback to vtable index + generated signature when needed."""
    _ = skill_name

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

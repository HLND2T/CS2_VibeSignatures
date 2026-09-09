#!/usr/bin/env python3
"""Preprocess script for find-CBaseEntity_GetChangeAccessorPathInfo_2 skill."""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    # GetChangeAccessorPathInfo_2 is a two-instruction this-adjusting thunk, so a
    # func_sig carries no discriminating bytes.
    ("CBaseEntity_GetChangeAccessorPathInfo_2", "CBaseEntity", "CEntityInstance_GetChangeAccessorPathInfo_2", False),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CBaseEntity_GetChangeAccessorPathInfo_2",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            # "func_sig",// unable to generate unique sig because there is CBaseEntity_GetChangeAccessorPathInfo_1
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

#!/usr/bin/env python3
"""Preprocess script for find-CSource2Server_GetAllServerClasses skill."""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    # GetAllServerClasses is a four-instruction vtable-forwarding thunk, so a
    # func_sig is not stable enough to retain.
    (
        "CSource2Server_GetAllServerClasses",
        "CSource2Server",
        "../engine/ISource2Server_GetAllServerClasses",
        False,
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CSource2Server_GetAllServerClasses",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
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
    """Reuse an old signature or inherit the interface slot into CSource2Server."""
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

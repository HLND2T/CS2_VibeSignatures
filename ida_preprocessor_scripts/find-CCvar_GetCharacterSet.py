#!/usr/bin/env python3
"""Find the CCvar GetCharacterSet vfunc slot."""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    # GetCharacterSet is a two-instruction accessor thunk, so no unique func_sig exists.
    ("CCvar_GetCharacterSet", "CCvar", "ICvar_GetCharacterSet", False),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CCvar_GetCharacterSet",
        ["func_name", "func_va", "func_rva", "func_size", "vtable_name", "vfunc_offset", "vfunc_index"],
    )
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
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

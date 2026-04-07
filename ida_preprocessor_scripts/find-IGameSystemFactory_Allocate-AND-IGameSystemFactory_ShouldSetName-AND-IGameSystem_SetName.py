#!/usr/bin/env python3
"""Preprocess script for find-IGameSystemFactory_Allocate-AND-IGameSystemFactory_HasName-AND-IGameSystem_SetName skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IGameSystemFactory_Allocate",
    "IGameSystemFactory_HasName",
    "IGameSystem_SetName",
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class, generate_vfunc_offset)
    ("IGameSystemFactory_Allocate", "IGameSystemFactory", True),
    ("IGameSystemFactory_HasName", "IGameSystemFactory", True),
    ("IGameSystem_SetName", "IGameSystem", True),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
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
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        debug=debug,
    )

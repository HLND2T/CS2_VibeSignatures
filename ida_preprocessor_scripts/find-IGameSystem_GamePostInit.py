#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_GamePostInit skill."""

from ida_preprocessor_scripts._igamesystem_slot_dispatch_common import (
    preprocess_igamesystem_slot_dispatch_skill,
)

DISPATCHER_YAML_STEM = "IGameSystem_LoopPostInitAllSystems"

TARGET_SPECS = [
    {
        "target_name": "IGameSystem_GamePostInit",
        "vtable_name": "IGameSystem",
        "dispatch_rank": 0,
    },
]

EXPECTED_DISPATCH_COUNT = 1


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
    _ = skill_name
    _ = old_yaml_map
    _ = image_base

    return await preprocess_igamesystem_slot_dispatch_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        dispatcher_yaml_stem=DISPATCHER_YAML_STEM,
        target_specs=TARGET_SPECS,
        multi_order="index",
        expected_dispatch_count=EXPECTED_DISPATCH_COUNT,
        debug=debug,
    )

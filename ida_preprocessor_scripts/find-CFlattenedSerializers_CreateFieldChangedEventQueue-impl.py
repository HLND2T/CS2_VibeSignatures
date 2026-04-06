#!/usr/bin/env python3
"""Preprocess script for find-CFlattenedSerializers_CreateFieldChangedEventQueue-impl skill."""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    (
        "CFlattenedSerializers_CreateFieldChangedEventQueue",
        "CFlattenedSerializers",
        "../server/CFlattenedSerializers_CreateFieldChangedEventQueue",
        True,
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
    _ = skill_name

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        debug=debug,
    )

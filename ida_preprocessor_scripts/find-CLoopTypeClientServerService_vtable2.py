#!/usr/bin/env python3
"""Preprocess script for find-CLoopTypeClientServerService_vtable2 skill."""

from pathlib import Path

from ida_analyze_util import write_vtable_yaml
from ida_preprocessor_scripts._ordinal_vtable_common import (
    preprocess_ordinal_vtable_via_mcp,
)


TARGET_CLASS_NAME = "CLoopTypeClientServerService"
TARGET_OUTPUT_STEM = "CLoopTypeClientServerService_vtable2"
WINDOWS_SYMBOL_ALIASES = ["??_7CLoopTypeClientServerService@@6B@_0"]
LINUX_EXPECTED_OFFSET_TO_TOP = -56


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
    _ = skill_name, old_yaml_map, new_binary_dir

    expected_filename = f"{TARGET_OUTPUT_STEM}.{platform}.yaml"
    matching_outputs = [
        output_path
        for output_path in expected_outputs
        if Path(output_path).name == expected_filename
    ]
    if len(matching_outputs) != 1:
        return False

    if platform == "windows":
        symbol_aliases = WINDOWS_SYMBOL_ALIASES
        expected_offset_to_top = None
    elif platform == "linux":
        symbol_aliases = None
        expected_offset_to_top = LINUX_EXPECTED_OFFSET_TO_TOP
    else:
        return False

    result = await preprocess_ordinal_vtable_via_mcp(
        session=session,
        class_name=TARGET_CLASS_NAME,
        ordinal=0,
        image_base=image_base,
        platform=platform,
        debug=debug,
        symbol_aliases=symbol_aliases,
        expected_offset_to_top=expected_offset_to_top,
    )
    if not result:
        return False

    write_vtable_yaml(matching_outputs[0], result)
    return True

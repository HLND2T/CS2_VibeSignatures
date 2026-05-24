#!/usr/bin/env python3
"""Preprocess script for find-CSource2Server_OnStreamEntitiesFromFileCompleted."""

import os
from pathlib import Path

from ida_analyze_util import preprocess_func_sig_via_mcp, write_func_yaml


TARGET_FUNCTION_NAME = "CSource2Server_OnStreamEntitiesFromFileCompleted"
VTABLE_STEM = "CSource2Server_vtable2"
VFUNC_OFFSET = "0x0"


def _match_output(expected_outputs, platform):
    expected_filename = f"{TARGET_FUNCTION_NAME}.{platform}.yaml"
    matches = [
        output_path
        for output_path in expected_outputs
        if Path(output_path).name == expected_filename
    ]
    return matches[0] if len(matches) == 1 else None


def _old_yaml_path(old_yaml_map, output_path):
    if not old_yaml_map:
        return None
    filename = os.path.basename(output_path)
    return old_yaml_map.get(output_path) or old_yaml_map.get(filename)


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
    output_path = _match_output(expected_outputs, platform)
    if not output_path:
        return False

    result = await preprocess_func_sig_via_mcp(
        session=session,
        new_path=output_path,
        old_path=_old_yaml_path(old_yaml_map, output_path),
        image_base=image_base,
        new_binary_dir=new_binary_dir,
        platform=platform,
        func_name=TARGET_FUNCTION_NAME,
        debug=debug,
        direct_vtable_class=VTABLE_STEM,
        direct_vfunc_offset=VFUNC_OFFSET,
    )
    if not isinstance(result, dict):
        return False

    write_func_yaml(output_path, result)
    return True

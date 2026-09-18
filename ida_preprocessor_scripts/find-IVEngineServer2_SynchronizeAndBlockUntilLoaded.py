#!/usr/bin/env python3
"""Preprocess IVEngineServer2::SynchronizeAndBlockUntilLoaded's interface slot."""

import os

import yaml

from ida_analyze_util import write_func_yaml

PRECEDING_INTERFACE_VFUNC = "IVEngineServer2_MakeSpawnGroupActive"
SLOT_DELTA = 2
TARGET_FUNCTION_NAME = "IVEngineServer2_SynchronizeAndBlockUntilLoaded"
VTABLE_NAME = "IVEngineServer2"


def _read_vfunc_index(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        return int(data["vfunc_index"])
    except (OSError, TypeError, ValueError, KeyError):
        return None


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
    """Advance from MakeSpawnGroupActive across the two adjacent SDK methods."""
    _ = session, skill_name, old_yaml_map, image_base
    source_path = os.path.join(new_binary_dir, f"{PRECEDING_INTERFACE_VFUNC}.{platform}.yaml")
    source_index = _read_vfunc_index(source_path)
    output_name = f"{TARGET_FUNCTION_NAME}.{platform}.yaml"
    output_paths = [path for path in expected_outputs if os.path.basename(path) == output_name]
    if source_index is None or len(output_paths) != 1:
        return False

    target_index = source_index + SLOT_DELTA
    write_func_yaml(
        output_paths[0],
        {
            "func_name": TARGET_FUNCTION_NAME,
            "vtable_name": VTABLE_NAME,
            "vfunc_offset": hex(target_index * 8),
            "vfunc_index": target_index,
        },
    )
    if debug:
        print(
            "    Preprocess: derived "
            f"{TARGET_FUNCTION_NAME} slot {target_index} from "
            f"{PRECEDING_INTERFACE_VFUNC} slot {source_index}"
        )
    return True

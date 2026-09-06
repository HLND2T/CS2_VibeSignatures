#!/usr/bin/env python3
"""Preprocess script for find-CNetworkClientSpawnGroupCreatePrerequisites_Init.

The client spawn-group prerequisite initialization is the unique function that
references BOTH the "%s spawn group prerequisites" debug string and the
g_pGameResourceServiceClient global (the server-side Init and its linux helper
use g_pGameResourceServiceServer instead, so the dual-anchor intersection stays
unique on both platforms).  The gv VA is only known after IDA analysis, so the
xref_gvs entry is built at runtime from the tracked gv YAML.
"""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = [
    "CNetworkClientSpawnGroupCreatePrerequisites_Init",
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkClientSpawnGroupCreatePrerequisites_Init",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]


def _read_gv_va(yaml_path):
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            va = data.get("gv_va")
            if va:
                return str(va)
    except Exception:
        pass
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
    """Find the client Init via the prerequisite string + client service global."""
    _ = skill_name

    gv_yaml_path = os.path.join(new_binary_dir, f"g_pGameResourceServiceClient.{platform}.yaml")
    gv_va = _read_gv_va(gv_yaml_path)
    if not gv_va:
        if debug:
            print("    Preprocess: g_pGameResourceServiceClient gv_va not found, cannot resolve xref_gvs")
        return False

    func_xrefs = [
        {
            "func_name": "CNetworkClientSpawnGroupCreatePrerequisites_Init",
            "xref_strings": ["%s spawn group prerequisites"],
            "xref_gvs": [str(gv_va)],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": [],
        },
    ]

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

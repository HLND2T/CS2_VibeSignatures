#!/usr/bin/env python3
"""Preprocess script for find-CSource2Server_BroadcastServerFrameTime skill."""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = [
    "CSource2Server_BroadcastServerFrameTime",
]

FUNC_VTABLE_RELATIONS = [
    ("CSource2Server_BroadcastServerFrameTime", "CSource2Server_vtable"),
]

# Artifact keys stay stable; emitted names reflect the verified SDK semantics.
OUTPUT_NAME_MAP = {
    "CSource2Server_BroadcastServerFrameTime": "CSource2Server_SendServerFrameTime",
}

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CSource2Server_BroadcastServerFrameTime",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
]


def _read_vtable_va(yaml_path):
    """Read vtable_va from a vtable YAML file, returning it as a hex string or None."""
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            va = data.get("vtable_va")
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
    """Locate CSource2Server::BroadcastServerFrameTime via the message vtable xref."""
    vtable_yaml_path = os.path.join(
        new_binary_dir,
        f"CUserMessageServerFrameTime_t_vtable.{platform}.yaml",
    )
    vtable_va = _read_vtable_va(vtable_yaml_path)
    if not vtable_va:
        if debug:
            print("    Preprocess: CUserMessageServerFrameTime_t_vtable vtable_va not found, cannot resolve xref_gvs")
        return False

    func_xrefs = [
        {
            "func_name": "CSource2Server_BroadcastServerFrameTime",
            "xref_strings": [],
            "xref_gvs": [vtable_va],
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
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
        output_name_map=OUTPUT_NAME_MAP,
    )

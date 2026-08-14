#!/usr/bin/env python3
"""Preprocess script for find-CSource2Server_SetGlobals skill."""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CSource2Server_SetGlobals",
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_artifact)
    ("CSource2Server_SetGlobals", "CSource2Server_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CSource2Server_SetGlobals",
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


def _read_func_va(yaml_path):
    """Read func_va from a function YAML file, returning it as a string or None."""
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            va = data.get("func_va")
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
    """Locate the target vfunc from its warning callback data reference and vtable.

    Both CSource2Server::SetGlobals and CSource2Server::Connect reference the
    GlobalVarsWarningFunc address, so Connect is excluded by its own func_va.
    """
    warning_yaml_path = os.path.join(new_binary_dir, f"GlobalVarsWarningFunc.{platform}.yaml")
    warning_func_va = _read_func_va(warning_yaml_path)
    if not warning_func_va:
        if debug:
            print("    Preprocess: GlobalVarsWarningFunc func_va not found, cannot resolve xref_gvs")
        return False

    func_xrefs = [
        {
            "func_name": "CSource2Server_SetGlobals",
            "xref_strings": [],
            "xref_gvs": [str(warning_func_va)],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": ["CSource2Server_Connect"],
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
    )

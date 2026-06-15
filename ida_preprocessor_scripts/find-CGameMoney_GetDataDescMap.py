#!/usr/bin/env python3
"""Preprocess script for find-CGameMoney_GetDataDescMap skill."""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameMoney_GetDataDescMap",
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CGameMoney_GetDataDescMap", "CGameMoney_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CGameMoney_GetDataDescMap",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
]


def _read_gv_va(yaml_path):
    """Read gv_va from a global variable YAML file, returning it as a string or None."""
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
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    gv_yaml_path = os.path.join(
        new_binary_dir, f"CGameMoney_m_DataMap.{platform}.yaml"
    )
    gv_va = _read_gv_va(gv_yaml_path)
    if not gv_va:
        if debug:
            print(
                "    Preprocess: CGameMoney_m_DataMap gv_va not found, "
                "cannot resolve xref_gvs"
            )
        return False

    func_xrefs = [
        {
            "func_name": "CGameMoney_GetDataDescMap",
            "xref_strings": [],
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
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Preprocess script for find-CCSPlayer_BulletServices_ctor skill.

CCSPlayer_BulletServices_ctor is identified as the function that writes the
CCSPlayer_BulletServices vtable pointer (read from the class-name resolved
vtable artifact). Its destructor(s) write the same vtable and additionally
reset the object vptr to the CPlayerPawnComponent base vtable, so functions
that reference the base vtable are excluded via exclude_gvs. Two base-vtable
addresses are excluded because the reference shape is ABI dependent: MSVC
stores the base address point directly, while the Itanium destructor
materializes the _ZTV base and adds the address-point offset, so IDA records
that xref against the _ZTV base instead of the address point.
"""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CCSPlayer_BulletServices_ctor",
]

# Itanium vtable address point sits this far above the _ZTV symbol base
# (offset-to-top + typeinfo words).
ITANIUM_ADDRESS_POINT_OFFSET = 0x10

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CCSPlayer_BulletServices_ctor",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
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
    """Locate the BulletServices ctor via its vtable write, excluding the base-vtable dtor."""
    vtable_yaml_path = os.path.join(new_binary_dir, f"CCSPlayer_BulletServices_vtable.{platform}.yaml")
    vtable_va = _read_vtable_va(vtable_yaml_path)
    if not vtable_va:
        if debug:
            print("    Preprocess: CCSPlayer_BulletServices_vtable vtable_va not found, cannot resolve xref_gvs")
        return False

    exclude_vtable_yaml_path = os.path.join(new_binary_dir, f"CPlayerPawnComponent_vtable.{platform}.yaml")
    exclude_vtable_va = _read_vtable_va(exclude_vtable_yaml_path)
    if not exclude_vtable_va:
        if debug:
            print("    Preprocess: CPlayerPawnComponent_vtable vtable_va not found, cannot resolve exclude_gvs")
        return False

    exclude_gvs = [str(exclude_vtable_va)]
    try:
        ztv_base = int(str(exclude_vtable_va), 16) - ITANIUM_ADDRESS_POINT_OFFSET
    except (TypeError, ValueError):
        if debug:
            print("    Preprocess: CPlayerPawnComponent_vtable vtable_va is not an integer address")
        return False
    exclude_gvs.append(hex(ztv_base))

    func_xrefs = [
        {
            "func_name": "CCSPlayer_BulletServices_ctor",
            "xref_strings": [],
            "xref_gvs": [str(vtable_va)],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": exclude_gvs,
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

#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_ReleaseKeyValues skill."""

import os
from pathlib import Path

from ida_analyze_util import preprocess_common_skill, preprocess_func_sig_via_mcp, write_func_yaml

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_ReleaseKeyValues",
]

FUNC_XREFS = [
    {
        "func_name": "CEntitySystem_ReleaseKeyValues",
        "xref_strings": [
            "kv 0x%p Release refcount == %d\n",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [
            "kv 0x%p AddRef refcount == %d\n",
        ],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_artifact_stem)
    ("CEntitySystem_ReleaseKeyValues", "CEntitySystem_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEntitySystem_ReleaseKeyValues",
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

VTABLE_STEM = "CEntitySystem_vtable"
VFUNC_OFFSET = "0x40"  # index 8, consistent across platforms


def _match_output(expected_outputs, func_name, platform):
    expected_filename = f"{func_name}.{platform}.yaml"
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
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    result = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    if result:
        return result

    # Fallback: directly look up vtable index 8 (offset 0x40).
    # On Windows, CEntitySystem_ReleaseKeyValues does not directly reference
    # the Release debug string, so the xref approach fails there.
    if debug:
        print(
            "    Preprocess: xref approach failed for CEntitySystem_ReleaseKeyValues; "
            f"falling back to direct vtable lookup at {VTABLE_STEM}[{VFUNC_OFFSET}]"
        )
    output_path = _match_output(expected_outputs, "CEntitySystem_ReleaseKeyValues", platform)
    if not output_path:
        return False

    data = await preprocess_func_sig_via_mcp(
        session=session,
        new_path=output_path,
        old_path=_old_yaml_path(old_yaml_map, output_path),
        image_base=image_base,
        new_binary_dir=new_binary_dir,
        platform=platform,
        func_name="CEntitySystem_ReleaseKeyValues",
        debug=debug,
        direct_vtable_class=VTABLE_STEM,
        direct_vfunc_offset=VFUNC_OFFSET,
    )
    if not isinstance(data, dict):
        return False

    write_func_yaml(output_path, data)
    return True

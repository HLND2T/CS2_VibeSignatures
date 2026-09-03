#!/usr/bin/env python3
"""Preprocess script for find-CVoiceGameMgr_UpdateMasks skill."""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CVoiceGameMgr_UpdateMasks"]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CVoiceGameMgr_UpdateMasks",
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
    try:
        with open(yaml_path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        if isinstance(data, dict):
            value = data.get("vtable_va")
            if value:
                return str(value)
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
    """Find the voice-mask updater by references to its message vtable."""
    _ = skill_name
    vtable_path = os.path.join(new_binary_dir, f"CUserMessageVoiceMask_t_vtable.{platform}.yaml")
    vtable_va = _read_vtable_va(vtable_path)
    if not vtable_va:
        if debug:
            print("    Preprocess: CUserMessageVoiceMask_t vtable_va not found")
        return False

    xref_va = vtable_va if platform == "windows" else hex(int(vtable_va, 16) - 0x10)
    func_xrefs = [
        {
            "func_name": "CVoiceGameMgr_UpdateMasks",
            "xref_strings": [],
            "xref_gvs": [xref_va],
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

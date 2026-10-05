#!/usr/bin/env python3
"""Preprocess script for find-CBaseEntity_SetOwner skill."""

from pathlib import Path

import yaml

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._set_owner_anchor import can_reuse, load_anchors, validate_result

TARGET_FUNCTION_NAMES = [
    "CBaseEntity_SetOwner",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CBaseEntity_SetOwner",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CCSPlayer_WeaponServices_EquipWeapon.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CCSPlayer_WeaponServices_EquipWeapon.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CBaseEntity_SetOwner", "CBaseEntity"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CBaseEntity_SetOwner",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
]


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    """Accept only a live EquipWeapon anchor resolving to the owner-handle setter."""
    try:
        anchors = await load_anchors(session, new_binary_dir, platform, image_base)
        verified_old_map = {}
        for output, old_path in (old_yaml_map or {}).items():
            payload = yaml.safe_load(Path(old_path).read_text(encoding="utf-8"))
            if isinstance(payload, dict) and await can_reuse(session, payload, anchors):
                verified_old_map[output] = old_path
    except Exception as exc:
        if debug:
            print(f"    Preprocess: SetOwner identity verification failed: {exc}")
        return False
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=verified_old_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        llm_result_validator=lambda result: validate_result(result, anchors),
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

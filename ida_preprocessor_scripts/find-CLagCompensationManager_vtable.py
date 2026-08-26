#!/usr/bin/env python3
"""Preprocess script for find-CLagCompensationManager_vtable skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_CLASS_NAMES = ["CLagCompensationManager"]
CANONICAL_VTABLE_SYMBOLS_BY_PLATFORM = {
    "windows": {"CLagCompensationManager": "CLagCompensationManager_vtable"},
    "linux": {"CLagCompensationManager": "_ZTV23CLagCompensationManager + 0x10"},
}

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CLagCompensationManager",
        [
            "vtable_class",
            "vtable_symbol",
            "vtable_va",
            "vtable_rva",
            "vtable_size",
            "vtable_numvfunc",
            "vtable_entries",
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
    debug=False,
):
    """Generate the lag-compensation manager vtable YAML by symbol lookup."""
    _ = skill_name, old_yaml_map
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        vtable_class_names=TARGET_CLASS_NAMES,
        platform=platform,
        image_base=image_base,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        canonical_vtable_symbols=CANONICAL_VTABLE_SYMBOLS_BY_PLATFORM.get(platform),
        debug=debug,
    )

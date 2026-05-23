#!/usr/bin/env python3
"""Preprocess script for find-CGameSystemReallocatingFactory_CSource2EntitySystem_vtable skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_CLASS_NAMES = [
    "CGameSystemReallocatingFactory_CSource2EntitySystem",
]

MANGLED_CLASS_NAMES = {
    "CGameSystemReallocatingFactory_CSource2EntitySystem": [
        "??_7?$CGameSystemReallocatingFactory@VCSource2EntitySystem@@V1@@@6B@",
        "_ZTV30CGameSystemReallocatingFactoryI20CSource2EntitySystemS0_E",
    ],
}


GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CGameSystemReallocatingFactory_CSource2EntitySystem",
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
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Generate CGameSystemReallocatingFactory_CSource2EntitySystem vtable YAML by class-name lookup via MCP."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        vtable_class_names=TARGET_CLASS_NAMES,
        mangled_class_names=MANGLED_CLASS_NAMES,
        platform=platform,
        image_base=image_base,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

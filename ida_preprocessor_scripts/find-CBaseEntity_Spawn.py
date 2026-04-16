#!/usr/bin/env python3
"""Preprocess script for find-CBaseEntity_Spawn skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CBaseEntity_Spawn",
]

FUNC_XREFS = [
                 {
                     "func_name": 'CBaseEntity_Spawn',
                     "xref_strings": ['hammerUniqueId'],
                     "xref_gvs": [],
                     "xref_signatures": ['38 A0 63 A9'],
                     "xref_funcs": [],
                     "exclude_funcs": ['CGameSceneNode_PostSpawnKeyValues', 'CBaseEntity_SpawnRadius'],
                     "exclude_strings": [],
                     "exclude_gvs": [],
                     "exclude_signatures": [],
                 },
             ]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CBaseEntity_Spawn", "CBaseEntity"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CBaseEntity_Spawn",
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

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    return await preprocess_common_skill(
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

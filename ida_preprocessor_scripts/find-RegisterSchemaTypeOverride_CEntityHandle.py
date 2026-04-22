#!/usr/bin/env python3
"""Preprocess script for find-RegisterSchemaTypeOverride_CEntityHandle skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "RegisterSchemaTypeOverride_CEntityHandle",
]

FUNC_XREFS_WINDOWS = [
                 {
                     "func_name": 'RegisterSchemaTypeOverride_CEntityHandle',
                     "xref_strings": ['CEntityHandle', 'ehandle'],
                     "xref_gvs": [],
                     "xref_signatures": ['48 8B ?? 48 FF A0 ?? ?? ?? ??'],
                     "xref_funcs": [],
                     "exclude_funcs": [],
                     "exclude_strings": [],
                     "exclude_gvs": [],
                     "exclude_signatures": [],
                 },
             ]

FUNC_XREFS_LINUX = [
                 {
                     "func_name": 'RegisterSchemaTypeOverride_CEntityHandle',
                     "xref_strings": ['CEntityHandle', 'ehandle'],
                     "xref_gvs": [],
                     "xref_signatures": ['48 8B 80 ?? ?? ?? ?? FF E0'],
                     "xref_funcs": [],
                     "exclude_funcs": [],
                     "exclude_strings": [],
                     "exclude_gvs": [],
                     "exclude_signatures": [],
                 },
             ]

FUNC_VTABLE_RELATIONS = []

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "RegisterSchemaTypeOverride_CEntityHandle",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
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
        func_xrefs=FUNC_XREFS_WINDOWS if platform == "windows" else FUNC_XREFS_LINUX,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

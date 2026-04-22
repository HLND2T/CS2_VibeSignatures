#!/usr/bin/env python3
"""Preprocess script for find-CLoopModeGame_Shutdown-linux skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CLoopModeGame_Shutdown",
]

FUNC_XREFS = [
                 {
                     "func_name": 'CLoopModeGame_Shutdown',
                     "xref_strings": ['--CLoopModeGame::SetWorldSession'],
                     "xref_gvs": [],
                     "xref_signatures": [],
                     "xref_funcs": ['CLoopModeGame_SetGameSystemState'],
                     "exclude_funcs": ['CLoopModeGame_SetWorldSession'],
                     "exclude_strings": ["CLoopModeGame::ReceivedServerInfo restarting loopmode game systems from"],
                     "exclude_gvs": [],
                     "exclude_signatures": [],
                 },
             ]

FUNC_VTABLE_RELATIONS = []


GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CLoopModeGame_Shutdown",
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
        func_xrefs=FUNC_XREFS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

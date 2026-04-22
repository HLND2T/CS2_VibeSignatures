#!/usr/bin/env python3
"""Preprocess script for find-TraceAttack-windows skill.

On Windows, FireBulletImpactEvent is inlined into TraceAttack, so TraceAttack
directly references the "bullet_impact" string.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "TraceAttack",
]

FUNC_XREFS = [
                 {
                     "func_name": 'TraceAttack',
                     "xref_strings": ['bullet_impact'],
                     "xref_gvs": [],
                     "xref_signatures": ["0B 30 1C 00"],
                     "xref_funcs": ['CBaseEntity_TakeDamageOld'],
                     "exclude_funcs": [],
                     "exclude_strings": [],
                     "exclude_gvs": [],
                     "exclude_signatures": [],
                 },
             ]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "TraceAttack",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

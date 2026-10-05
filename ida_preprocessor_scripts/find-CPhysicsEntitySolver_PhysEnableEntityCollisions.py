#!/usr/bin/env python3
"""Preprocess script for find-CPhysicsEntitySolver_PhysEnableEntityCollisions skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CPhysicsEntitySolver_PhysEnableEntityCollisions",
]

FUNC_XREFS = [
    {
        "func_name": "CPhysicsEntitySolver_PhysEnableEntityCollisions",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        # The target is the CPhysicsEntitySolver UpdateOnRemove override: it re-enables the
        # entity pair collisions and then chains to BaseClass::UpdateOnRemove. Since 14182 the
        # PhysEnableEntityCollisions helper is inlined into it (#1065), so it no longer calls
        # that helper; anchor on the base chain call instead, which is the only caller of
        # CBaseEntity_UpdateOnRemove among the CPhysicsEntitySolver vtable entries.
        "xref_funcs": ["CBaseEntity_UpdateOnRemove"],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CPhysicsEntitySolver_PhysEnableEntityCollisions", "CPhysicsEntitySolver"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CPhysicsEntitySolver_PhysEnableEntityCollisions",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
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
    debug=False,
):
    """Reuse previous gamever func_sig to locate target virtual function and write YAML."""
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

#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_AddRefKeyValues skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_AddRefKeyValues",
]

FUNC_XREFS = [
    {
        "func_name": "CEntitySystem_AddRefKeyValues",
        "xref_strings": [
            "kv 0x%p AddRef refcount == %d\n",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        # The true AddRefKeyValues only references the AddRef string; a large spawn-entity
        # function that also appears in the vtable references both AddRef and Release strings.
        "exclude_strings": ["kv 0x%p Release refcount == %d\n"],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # use artifact stem since expected_input has CEntitySystem_vtable.{platform}.yaml
    ("CEntitySystem_AddRefKeyValues", "CEntitySystem_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEntitySystem_AddRefKeyValues",
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

#!/usr/bin/env python3
"""Preprocess script for find-CSchemaSystem_GetClassModuleName skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CSchemaSystem_GetClassModuleName",
]

FUNC_XREFS_WINDOWS = [
    {
        "func_name": "CSchemaSystem_GetClassModuleName",
        "xref_strings": [
            "<No schema binary for binding>",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_XREFS_LINUX = [
    {
        "func_name": "CSchemaSystem_GetClassModuleName",
        "xref_strings": [
            "<No schema binary for binding>",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        # "GetClassModuleName" (idx 22) and "GetEnumModuleName" (idx 24) share
        # this string and have byte-identical lookup bodies. On Windows the two
        # slots are folded to one address, so the string yields a single
        # candidate; on Linux they are separate functions (0x3ae70 / 0x3af10).
        # Exclude the idx-24 copy by its RIP-relative "lea rax, aNoSchemaBinary"
        # displacement, which is the only byte that differs between the two.
        "exclude_signatures": ["48 8D 05 13 AB FF FF"],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CSchemaSystem_GetClassModuleName", "CSchemaSystem"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CSchemaSystem_GetClassModuleName",
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
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
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

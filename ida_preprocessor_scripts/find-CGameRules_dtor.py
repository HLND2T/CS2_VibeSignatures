#!/usr/bin/env python3
"""Preprocess script for find-CGameRules_dtor skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameRules_dtor",
]

# Substring of "%s:  CGameRules::CGameRules destructed\n"; the leading format
# specifier and the trailing newline are omitted so the match stays robust.
XREF_STRINGS = ["CGameRules::CGameRules destructed"]

# On Windows the virtual (deleting) destructor at CGameRules vtable index 20 inlines the
# whole base-object destructor body, so it references the same string. Exclude it by its
# prologue: it saves rbx AND rsi, while the base-object destructor only saves rbx.
#   base dtor : 48 89 5C 24 08 57          (mov [rsp+8], rbx; push rdi)
#   vdtor     : 48 89 5C 24 08 48 89 74 24 10 57
# Linux keeps the two destructors distinct enough that the string xref is already unique.
WINDOWS_EXCLUDE_SIGNATURES = ["48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20"]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # The base-object destructor is registered as `category: func`, so it carries no
    # vfunc fields and needs no FUNC_VTABLE_RELATIONS.
    (
        "CGameRules_dtor",
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
    _ = skill_name

    func_xrefs = [
        {
            "func_name": "CGameRules_dtor",
            "xref_strings": list(XREF_STRINGS),
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": (list(WINDOWS_EXCLUDE_SIGNATURES) if platform == "windows" else []),
        },
    ]

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

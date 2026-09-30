#!/usr/bin/env python3
"""Preprocess script for find-CSchemaSystem_CompleteModuleRegistration skill.

``CSchemaSystem::CompleteModuleRegistration(const char *pszModuleName)`` is a
thin vfunc (ISchemaSystem slot) that resolves the module's type scope from
``m_TypeScopes`` and tail-calls into the scope. It owns no debug string, so it
is anchored by its prologue byte signature. The calling convention differs per
platform, so the prologue (and the ``m_TypeScopes`` offset) is platform-specific:
Windows ``mov rbx, rcx; mov r8, rdx; add rcx, 1A8h`` (offset 0x1A8), Linux
``push rbp; mov rdx, rsi; mov rbx, rdi; lea rsi, [rbx+208h]`` (offset 0x208).
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CSchemaSystem_CompleteModuleRegistration",
]

FUNC_XREFS_WINDOWS = [
    {
        "func_name": "CSchemaSystem_CompleteModuleRegistration",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": ["48 8B D9 4C 8B C2 48 81 C1 A8 01 00 00"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_XREFS_LINUX = [
    {
        "func_name": "CSchemaSystem_CompleteModuleRegistration",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": ["55 48 89 F2 48 89 E5 53 48 89 FB 48 8D B3 08 02 00 00"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CSchemaSystem_CompleteModuleRegistration", "CSchemaSystem"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CSchemaSystem_CompleteModuleRegistration",
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

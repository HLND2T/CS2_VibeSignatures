#!/usr/bin/env python3
"""Preprocess script for find-CCommandLine_CreateCmdLinePrependAppName skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CCommandLine_CreateCmdLinePrependAppName",
]

FUNC_XREFS_WINDOWS = [
    {
        "func_name": "CCommandLine_CreateCmdLinePrependAppName",
        "xref_strings": [
            "%s: Unable to get executable filename (%d byte buffer).",
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
        "func_name": "CCommandLine_CreateCmdLinePrependAppName",
        # The Windows error string above is Windows-only; libtier0.so has no
        # string xref into this vfunc. Anchor it by its unique VPROF prologue
        # (mov rax, 0C00000C800000000h; push rbp; mov rbp,rsp; push r14;
        # push r13; lea r13,[rbp-0F0h]) -- verified to match exactly one
        # function (vtable slot 2 = 0x151200) in libtier0.so.
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [
            "48 B8 00 00 00 00 C8 00 00 C0 55 48 89 E5 41 56 41 55 4C 8D AD 10 FF FF FF",
        ],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CCommandLine_CreateCmdLinePrependAppName", "CCommandLine"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CCommandLine_CreateCmdLinePrependAppName",
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

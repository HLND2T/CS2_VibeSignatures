#!/usr/bin/env python3
"""Preprocess script for find-CKeyValuesSystem_dtor skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CKeyValuesSystem_dtor",
]

FUNC_XREFS = [
    {
        "func_name": "CKeyValuesSystem_dtor",
        "xref_strings": [
            "Leaked KeyValues blocks: %d\n",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        # 0x1802EC310 is a leak-report helper (loads the global KeyValuesSystem,
        # writes the vtable to a different global, DevMsg the leak count); the
        # real ~CKeyValuesSystem() dtor writes the vtable to [rcx]. Exclude the
        # helper by its push-based prologue (push rbx; sub rsp,20h; mov rbx,[rip+disp]).
        "exclude_signatures": ["53 48 83 EC 20 48 8B 1D ?? ?? ?? ??"],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CKeyValuesSystem_dtor",
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

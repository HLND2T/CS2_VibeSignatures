#!/usr/bin/env python3
"""Preprocess script for find-CBaseFilter_InputTestActivator skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CBaseFilter_InputTestActivator",
]

FUNC_XREFS_LINUX = [
    {
        "func_name": "CBaseFilter_InputTestActivator",
        "xref_strings": [],
        "xref_gvs": [],
        # Legacy CBaseFilter::InputTestActivator body. Entity inputs moved to `_API`
        # registration in 14182 (issue #1061), so the registration descriptor and the
        # bare "TestActivator" string no longer reach this symbol; the `_API` wrapper
        # (find-CBaseFilter_API_TestActivator) forwards to it instead. Signature comes
        # from CS2Fixes' maintained entry of the same name.
        "xref_signatures": ["55 48 89 E5 41 55 41 54 49 89 F4 53 48 89 FB 48 81 EC ? ? ? ? 48 8B 07 48 8B 16"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CBaseFilter_InputTestActivator",
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
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    """Locate the legacy CBaseFilter::InputTestActivator body; Linux only, MSVC inlines it on Windows."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS_LINUX,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

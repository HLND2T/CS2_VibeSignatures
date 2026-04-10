#!/usr/bin/env python3
"""Preprocess script for find-CNetworkMessages_GetNetworkGroupCount-AND-CNetworkMessages_GetNetworkGroupName-AND-CNetworkMessages_GetNetworkGroupColor skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkMessages_GetNetworkGroupCount",
    "CNetworkMessages_GetNetworkGroupName",
    "CNetworkMessages_GetNetworkGroupColor",
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CNetworkMessages_GetNetworkGroupCount", "CNetworkMessages"),
    ("CNetworkMessages_GetNetworkGroupName", "CNetworkMessages"),
    ("CNetworkMessages_GetNetworkGroupColor", "CNetworkMessages"),
]


GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CNetworkMessages_GetNetworkGroupCount",
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
    (
        "CNetworkMessages_GetNetworkGroupName",
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
    (
        "CNetworkMessages_GetNetworkGroupColor",
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
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

#!/usr/bin/env python3
"""Preprocess script for find-CNetworkSystem_GetSteamUserNetworkingSockets skill."""

from ida_analyze_util import preprocess_common_skill

# On Windows the getter is an 8-byte ``mov rax, cs:qword; ret`` thunk whose
# RIP-relative displacement is byte-identical to its sibling
# GetSteamNetworkingSockets slot, so no local byte signature can be unique:
# resolve that platform by inherited slot only. Linux keeps the full field set,
# where the displacement still yields a unique signature.
INHERIT_VFUNCS_BY_PLATFORM = {
    "windows": [
        # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
        (
            "CNetworkSystem_GetSteamUserNetworkingSockets",
            "CNetworkSystem",
            "../engine/INetworkSystem_GetSteamUserNetworkingSockets",
            False,
        )
    ],
    "linux": [
        (
            "CNetworkSystem_GetSteamUserNetworkingSockets",
            "CNetworkSystem",
            "../engine/INetworkSystem_GetSteamUserNetworkingSockets",
            True,
        )
    ],
}

_SLOT_ONLY_FIELDS = [
    "func_name",
    "vtable_name",
    "vfunc_offset",
    "vfunc_index",
]
_FULL_FIELDS = [
    "func_name",
    "func_va",
    "func_rva",
    "func_size",
    "func_sig",
    "vtable_name",
    "vfunc_offset",
    "vfunc_index",
]

GENERATE_YAML_DESIRED_FIELDS_BY_PLATFORM = {
    "windows": [("CNetworkSystem_GetSteamUserNetworkingSockets", _SLOT_ONLY_FIELDS)],
    "linux": [("CNetworkSystem_GetSteamUserNetworkingSockets", _FULL_FIELDS)],
}


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
    """Reuse the old vfunc slot; fall back to inheriting the slot from INetworkSystem."""
    _ = skill_name
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS_BY_PLATFORM.get(platform, INHERIT_VFUNCS_BY_PLATFORM["windows"]),
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS_BY_PLATFORM.get(
            platform, GENERATE_YAML_DESIRED_FIELDS_BY_PLATFORM["windows"]
        ),
        debug=debug,
    )

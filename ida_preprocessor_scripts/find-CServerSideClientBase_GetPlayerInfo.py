#!/usr/bin/env python3
"""Preprocess script for find-CServerSideClientBase_GetPlayerInfo skill.

Resolves the vfunc behind the historical ``CServerSideClientBase_GetPlayerInfo``
artifact key, which the SDK declares as ``CServerSideClientBase::Create``, from the
exact ``"userinfo"`` string reference. Slot 9 clears the client, applies the SteamID
and name without connecting, and returns its slot; the real ``GetPlayerInfo`` is the
sibling ``return this + 400`` accessor at slot 54.

Its vtable-mate ``CServerSideClientBase_Connect`` also references ``"userinfo"``, so
the ``"CServerSideClientBase::Connect"`` string is excluded to keep only ``Create``.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CServerSideClientBase_GetPlayerInfo",
]

# The artifact key is historical: slot 9 clears the client, applies the SteamID
# and name without connecting, then returns its slot, which the SDK declares as
# Create. The real GetPlayerInfo is the sibling "return this + 400" accessor.
OUTPUT_NAME_MAP = {
    "CServerSideClientBase_GetPlayerInfo": "CServerSideClientBase_Create",
}

FUNC_XREFS = [
    {
        "func_name": "CServerSideClientBase_GetPlayerInfo",
        "xref_strings": [
            "FULLMATCH:userinfo",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [
            "CServerSideClientBase::Connect",
        ],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

# CServerSideClientBase_GetPlayerInfo is a vfunc of CServerSideClientBase
FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CServerSideClientBase_GetPlayerInfo", "CServerSideClientBase_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CServerSideClientBase_GetPlayerInfo",
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
        func_xrefs=FUNC_XREFS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
        output_name_map=OUTPUT_NAME_MAP,
    )

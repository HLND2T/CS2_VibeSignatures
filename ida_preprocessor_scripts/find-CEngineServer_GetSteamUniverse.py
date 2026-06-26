#!/usr/bin/env python3
"""Preprocess script for find-CEngineServer_GetSteamUniverse skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEngineServer_GetSteamUniverse",
]

FUNC_XREFS = [
    {
        "func_name": "CEngineServer_GetSteamUniverse",
        "xref_strings": [
            "Steam Universe is invalid, possibly asking before Steam was successfully initialized",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        # 6 functions reference both Universe strings; exclude the other 5 by prologue bytes.
        # sub_1800626F0 (0x176): 48 83 EC 48 ...  (sub esp,48h vs our sub esp,28h)
        # sub_1800848D0 (0x24c): 40 55 41 54 ...  (push r12/r13/r14/r15 prologue)
        # sub_18006C280 (0x8fd), sub_1800B3170 (0xd69),
        # CServerSideClientBase_ProcessClientInfo: all start 48 89 5C 24 ??
        "exclude_signatures": ["48 83 EC 48", "40 55 41 54", "48 89 5C 24 ??"],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CEngineServer_GetSteamUniverse", "CEngineServer_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEngineServer_GetSteamUniverse",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "vfunc_sig",
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

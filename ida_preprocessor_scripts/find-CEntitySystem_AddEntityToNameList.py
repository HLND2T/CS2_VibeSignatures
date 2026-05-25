#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_AddEntityToNameList skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_AddEntityToNameList",
]

# Windows: identified by the CUtlRBTree template type string that only exists in
# the Windows PDB/debug string table.
FUNC_XREFS_WINDOWS = [
    {
        "func_name": "CEntitySystem_AddEntityToNameList",
        "xref_strings": [
            "CUtlRBTree<struct CUtlOrderedMapBase<class CUtlSymbolLarge,class CEntityNameList *,class CDefLess<class CU",
        ],
        "xref_gvs": [], "xref_signatures": [], "xref_funcs": [],
        "exclude_funcs": [], "exclude_strings": [], "exclude_gvs": [], "exclude_signatures": [],
    },
]

# Linux: the CUtlRBTree type string and CEntityNameList strings are absent in the Linux
# binary.  The common assertion strings "!link" and "Found existing value when inserting..."
# each appear in ~148 functions -- too many to be unique.
# Instead, identify by xref_funcs: this function is a direct callee of
# CEntityIdentity_SetEntityName (which IS reliably tracked in the YAML database).
# Among all callees of CEntityIdentity_SetEntityName, this is the only one that
# allocates 32 bytes (new CEntityNameList) and calls CUtlRBTree helpers internally.
FUNC_XREFS_LINUX = [
    {
        "func_name": "CEntitySystem_AddEntityToNameList",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [
            "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC ??",  # prologue: push rbp; mov rbp,rsp; push r15..r12,rbx; sub rsp,N
        ],
        "xref_funcs": [
            "CEntityIdentity_SetEntityName",
        ],
        "exclude_funcs": [], "exclude_strings": [], "exclude_gvs": [], "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEntitySystem_AddEntityToNameList",
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
        func_xrefs=FUNC_XREFS_WINDOWS if platform == "windows" else FUNC_XREFS_LINUX,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

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

# Linux: the CUtlRBTree template type string is absent in the Linux binary.
# The assertion string "Found existing value when inserting..." appears in ~148 functions,
# but is needed to build the initial candidate set.
# Narrow with xref_signatures: the prologue ends with `mov r14, [rsi+18h]` (4C 8B 76 18)
# which reads the entity name from CEntityIdentity->m_iszEntityName -- unique to
# functions taking a CEntityIdentity* in rsi as the second argument.
FUNC_XREFS_LINUX = [
    {
        "func_name": "CEntitySystem_AddEntityToNameList",
        "xref_strings": [
            "Found existing value when inserting into tree",
        ],
        "xref_gvs": [],
        "xref_signatures": [
            "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC ?? 4C 8B 76 18",  # prologue + mov r14,[rsi+18h]
        ],
        "xref_funcs": [],
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
#!/usr/bin/env python3
from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CNetChan_SendMessages"]
FUNC_XREFS = [
    {
        "func_name": "CNetChan_SendMessages",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CNetChan_SendMessages_Internal"],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]

FUNC_XREFS_WINDOWS = [
    {
        **FUNC_XREFS[0],
        "exclude_signatures": [
            "48 89 6C 24 ?? 56 57 41 56 48 83 EC ?? 80 B9 ?? 70 00 00 ??",
        ],
    }
]

FUNC_XREFS_LINUX = [
    {
        **FUNC_XREFS[0],
        "exclude_signatures": [
            "55 48 89 E5 41 56 49 89 F6 41 55 41 54 53 48 89 FB 48 83 EC ?? 80 BF ?? 70 00 00 ??",
        ],
    }
]
FUNC_VTABLE_RELATIONS = [("CNetChan_SendMessages", "CNetChan")]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetChan_SendMessages",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "vtable_name", "vfunc_offset", "vfunc_index"],
    )
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=(FUNC_XREFS_WINDOWS if platform == "windows" else FUNC_XREFS_LINUX),
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

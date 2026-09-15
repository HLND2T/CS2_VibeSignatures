#!/usr/bin/env python3
"""Find GetPrerequisiteStatus from the asset-load timing diagnostic."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CNetworkServerSpawnGroup_WaitForAssetLoadPrerequisite_GetPrerequisiteStatus"]

FUNC_XREFS = [{
    "func_name": "CNetworkServerSpawnGroup_WaitForAssetLoadPrerequisite_GetPrerequisiteStatus",
    "xref_strings": [
        "%s:  CNetworkServerSpawnGroup_WaitForAssetLoadPrerequisite %s [took %.3f msec]...",
    ],
    "xref_gvs": [], "xref_signatures": [], "xref_funcs": [],
    "exclude_funcs": [], "exclude_strings": [], "exclude_gvs": [], "exclude_signatures": [],
}]

FUNC_VTABLE_RELATIONS = [
    (
        "CNetworkServerSpawnGroup_WaitForAssetLoadPrerequisite_GetPrerequisiteStatus",
        "CNetworkServerSpawnGroup_WaitForAssetLoadPrerequisite_vtable",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkServerSpawnGroup_WaitForAssetLoadPrerequisite_GetPrerequisiteStatus",
        [
            "func_name", "func_va", "func_rva", "func_size", "func_sig",
            "vtable_name", "vfunc_offset", "vfunc_index",
        ],
    ),
]


async def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map,
                           new_binary_dir, platform, image_base, debug=False):
    """Reuse an old signature, then use the diagnostic-string xref."""
    return await preprocess_common_skill(
        session=session, expected_outputs=expected_outputs, old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir, platform=platform, image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES, func_xrefs=FUNC_XREFS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS, debug=debug,
    )

#!/usr/bin/env python3
"""Locate the server nav-mesh availability query used by CounterStrikeSharp.

CSS calls CSource2Server::GetNavMeshData ``CCSNavArea_IsValidNavMesh``. Find
its boolean null check of g_pNavMesh inside the server vtable. Preserve the
artifact key while emitting the SDK method name for ABI reference validation.
"""

import os

import yaml

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CSource2Server_IsValidNavMesh"]
FUNC_VTABLE_RELATIONS = [("CSource2Server_IsValidNavMesh", "CSource2Server_vtable")]

OUTPUT_NAME_MAP = {
    "CSource2Server_IsValidNavMesh": "CSource2Server_GetNavMeshData",
}

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CSource2Server_IsValidNavMesh",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            # The Windows body is only 12 bytes and its wildcarded null check
            # also occurs outside this vtable. Signing needs adjacent bytes.
            "func_sig_allow_across_function_boundary:true",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
]

NULL_CHECK_SIGNATURES = {
    "windows": "48 83 3D ?? ?? ?? ?? 00 0F 95 C0 C3",
    "linux": "48 8D 05 ?? ?? ?? ?? 48 83 38 00 0F 95 C0 C3",
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
    """Intersect the nav global reference, boolean query, and server vtable."""
    nav_path = os.path.join(new_binary_dir, f"g_pNavMesh.{platform}.yaml")
    with open(nav_path, "r", encoding="utf-8") as stream:
        nav_data = yaml.safe_load(stream)
    if not isinstance(nav_data, dict) or not nav_data.get("gv_va"):
        return False

    func_xrefs = [
        {
            "func_name": TARGET_FUNCTION_NAMES[0],
            "xref_strings": [],
            "xref_gvs": [str(nav_data["gv_va"])],
            "xref_signatures": [NULL_CHECK_SIGNATURES[platform]],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": [],
        },
    ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        output_name_map=OUTPUT_NAME_MAP,
        debug=debug,
    )

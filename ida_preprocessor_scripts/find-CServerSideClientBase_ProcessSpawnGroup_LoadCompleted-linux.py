#!/usr/bin/env python3
"""Preprocess script for find-CServerSideClientBase_ProcessSpawnGroup_LoadCompleted-linux skill."""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CServerSideClientBase_ProcessSpawnGroup_LoadCompleted",
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CServerSideClientBase_ProcessSpawnGroup_LoadCompleted", "CServerSideClientBase"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CServerSideClientBase_ProcessSpawnGroup_LoadCompleted",
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


def _read_vtable_va(yaml_path):
    """Read vtable_va from a vtable YAML file, returning it as a hex string or None."""
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            va = data.get("vtable_va")
            if va:
                return str(va)
    except Exception:
        pass
    return None


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    # The MarkSpawnGroupLoadCompleted helper is inlined on Linux, so the xref string
    # appears in ProcessSpawnGroup_LoadCompleted itself -- but also in
    # CNETMsg_SpawnGroup_LoadCompleted_t::MergeFrom (the protobuf message ctor),
    # so exclude functions that reference that vtable.
    exclude_vtable_yaml_path = os.path.join(
        new_binary_dir, f"CNETMsg_SpawnGroup_LoadCompleted_t_vtable.{platform}.yaml"
    )
    exclude_vtable_va = _read_vtable_va(exclude_vtable_yaml_path)
    if not exclude_vtable_va:
        if debug:
            print(
                "    Preprocess: CNETMsg_SpawnGroup_LoadCompleted_t_vtable vtable_va not "
                "found, cannot resolve exclude_gvs"
            )
        return False

    func_xrefs = [
        {
            "func_name": "CServerSideClientBase_ProcessSpawnGroup_LoadCompleted",
            "xref_strings": [
                "WARNING: Received SpawnGroup_LoadCompleted for an unknown spawngrouphandle(%s) from client '%s'",
            ],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [str(exclude_vtable_va)],
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
        debug=debug,
    )

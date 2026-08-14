#!/usr/bin/env python3
"""Preprocess script for find-CEntityInstance_dtor skill."""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntityInstance_dtor",
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEntityInstance_dtor",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
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
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML.

    The "kv 0x%p Release refcount == %d\n" logging string is inlined into ~91
    functions (via CEntitySystem_ReleaseKeyValues), so it cannot uniquely locate
    the destructor on its own. The base-object destructor also writes the
    CEntityInstance vtable pointer, so intersecting the string xref with an
    xref to CEntityInstance_vtable narrows the result to the destructor. This
    mirrors the sibling find-CBaseEntity_dtor, which also anchors on its vtable.
    """
    vtable_yaml_path = os.path.join(new_binary_dir, f"CEntityInstance_vtable.{platform}.yaml")
    vtable_va = _read_vtable_va(vtable_yaml_path)
    if not vtable_va:
        if debug:
            print("    Preprocess: CEntityInstance_vtable vtable_va not found, cannot resolve xref_gvs")
        return False

    # The CEntityInstance destructor writes the vtable pointer directly
    # (`lea rax, CEntityInstance_vtable; mov [rcx], rax`), so the vtable's own
    # VA is the data reference on both platforms (unlike CBaseEntity, whose
    # Linux dtor references the _ZTV base).
    xref_va = vtable_va

    # The "kv 0x%p Release refcount == %d\n" log string is inlined into ~90
    # functions (via CEntitySystem_ReleaseKeyValues), so intersect it with a
    # reference to the CEntityInstance vtable to isolate the destructors. That
    # intersection still contains the *deleting* destructor (the vtable slot 4
    # entry on Windows / slot 5 D0 on Linux), which the prior failed attempt
    # wrongly picked. Exclude it by its self-delete signature so only the
    # base-object destructor remains, mirroring find-CBaseEntity_dtor.
    #   Windows: scalar-deleting dtor tests the deleting flag then
    #            `operator delete(this, 0x30)`: test sil,1 / jz / mov edx,48 /
    #            mov rcx,rbx.
    #   Linux:   D0 deleting dtor makes a `call [rax+0A8h]` virtual call before
    #            tail-calling operator delete on `this`; the complete-object
    #            destructor (D1, slot 4) instead ends in `jmp rax`.
    if platform == "windows":
        exclude_signatures = ["40 F6 C6 01 74 ?? BA 30 00 00 00 48 8B CB"]
    else:
        exclude_signatures = ["FF 90 A8 00 00 00"]

    func_xrefs = [
        {
            "func_name": "CEntityInstance_dtor",
            "xref_strings": ["kv 0x%p Release refcount == %d\n"],
            "xref_gvs": [xref_va],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": ["CEntityInstance_UpdateOnRemove"],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": exclude_signatures,
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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

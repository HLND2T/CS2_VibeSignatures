#!/usr/bin/env python3
"""Preprocess script for find-CNetworkSystem_CloseSocket.

The interface slot is recovered by find-INetworkSystem_CloseSocket in the
engine module (the INetworkSystem interface callers live in engine2.dll);
this skill inherits that slot index and resolves the concrete override in
the CNetworkSystem vtable inside networksystem.dll.

This replaces the previous CloseSocketInternal / -deinlined / -inlined
fallback chain: the string-owning teardown body is fused into the vfunc on
networksystem.dll but de-inlined into a standalone helper on
libnetworksystem.so, which used to break the string anchor. Slot
inheritance does not depend on the function body's inline state at all,
so a single finder now covers both platforms and both inline topologies.

``func_sig`` is intentionally omitted so the CloseSocket output keeps the
same shape the old chain produced: the de-inlined vfunc is a small
bounds-check forwarder whose head bytes differ from the large fused body,
so the vtable slot (``vfunc_offset`` / ``vfunc_index``) is the stable
locator instead.
"""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    (
        "CNetworkSystem_CloseSocket",
        "CNetworkSystem",
        "../engine/INetworkSystem_CloseSocket",
        False,
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkSystem_CloseSocket",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
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
    """Inherit the CloseSocket slot from INetworkSystem (engine module)."""
    _ = skill_name
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

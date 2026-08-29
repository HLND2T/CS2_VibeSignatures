#!/usr/bin/env python3
"""Preprocess script for find-CNetworkSystem_CloseSocket-inlined skill (deinline-fix chain, link 3/3).

Resolves ``CNetworkSystem_CloseSocket`` directly from the
``"Closing '%s' UDP listen socket"`` teardown string.  This path is correct whenever
``CNetworkSystem::CloseSocketInternal`` (the body that owns the four teardown strings)
is *inlined* into the ``CloseSocket`` vfunc -- i.e. ``CloseSocket`` is the single fused
function that both holds the strings and sits in ``CNetworkSystem_vtable``
(``networksystem.dll`` on all observed builds)::

    CNetworkSystem::CloseSocket(this, nSocket):        ; the fused vfunc
        if (nSocket < 0 || nSocket >= this->m_nSockets) return false;
        ...
        LoggingSystem_Log(..., "Closing '%s' UDP listen socket\\n");   ; <- the anchor
        LoggingSystem_Log(..., "Closing '%s' P2P listen socket\\n");
        LoggingSystem_Log(..., "Closing '%s' SDR listen socket\\n");
        LoggingSystem_Log(..., "Closing '%s' poll group\\n");
        return true;

``CNetworkSystem::CloseAllSockets`` inlines the same teardown block, so it also xrefs the
anchor string; ``exclude_strings: ["CNetworkSystem::CloseAllSockets()"]`` drops it via its
own VProf string, and the ``CNetworkSystem_vtable`` intersection pins the rest.

When the body is *de-inlined* (``libnetworksystem.so``), the strings move out of the vfunc
into the standalone ``CNetworkSystem_CloseSocketInternal`` and the vfunc degrades to a thin
bounds-check forwarder, so this finder would resolve to ``CloseSocketInternal`` -- which is
not a vtable member, so the intersection collapses to nothing.  In that case
``find-CNetworkSystem_CloseSocket-deinlined`` runs first and produces the correct vfunc
address, and this skill is skipped via ``skip_if_exists``.

``func_sig`` is intentionally omitted so the ``CloseSocket`` output has an identical shape
regardless of inline state: on the de-inlined build the vfunc is a small bounds-check
forwarder whose head bytes differ from the large fused body, so the vtable slot
(``vfunc_offset`` / ``vfunc_index``) is the stable locator instead.  The ``-deinlined``
path drops ``func_sig`` too.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CNetworkSystem_CloseSocket"]

FUNC_XREFS = [
    {
        "func_name": "CNetworkSystem_CloseSocket",
        "xref_strings": ["Closing '%s' UDP listen socket"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": ["CNetworkSystem::CloseAllSockets()"],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [("CNetworkSystem_CloseSocket", "CNetworkSystem_vtable")]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # NOTE: func_sig is intentionally omitted to match the -deinlined path.  Although the
    # fused vfunc body is large enough to sign, the de-inlined vfunc is a thin bounds-check
    # forwarder whose head bytes differ; dropping func_sig on both paths keeps the symbol's
    # output shape identical regardless of inline state.  The vtable slot (vfunc_offset /
    # vfunc_index) is the stable locator.
    (
        "CNetworkSystem_CloseSocket",
        ["func_name", "func_va", "func_rva", "func_size", "vtable_name", "vfunc_offset", "vfunc_index"],
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    """Find the CNetworkSystem::CloseSocket virtual function."""
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

#!/usr/bin/env python3
"""Preprocess script for find-CNetworkSystem_CloseSocket-deinlined skill (deinline-fix chain, link 2/3).

Resolves ``CNetworkSystem_CloseSocket`` as the thin bounds-check wrapper that forwards into
the standalone ``CNetworkSystem_CloseSocketInternal``.  This path only applies when the
string-owning teardown body is *de-inlined* out of the vfunc (``libnetworksystem.so``)::

    CNetworkSystem::CloseSocket(this, nSocket):            ; the vfunc we want
        if (nSocket < 0 || nSocket >= this->m_nSockets) return false;
        CNetworkSystem::CloseSocketInternal(this, nSocket);
        return true;

There the vfunc holds no strings at all, so the ``"Closing '%s' UDP listen socket"`` anchor
used by ``find-CNetworkSystem_CloseSocket-inlined`` no longer selects it.  Two candidate
sources are combined instead:
  * ``xref_funcs: [CNetworkSystem_CloseSocketInternal]`` -- callers of the de-inlined body.
  * ``FUNC_VTABLE_RELATIONS`` on ``CNetworkSystem_vtable`` -- only vtable members survive,
    which drops non-virtual callers of the body.

On libnetworksystem.so 14178 that intersection is six ``CNetworkSystem`` vtable members, all
of which log while ``CloseSocket`` itself references no string at all, so each collider is
removed through a string it owns -- deliberately the *same* literal its own finder anchors
on, so an upstream string change breaks (and gets fixed) in one place:

    idx  4  CNetworkSystem::Shutdown                      "CNetworkSystem::CloseAllSockets()"
    idx 12  CNetworkSystem::ShutdownGameServer            "CNetworkSystem::ShutdownGameServer"
    idx 15  CNetworkSystem::ConnectSocket                 "Reusing cacheable shared Steam Net
                                                           Connection to '%s'"
    idx 17  CNetworkSystem::CloseSocket                   (no strings)  <- the target
    idx 18  CNetworkSystem::EnableLoopbackBetweenSockets  "Can't ConnectLoopback between
                                                           socket %d and %d, not enough slots"
    idx 38  CNetworkSystem::CloseAllSockets               "CNetworkSystem::CloseAllSockets()"

On ``networksystem.dll`` the body is fused into the vfunc, so the
``find-CNetworkSystem_CloseSocketInternal`` helper is ``platform: linux`` and does not run:
no ``CNetworkSystem_CloseSocketInternal.windows.yaml`` exists, the ``xref_funcs`` callee
cannot be resolved, and this skill legitimately produces nothing (``optional_output``, so it
soft-skips).  ``find-CNetworkSystem_CloseSocket-inlined`` then resolves the fused vfunc
directly from the anchor string.

``func_sig`` is intentionally omitted so the ``CloseSocket`` output has an identical shape
regardless of inline state: the de-inlined vfunc is a small bounds-check forwarder whose head
bytes differ from the large fused body, so the vtable slot (``vfunc_offset`` /
``vfunc_index``) is the stable locator instead.  The ``-inlined`` fallback drops ``func_sig``
too.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CNetworkSystem_CloseSocket"]

FUNC_XREFS = [
    {
        "func_name": "CNetworkSystem_CloseSocket",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CNetworkSystem_CloseSocketInternal"],
        "exclude_funcs": [],
        "exclude_strings": [
            # Every other CNetworkSystem vtable member that calls CloseSocketInternal logs;
            # CloseSocket itself owns no string.  Each literal is the anchor its own finder
            # uses (find-CNetworkSystem_ShutdownGameServer / -ConnectSocket /
            # -EnableLoopbackBetweenSockets), so a string change breaks in one place only.
            "CNetworkSystem::CloseAllSockets()",  # CloseAllSockets + Shutdown
            "CNetworkSystem::ShutdownGameServer",
            "Reusing cacheable shared Steam Net Connection to '%s'",  # ConnectSocket
            "Can't ConnectLoopback between socket %d and %d, not enough slots",  # EnableLoopbackBetweenSockets
        ],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [("CNetworkSystem_CloseSocket", "CNetworkSystem_vtable")]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # NOTE: func_sig is intentionally omitted so the CloseSocket vfunc output has an
    # identical shape regardless of inline state.  On this de-inlined build the vfunc body
    # is a small bounds-check forwarder (cmp/jge + call CloseSocketInternal) whose head bytes
    # differ from the large fused body, so the vtable slot (vfunc_offset / vfunc_index) is
    # the stable locator instead.  The -inlined fallback drops func_sig too so the symbol's
    # output shape does not depend on which path wins.
    (
        "CNetworkSystem_CloseSocket",
        ["func_name", "func_va", "func_rva", "func_size", "vtable_name", "vfunc_offset", "vfunc_index"],
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    """Find the CNetworkSystem::CloseSocket vfunc as the caller of the de-inlined body."""
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

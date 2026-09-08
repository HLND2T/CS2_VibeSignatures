#!/usr/bin/env python3
"""Preprocess script for find-CNetworkSystem_CloseSocketInternal skill (deinline-fix chain, link 1/3).

Resolves the standalone ``CNetworkSystem::CloseSocketInternal`` body that owns the four
socket-teardown log strings on ``libnetworksystem.so``, where the compiler keeps it out of
the ``CNetworkSystem::CloseSocket`` vfunc::

    CNetworkSystem::CloseSocket(this, nSocket):            ; the vfunc -- string-less guard
        if (nSocket < 0 || nSocket >= this->m_nSockets) return false;
        CNetworkSystem::CloseSocketInternal(this, nSocket);
        return true;

    CNetworkSystem::CloseSocketInternal(this, nSocket):    ; the body we want
        ...
        LoggingSystem_Log(..., "Closing '%s' UDP listen socket\\n");   ; <- the anchor
        LoggingSystem_Log(..., "Closing '%s' P2P listen socket\\n");
        LoggingSystem_Log(..., "Closing '%s' SDR listen socket\\n");
        LoggingSystem_Log(..., "Closing '%s' poll group\\n");

``find-CNetworkSystem_CloseSocket-deinlined`` then picks the vfunc back up as the
vtable-filtered caller of this body.

This is an intermediate helper, not a published symbol -- it is deliberately NOT registered
under ``symbols:`` in ``configs/<GAMEVER>.yaml``.

``platform: linux`` scoping (see the ``configs/<GAMEVER>.yaml`` entry): on
``networksystem.dll`` the body is fused into the vfunc, so the anchor string lives inside
``CloseSocket`` itself and this finder would hand ``-deinlined`` the vfunc's own address as
its "callee".  Scoping the helper to Linux keeps Windows on the proven
``find-CNetworkSystem_CloseSocket-inlined`` path instead.  (Same treatment as
``find-CMsgSource2NetworkFlowQuality_PrintStatsInternal``.)

``CloseSocketInternal`` is a regular function (not a vfunc), so ``func_sig`` is its only
stable locator and is retained.  ``exclude_strings: ["CNetworkSystem::CloseAllSockets()"]``
guards against a build where ``CloseAllSockets`` inlines a second copy of the teardown block
while ``CloseSocketInternal`` still exists.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CNetworkSystem_CloseSocketInternal"]

FUNC_XREFS = [
    {
        "func_name": "CNetworkSystem_CloseSocketInternal",
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

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    ("CNetworkSystem_CloseSocketInternal", ["func_name", "func_va", "func_rva", "func_size", "func_sig"]),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    """Find the de-inlined CNetworkSystem::CloseSocketInternal body."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

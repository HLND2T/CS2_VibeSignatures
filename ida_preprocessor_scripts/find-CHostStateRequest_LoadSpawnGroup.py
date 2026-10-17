#!/usr/bin/env python3
"""Preprocess script for find-CHostStateRequest_LoadSpawnGroup skill (deinline-fix chain, link 1/2; both platforms).

`CHostStateRequest::LoadSpawnGroup` fills the 104-byte `CHostStateRequest` POD that
`CHostStateMgr::RequestHS_LoadSpawnGroup` queues. Unlike the inferred fills in this family
(`Idle`, `Connect`, `ChangelevelReconnect`, ...), this one is a real `CHostStateRequest`
method with Dota dylib symbol proof
(`__ZN17CHostStateRequest14LoadSpawnGroupEPKcbbS1_P9KeyValues`), and CS2 14190 keeps it
out-of-line on BOTH platforms (Linux `0x37eee0`, Windows `0x18021a780`). It owns the
`"Transition Return (%s [returning to :%s])"` message and is an intermediate anchor for
`find-CHostStateMgr_RequestHS_LoadSpawnGroup-noinline`; it is deliberately NOT registered
as a gamedata symbol.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CHostStateRequest_LoadSpawnGroup"]

FUNC_XREFS = [
    {
        "func_name": "CHostStateRequest_LoadSpawnGroup",
        "xref_strings": ["Transition Return (%s [returning to :%s])"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CHostStateRequest_LoadSpawnGroup",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
    )
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
    """Resolve the out-of-line `CHostStateRequest::LoadSpawnGroup` fill function by its message string."""
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

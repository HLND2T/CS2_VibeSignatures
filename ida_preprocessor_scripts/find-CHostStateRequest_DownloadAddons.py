#!/usr/bin/env python3
"""Preprocess script for find-CHostStateRequest_DownloadAddons skill (deinline-fix chain, link 1/3; Linux only).

`CHostStateRequest::DownloadAddons` fills the `CHostStateRequest` POD that
`CHostStateMgr::RequestHS_DownloadAddons` queues. CS2 14190 compiles it as a standalone
function on Linux (owns the `"Downloading Addons (%s)"` message) but inlines it into the
`RequestHS_DownloadAddons` vfunc on Windows, so this skill is Linux-scoped and its output is an
intermediate anchor for `find-CHostStateMgr_RequestHS_DownloadAddons-noinline` -- it is
deliberately NOT registered as a gamedata symbol.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CHostStateRequest_DownloadAddons"]

FUNC_XREFS = [
    {
        "func_name": "CHostStateRequest_DownloadAddons",
        "xref_strings": ["Downloading Addons (%s)"],
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
        "CHostStateRequest_DownloadAddons",
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
    """Resolve the out-of-line `CHostStateRequest::DownloadAddons` fill function by its message string."""
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

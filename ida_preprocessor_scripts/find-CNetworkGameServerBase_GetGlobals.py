#!/usr/bin/env python3
"""Resolve CNetworkGameServerBase::GetGlobals from its declared vtable slot."""

from pathlib import Path

from ida_analyze_util import _preprocess_direct_func_sig_via_mcp, write_func_yaml


TARGET_FUNCTION_NAME = "CNetworkGameServerBase_GetGlobals"
VTABLE_CLASS = "CNetworkGameServerBase"
# INetworkGameServer declares GetGlobals after Init, SetGameSpawnGroupMgr,
# SetGameSessionManifest, RegisterLoadingSpawnGroups, Shutdown, AddRef, and
# Release. The inherited slot is therefore index 7 (0x38) on both platforms.
VFUNC_OFFSET = "0x38"


def _match_output(expected_outputs, platform):
    expected_filename = f"{TARGET_FUNCTION_NAME}.{platform}.yaml"
    matches = [output_path for output_path in expected_outputs if Path(output_path).name == expected_filename]
    return matches[0] if len(matches) == 1 else None


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
    """Resolve the SDK-defined inherited slot without an unstable getter signature."""
    _ = skill_name, old_yaml_map, new_binary_dir
    output_path = _match_output(expected_outputs, platform)
    if not output_path:
        return False

    result = await _preprocess_direct_func_sig_via_mcp(
        session=session,
        new_path=output_path,
        image_base=image_base,
        platform=platform,
        func_name=TARGET_FUNCTION_NAME,
        debug=debug,
        direct_vtable_class=VTABLE_CLASS,
        direct_vfunc_offset=VFUNC_OFFSET,
        require_func_sig=False,
    )
    if not isinstance(result, dict):
        return False

    write_func_yaml(output_path, result)
    return True

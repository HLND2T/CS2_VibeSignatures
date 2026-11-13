#!/usr/bin/env python3
"""Current-layout anchors and call-site checks for network group statistics."""

import os
from pathlib import Path

from ida_preprocessor_scripts._global_receiver_vcalls_common import (
    _probe_global_receiver_calls,
    probe_global_receiver_calls,
)
from ida_preprocessor_scripts._vtable_slot_anchor_common import SLOT_SIZE, _load_vfunc_anchor_slot, _load_vtable_entries

VTABLE_CLASS = "CNetworkMessages"
GROUP_ANCHOR = "CNetworkMessages_FindNetworkGroup"
GROUP_METHODS = (
    "INetworkMessages_GetNetworkGroupCount",
    "INetworkMessages_GetNetworkGroupName",
    "INetworkMessages_GetNetworkGroupColor",
)
# These getters immediately follow FindNetworkGroup in INetworkMessages.
GROUP_SLOT_DELTAS = (1, 2, 3)
# MSVC returns Color through an additional output argument; Itanium returns it by value.
GROUP_CALL_ARITIES = {"windows": (1, 2, 3), "linux": (1, 2, 2)}


def load_group_slots(new_binary_dir, platform, debug=False):
    if platform not in GROUP_CALL_ARITIES:
        return None
    entries = _load_vtable_entries(new_binary_dir, VTABLE_CLASS, platform, debug=debug)
    if entries is None:
        return None
    anchor = _load_vfunc_anchor_slot(new_binary_dir, platform, GROUP_ANCHOR, VTABLE_CLASS, entries, debug=debug)
    if anchor is None:
        return None
    slots = [anchor + delta for delta in GROUP_SLOT_DELTAS]
    if any(slot not in entries for slot in slots) or len({entries[slot] for slot in slots}) != len(slots):
        return None
    return slots


def resolve_output_path(expected_outputs, new_binary_dir, symbol, platform):
    module_root = Path(new_binary_dir).resolve()
    filename = f"{symbol}.{platform}.yaml"
    matches = [
        os.fspath(path)
        for path in expected_outputs
        if Path(path).name == filename and Path(path).resolve().parent == module_root
    ]
    return matches[0] if len(matches) == 1 else None


# Keep the private entry point available to existing probe behavior tests.
_probe_stats_group_calls = _probe_global_receiver_calls


async def probe_stats_group_calls(session, func_va, slots, platform, debug=False):
    return await probe_global_receiver_calls(
        session=session, func_va=func_va,
        offsets=[slot * SLOT_SIZE for slot in slots], arities=GROUP_CALL_ARITIES[platform], debug=debug,
    )

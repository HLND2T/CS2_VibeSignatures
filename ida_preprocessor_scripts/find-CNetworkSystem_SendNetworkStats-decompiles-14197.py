#!/usr/bin/env python3
"""Generate network-group interface signatures from verified 14197 stats call sites."""

from pathlib import Path

from ida_analyze_util import _read_yaml_file, preprocess_gen_vfunc_sig_via_mcp, write_func_yaml
from ida_preprocessor_scripts._network_stats_common import (
    GROUP_METHODS,
    load_group_slots,
    probe_stats_group_calls,
    resolve_output_path,
)
from ida_preprocessor_scripts._vtable_slot_anchor_common import SLOT_SIZE

SENDER_NAME = "CNetworkSystem_SendNetworkStats"
TARGET_FUNCTION_NAMES = list(GROUP_METHODS)
GENERATE_YAML_DESIRED_FIELDS = [
    (name, ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"]) for name in TARGET_FUNCTION_NAMES
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
    """Sign each current virtual-call instruction only after checking its receiver and role."""
    _ = skill_name, old_yaml_map, image_base
    slots = load_group_slots(new_binary_dir, platform, debug=debug)
    outputs = [resolve_output_path(expected_outputs, new_binary_dir, name, platform) for name in TARGET_FUNCTION_NAMES]
    sender = _read_yaml_file(Path(new_binary_dir) / f"{SENDER_NAME}.{platform}.yaml")
    if slots is None or any(output is None for output in outputs) or not isinstance(sender, dict):
        return False
    if sender.get("func_name") != SENDER_NAME:
        return False
    try:
        sender_va = int(str(sender["func_va"]), 0)
        if sender_va <= 0:
            return False
        calls = await probe_stats_group_calls(
            session=session, func_va=sender_va, slots=slots, platform=platform, debug=debug
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: network group call validation failed: {exc}")
        return False
    if calls is None:
        return False

    payloads = []
    for name, slot, call in zip(TARGET_FUNCTION_NAMES, slots, calls["calls"]):
        generated = await preprocess_gen_vfunc_sig_via_mcp(
            session=session, inst_va=call["inst_va"], vfunc_offset=slot * SLOT_SIZE, debug=debug
        )
        if not isinstance(generated, dict) or not generated.get("vfunc_sig"):
            return False
        payloads.append(
            {
                "func_name": name,
                "vfunc_sig": generated["vfunc_sig"],
                "vfunc_offset": hex(slot * SLOT_SIZE),
                "vfunc_index": slot,
                "vtable_name": "INetworkMessages",
            }
        )
    for output, payload in zip(outputs, payloads):
        write_func_yaml(output, payload)
    return True

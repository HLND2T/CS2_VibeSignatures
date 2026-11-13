#!/usr/bin/env python3
"""Locate ById through its result flowing into GetNetMessageInfo on the same receiver."""

from pathlib import Path

from ida_analyze_util import (
    _collect_xref_func_starts_for_string,
    _read_yaml_file,
    preprocess_gen_vfunc_sig_via_mcp,
    write_func_yaml,
)
from ida_preprocessor_scripts._global_receiver_vcalls_common import probe_global_receiver_calls
from ida_preprocessor_scripts._network_stats_common import resolve_output_path
from ida_preprocessor_scripts._vtable_slot_anchor_common import SLOT_SIZE, _load_vfunc_anchor_slot, _load_vtable_entries

TARGET = "INetworkMessages_FindNetworkMessageById"
INFO = "INetworkMessages_GetNetMessageInfo"
PRIORITY = "CNetworkMessages_RegisterFieldChangeCallbackPriority"
VTABLE_CLASS = "CNetworkMessages"
# FindNetworkMessageById immediately follows the priority registration method in 14197.
BY_ID_SLOT_DELTA = 1
TARGET_FUNCTION_NAMES = [TARGET]
GENERATE_YAML_DESIRED_FIELDS = [(TARGET, ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"])]


def load_lookup_offsets(new_binary_dir, platform, debug=False):
    network_dir = Path(new_binary_dir).parent / "networksystem"
    entries = _load_vtable_entries(network_dir, VTABLE_CLASS, platform, debug=debug)
    if entries is None:
        return None
    priority = _load_vfunc_anchor_slot(network_dir, platform, PRIORITY, VTABLE_CLASS, entries, debug=debug)
    info = _read_yaml_file(Path(new_binary_dir) / f"{INFO}.{platform}.yaml")
    if priority is None or not isinstance(info, dict):
        return None
    if info.get("func_name") != INFO or info.get("vtable_name") != "INetworkMessages":
        return None
    try:
        index = int(str(info["vfunc_index"]), 0)
        offset = int(str(info["vfunc_offset"]), 0)
    except (KeyError, TypeError, ValueError):
        return None
    by_id = priority + BY_ID_SLOT_DELTA
    if index not in entries or by_id not in entries or offset != index * SLOT_SIZE:
        return None
    if index == by_id or entries[index] == entries[by_id]:
        return None
    return by_id * SLOT_SIZE, offset


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
    _ = skill_name, old_yaml_map, image_base
    offsets = load_lookup_offsets(new_binary_dir, platform, debug=debug)
    output = resolve_output_path(expected_outputs, new_binary_dir, TARGET, platform)
    if offsets is None or output is None:
        if debug:
            print(f"    Preprocess: invalid ById inputs or output: offsets={offsets}, output={output}")
        return False
    try:
        owners = await _collect_xref_func_starts_for_string(
            session=session, xref_string="FULLMATCH:Network Message %d", debug=debug
        )
        matches = []
        for owner in sorted(owners or ()):
            match = await probe_global_receiver_calls(
                session=session,
                func_va=owner,
                offsets=offsets,
                arities=(2, 2),
                result_flow=(0, 1, 1),
                debug=debug,
            )
            if match is not None:
                matches.append(match)
    except Exception as exc:
        if debug:
            print(f"    Preprocess: ById call-chain validation failed: {exc}")
        return False
    if not matches or len({match["receiver"] for match in matches}) != 1:
        if debug:
            print(f"    Preprocess: ById owners={sorted(owners or ())}, verified receiver groups={len(matches)}")
        return False
    for site in sorted({match["calls"][0]["inst_va"] for match in matches}):
        generated = await preprocess_gen_vfunc_sig_via_mcp(
            session=session, inst_va=site, vfunc_offset=offsets[0], debug=debug
        )
        if not isinstance(generated, dict) or not generated.get("vfunc_sig"):
            continue
        write_func_yaml(
            output,
            {
                "func_name": TARGET,
                "vfunc_sig": generated["vfunc_sig"],
                "vfunc_offset": hex(offsets[0]),
                "vfunc_index": offsets[0] // SLOT_SIZE,
                "vtable_name": "INetworkMessages",
            },
        )
        return True
    return False

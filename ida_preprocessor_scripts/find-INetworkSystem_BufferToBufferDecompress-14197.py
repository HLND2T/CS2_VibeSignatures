#!/usr/bin/env python3
"""Sign the current parser's decompression call after validating the concrete slot."""

from pathlib import Path

from ida_analyze_util import _read_yaml_file, preprocess_gen_vfunc_sig_via_mcp, write_func_yaml
from ida_preprocessor_scripts._global_receiver_vcalls_common import probe_global_receiver_calls
from ida_preprocessor_scripts._network_stats_common import resolve_output_path
from ida_preprocessor_scripts._vtable_slot_anchor_common import SLOT_SIZE, _load_vfunc_anchor_slot, _load_vtable_entries

TARGET = "INetworkSystem_BufferToBufferDecompress"
CONCRETE = "CNetworkSystem_BufferToBufferDecompress"
PARSER = "CNetworkStringTableClient_ParseUpdate"
VTABLE_CLASS = "CNetworkSystem"
# 14197 passes this, compressed bytes, byte count, and a growable output container.
DECOMPRESSION_CALL_ARITY = 4
TARGET_FUNCTION_NAMES = [TARGET]
GENERATE_YAML_DESIRED_FIELDS = [
    (TARGET, ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"])
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False,
):
    _ = skill_name, old_yaml_map, image_base
    output = resolve_output_path(expected_outputs, new_binary_dir, TARGET, platform)
    network_dir = Path(new_binary_dir).parent / "networksystem"
    entries = _load_vtable_entries(network_dir, VTABLE_CLASS, platform, debug=debug)
    parser = _read_yaml_file(Path(new_binary_dir) / f"{PARSER}.{platform}.yaml")
    if output is None or entries is None or not isinstance(parser, dict) or parser.get("func_name") != PARSER:
        return False
    slot = _load_vfunc_anchor_slot(network_dir, platform, CONCRETE, VTABLE_CLASS, entries, debug=debug)
    if slot is None:
        return False
    try:
        parser_va = int(str(parser["func_va"]), 0)
        if parser_va <= 0:
            return False
        calls = await probe_global_receiver_calls(
            session=session, func_va=parser_va, offsets=(slot * SLOT_SIZE,),
            arities=(DECOMPRESSION_CALL_ARITY,), debug=debug,
        )
    except Exception as exc:
        if debug:
            print(f"    Preprocess: decompression call validation failed: {exc}")
        return False
    if calls is None:
        return False
    generated = await preprocess_gen_vfunc_sig_via_mcp(
        session=session, inst_va=calls["calls"][0]["inst_va"], vfunc_offset=slot * SLOT_SIZE, debug=debug
    )
    if not isinstance(generated, dict) or not generated.get("vfunc_sig"):
        return False
    write_func_yaml(output, {
        "func_name": TARGET, "vfunc_sig": generated["vfunc_sig"],
        "vfunc_offset": hex(slot * SLOT_SIZE), "vfunc_index": slot, "vtable_name": "INetworkSystem",
    })
    return True

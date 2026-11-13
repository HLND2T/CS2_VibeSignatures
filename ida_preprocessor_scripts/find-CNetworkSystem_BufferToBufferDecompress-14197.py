#!/usr/bin/env python3
"""Identify the current decompression vfunc from its implementation diagnostic."""

from ida_preprocessor_scripts._network_registry_vfunc_common import VFUNC_FIELDS, _resolve_slot
from ida_preprocessor_scripts._network_stats_common import resolve_output_path
from ida_preprocessor_scripts._vtable_slot_anchor_common import _load_vtable_entries, _write_slot_func_yaml

TARGET = "CNetworkSystem_BufferToBufferDecompress"
VTABLE_CLASS = "CNetworkSystem"
ANCHOR = "Net_BufferToBufferDecompress: malformed compressed data\n"
TARGET_FUNCTION_NAMES = [TARGET]
GENERATE_YAML_DESIRED_FIELDS = [(TARGET, list(VFUNC_FIELDS))]


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
    _ = skill_name, old_yaml_map
    if resolve_output_path(expected_outputs, new_binary_dir, TARGET, platform) is None:
        return False
    entries = _load_vtable_entries(new_binary_dir, VTABLE_CLASS, platform, debug=debug)
    if entries is None:
        return False
    slot = await _resolve_slot(session, ANCHOR, entries, debug=debug, vtable_class=VTABLE_CLASS)
    if slot is None:
        return False
    return await _write_slot_func_yaml(
        session=session,
        expected_outputs=expected_outputs,
        platform=platform,
        image_base=image_base,
        target_name=TARGET,
        vtable_class=VTABLE_CLASS,
        vtable_entries=entries,
        slot=slot,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

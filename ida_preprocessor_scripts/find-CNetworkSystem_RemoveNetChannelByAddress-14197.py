#!/usr/bin/env python3
"""Resolve the address-based removal sibling only after reproving its receiver flow."""

from ida_preprocessor_scripts._network_channel_remove_common import (
    BY_ADDRESS,
    BY_ADDRESS_SLOT_DELTA,
    REMOVE,
    VTABLE_CLASS,
    resolve_remove_pair,
)
from ida_preprocessor_scripts._network_registry_vfunc_common import VFUNC_FIELDS
from ida_preprocessor_scripts._network_stats_common import resolve_output_path
from ida_preprocessor_scripts._vtable_slot_anchor_common import _load_vfunc_anchor_slot, _write_slot_func_yaml

TARGET_FUNCTION_NAMES = [BY_ADDRESS]
GENERATE_YAML_DESIRED_FIELDS = [(BY_ADDRESS, list(VFUNC_FIELDS))]


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
    if resolve_output_path(expected_outputs, new_binary_dir, BY_ADDRESS, platform) is None:
        return False
    pair = await resolve_remove_pair(session, new_binary_dir, platform, debug=debug)
    if pair is None:
        return False
    entries, slot = pair
    anchor = _load_vfunc_anchor_slot(new_binary_dir, platform, REMOVE, VTABLE_CLASS, entries, debug=debug)
    if anchor != slot:
        return False
    return await _write_slot_func_yaml(
        session=session,
        expected_outputs=expected_outputs,
        platform=platform,
        image_base=image_base,
        target_name=BY_ADDRESS,
        vtable_class=VTABLE_CLASS,
        vtable_entries=entries,
        slot=slot + BY_ADDRESS_SLOT_DELTA,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

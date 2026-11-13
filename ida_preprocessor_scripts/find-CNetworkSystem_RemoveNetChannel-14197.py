#!/usr/bin/env python3
"""Resolve removal using the current close-helper and address-based caller pair."""

from ida_preprocessor_scripts._network_channel_remove_common import REMOVE, VTABLE_CLASS, resolve_remove_pair
from ida_preprocessor_scripts._network_registry_vfunc_common import VFUNC_FIELDS
from ida_preprocessor_scripts._network_stats_common import resolve_output_path
from ida_preprocessor_scripts._vtable_slot_anchor_common import _write_slot_func_yaml

TARGET_FUNCTION_NAMES = [REMOVE]
GENERATE_YAML_DESIRED_FIELDS = [(REMOVE, list(VFUNC_FIELDS))]


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
    if resolve_output_path(expected_outputs, new_binary_dir, REMOVE, platform) is None:
        return False
    pair = await resolve_remove_pair(session, new_binary_dir, platform, debug=debug)
    if pair is None:
        return False
    entries, slot = pair
    return await _write_slot_func_yaml(
        session=session,
        expected_outputs=expected_outputs,
        platform=platform,
        image_base=image_base,
        target_name=REMOVE,
        vtable_class=VTABLE_CLASS,
        vtable_entries=entries,
        slot=slot,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

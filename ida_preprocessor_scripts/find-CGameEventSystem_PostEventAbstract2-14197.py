#!/usr/bin/env python3
"""Disambiguate the 14197 posting overload from its entity-event sibling."""

from ida_analyze_util import _collect_xref_func_starts_for_string
from ida_preprocessor_scripts._vtable_slot_anchor_common import (
    _load_vfunc_anchor_slot,
    _load_vtable_entries,
    _write_slot_func_yaml,
)

VTABLE_CLASS = "CGameEventSystem"
SIBLING_NAME = "CGameEventSystem_PostEntityEventAbstract"
TARGET_FUNCTION_NAMES = ["CGameEventSystem_PostEventAbstract2"]
POSTING_LOG = "GameEvent:  Posting %s (id:%d group:'%s') from code\n"
GENERATE_YAML_DESIRED_FIELDS = [
    (TARGET_FUNCTION_NAMES[0], ["func_name", "func_va", "func_rva", "func_size", "func_sig",
                               "vtable_name", "vfunc_offset", "vfunc_index"]),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False,
):
    """Require one current vtable log owner after excluding the verified sibling slot."""
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    entries = _load_vtable_entries(new_binary_dir, VTABLE_CLASS, platform, debug=debug)
    if entries is None:
        return False
    sibling = _load_vfunc_anchor_slot(new_binary_dir, platform, SIBLING_NAME, VTABLE_CLASS, entries, debug=debug)
    if sibling is None:
        return False
    owners = await _collect_xref_func_starts_for_string(session, f"FULLMATCH:{POSTING_LOG}", debug=debug)
    if not owners:
        return False
    candidates = [index for index, address in entries.items() if index != sibling and address in owners]
    if len(candidates) != 1:
        if debug:
            print(f"    Preprocess: expected one posting overload after sibling exclusion, found {len(candidates)}")
        return False
    return await _write_slot_func_yaml(
        session=session, expected_outputs=expected_outputs, platform=platform, image_base=image_base,
        target_name=TARGET_FUNCTION_NAMES[0], vtable_class=VTABLE_CLASS, vtable_entries=entries,
        slot=candidates[0], generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS, debug=debug,
    )

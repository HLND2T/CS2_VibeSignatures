#!/usr/bin/env python3
"""Resolve current vfuncs from their implementation owners and vtable entrypoints."""

from ida_analyze_util import (
    _collect_single_call_or_jump_xref_func_starts_for_ea,
    _collect_xref_func_starts_for_string,
)
from ida_preprocessor_scripts._vtable_slot_anchor_common import _load_vtable_entries, _write_slot_func_yaml

VTABLE_CLASS = "CNetworkMessages"
VFUNC_FIELDS = [
    "func_name",
    "func_va",
    "func_rva",
    "func_size",
    "func_sig",
    "vtable_name",
    "vfunc_offset",
    "vfunc_index",
]


async def _resolve_slot(session, anchor, entries, debug=False, vtable_class=VTABLE_CLASS):
    owners = await _collect_xref_func_starts_for_string(session=session, xref_string=f"FULLMATCH:{anchor}", debug=debug)
    if owners is None or len(owners) != 1:
        if debug:
            print(f"    Preprocess: expected one implementation owner for {anchor}")
        return None

    owner = next(iter(owners))
    slots = [index for index, address in entries.items() if address == owner]
    if not slots:
        callers = await _collect_single_call_or_jump_xref_func_starts_for_ea(
            session=session, target_ea=owner, debug=debug
        )
        if callers is None:
            return None
        slots = [index for index, address in entries.items() if address in callers]

    if len(slots) != 1:
        if debug:
            print(f"    Preprocess: expected one {vtable_class} entry for {anchor}, found {len(slots)}")
        return None
    return slots[0]


async def preprocess_registry_vfuncs(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    targets,
    generate_yaml_desired_fields,
    debug=False,
):
    """Resolve every target before emitting current vfuncs with fresh signatures."""
    if platform not in {"windows", "linux"} or not targets:
        return False
    entries = _load_vtable_entries(new_binary_dir, VTABLE_CLASS, platform, debug=debug)
    if entries is None:
        return False

    slots = []
    for _name, anchor in targets:
        slot = await _resolve_slot(session, anchor, entries, debug=debug)
        if slot is None:
            return False
        slots.append(slot)
    if len(set(slots)) != len(slots):
        return False

    for (name, _anchor), slot in zip(targets, slots):
        if not await _write_slot_func_yaml(
            session=session,
            expected_outputs=expected_outputs,
            platform=platform,
            image_base=image_base,
            target_name=name,
            vtable_class=VTABLE_CLASS,
            vtable_entries=entries,
            slot=slot,
            generate_yaml_desired_fields=generate_yaml_desired_fields,
            debug=debug,
        ):
            return False
    return True

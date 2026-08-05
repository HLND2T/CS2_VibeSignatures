#!/usr/bin/env python3
"""Preprocess script for find-CNetworkGameServerBase_IsHLTV skill.

``CNetworkGameServerBase::IsHLTV`` is a ``CNetworkGameServer_vtable`` vfunc whose
concrete implementation is a shared ``xor al, al ; retn`` return-false stub
(Windows 14174: ``0x1800245d0`` = ``32 C0 C3``; Linux 14174: ``0x4f0c50``). That
3-byte stub body is reused by 200+ unrelated vtable slots across the module, so
it has **no unique** ``func_sig``/``vfunc_sig`` and no distinctive string or xref
that could anchor it -- Patterns A/B/C are all infeasible. There is likewise no
thin single-vcall thunk that dispatches this slot on a ``CNetworkGameServer``
object (the only known callers, ``CNetworkGameServerBase_WriteDeltaEntities`` and
``sub_1800841C0``, each contain many distinct register-indirect vcalls), so the
Pattern L / ``_indirect_vcall_target_common`` "unique vcall" locator does not
apply either.

The one stable anchor is the vfunc's **position** in ``CNetworkGameServer_vtable``.
Per ``hl2sdk_cs2/public/iserver.h`` the derived-class methods are declared in a
fixed order in which ``IsHLTV`` immediately precedes ``IsPausable``. ``IsPausable``
has a real, signable body and is resolved independently
(``find-CNetworkGameServerBase_IsPausable-*``), so ``IsHLTV`` is deterministically
its slot minus one on every platform. The absolute slot differs by ABI --
Windows: ``IsPausable`` = slot 71 -> ``IsHLTV`` = slot 70 (``0x230``); Linux:
``IsPausable`` = slot 76 -> ``IsHLTV`` = slot 75 (``0x258``) -- so the index is
*derived* from the sibling every run rather than hardcoded, and a layout shift is
picked up automatically. The output is slot-only
(``func_name, vtable_name, vfunc_offset, vfunc_index``) because the stub body
carries no signable information.

The ``CNetworkGameServer_vtable.{platform}.yaml`` is read only to cross-validate
the anchor: the sibling's own slot must hold ``IsPausable``'s ``func_va`` and the
preceding slot must exist. This guards against a mis-derived index if the vtable
layout ever changes.
"""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import write_func_yaml

TARGET_FUNCTION_NAME = "CNetworkGameServerBase_IsHLTV"
VTABLE_NAME = "CNetworkGameServer_vtable"
VTABLE_YAML_STEM = "CNetworkGameServer_vtable"
# Adjacent signable sibling: IsHLTV occupies the slot immediately before IsPausable.
SIBLING_YAML_STEM = "CNetworkGameServerBase_IsPausable"


def _read_yaml(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _parse_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if raw:
            return int(raw, 0)
    raise ValueError(f"cannot parse integer from {value!r}")


def _resolve_output_path(expected_outputs, platform):
    filename = f"{TARGET_FUNCTION_NAME}.{platform}.yaml"
    matches = [p for p in expected_outputs if os.path.basename(p) == filename]
    if len(matches) != 1:
        return None
    return matches[0]


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
    """Derive the IsHLTV vtable slot as (IsPausable slot - 1) and write slot-only YAML."""
    _ = session, skill_name, old_yaml_map, image_base

    def _debug(message):
        if debug:
            print(f"    Preprocess: {message}")

    if yaml is None:
        _debug("PyYAML is required")
        return False

    output_path = _resolve_output_path(expected_outputs, platform)
    if output_path is None:
        _debug(f"expected exactly one output for {TARGET_FUNCTION_NAME}.{platform}.yaml")
        return False

    sibling_path = os.path.join(new_binary_dir, f"{SIBLING_YAML_STEM}.{platform}.yaml")
    sibling_yaml = _read_yaml(sibling_path)
    if not isinstance(sibling_yaml, dict):
        _debug(f"failed to read sibling YAML: {sibling_path}")
        return False

    try:
        sibling_index = _parse_int(sibling_yaml.get("vfunc_index"))
        sibling_va = _parse_int(sibling_yaml.get("func_va"))
    except Exception:
        _debug(f"sibling YAML missing/invalid vfunc_index or func_va: {sibling_path}")
        return False

    if sibling_index <= 0:
        _debug(f"sibling vfunc_index out of range: {sibling_index}")
        return False

    target_index = sibling_index - 1
    target_offset = target_index * 8

    # Cross-validate against the vtable: the sibling must sit at its recorded slot,
    # and the preceding (target) slot must exist. This catches a layout drift that
    # would otherwise silently mis-derive the index.
    vtable_path = os.path.join(new_binary_dir, f"{VTABLE_YAML_STEM}.{platform}.yaml")
    vtable_yaml = _read_yaml(vtable_path)
    if not isinstance(vtable_yaml, dict):
        _debug(f"failed to read vtable YAML: {vtable_path}")
        return False
    entries = vtable_yaml.get("vtable_entries")
    if not isinstance(entries, dict):
        _debug(f"vtable YAML missing vtable_entries: {vtable_path}")
        return False

    def _entry(index):
        # vtable_entries keys may be ints or strings depending on the loader.
        if index in entries:
            return entries[index]
        return entries.get(str(index))

    sibling_entry = _entry(sibling_index)
    target_entry = _entry(target_index)
    if sibling_entry is None or target_entry is None:
        _debug(f"vtable slot missing (sibling {sibling_index}: {sibling_entry}, target {target_index}: {target_entry})")
        return False
    try:
        if _parse_int(sibling_entry) != sibling_va:
            _debug(
                f"vtable slot {sibling_index} ({sibling_entry}) does not match sibling "
                f"func_va ({hex(sibling_va)}); layout drift"
            )
            return False
    except Exception:
        _debug(f"invalid vtable slot value for {sibling_index}: {sibling_entry}")
        return False

    payload = {
        "func_name": TARGET_FUNCTION_NAME,
        "vtable_name": VTABLE_NAME,
        "vfunc_offset": hex(target_offset),
        "vfunc_index": target_index,
    }
    write_func_yaml(output_path, payload)

    if debug:
        print(
            f"    Preprocess: written {os.path.basename(output_path)} -- "
            f"IsHLTV slot {target_index} (offset {hex(target_offset)}) derived from "
            f"{SIBLING_YAML_STEM} slot {sibling_index}"
        )
    return True

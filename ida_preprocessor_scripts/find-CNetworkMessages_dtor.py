#!/usr/bin/env python3
"""Deterministic preprocessor for the CNetworkMessages destructor vfunc."""

import os
from pathlib import Path

from ida_analyze_util import preprocess_gen_func_sig_via_mcp, write_func_yaml
from trusted_yaml import load_yaml_file

TARGET_FUNCTION_NAMES = ["CNetworkMessages_dtor"]
VTABLE_CLASS = "CNetworkMessages"

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkMessages_dtor",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
]


def _resolve_destructor_slot(vtable_payload, platform):
    if not isinstance(vtable_payload, dict) or vtable_payload.get("vtable_class") != VTABLE_CLASS:
        return None
    if platform not in {"windows", "linux"}:
        return None

    try:
        count = int(vtable_payload["vtable_numvfunc"])
        entries = {int(index): int(str(address), 0) for index, address in vtable_payload["vtable_entries"].items()}
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    if count < 3 or set(entries) != set(range(count)):
        return None

    # MSVC exposes the scalar-deleting destructor in the final slot. The
    # Itanium ABI exposes the complete and deleting destructors as the final
    # pair; the source-owned symbol represents the complete destructor.
    index = count - 1 if platform == "windows" else count - 2
    func_va = entries.get(index)
    if func_va is None or func_va <= 0:
        return None
    return index, func_va


def _resolve_target_output(expected_outputs, new_binary_dir, platform):
    expected_basename = f"{TARGET_FUNCTION_NAMES[0]}.{platform}.yaml"
    module_root = Path(new_binary_dir).resolve()
    matches = [
        os.fspath(Path(path))
        for path in expected_outputs
        if Path(path).name == expected_basename and Path(path).resolve().parent == module_root
    ]
    return matches[0] if len(matches) == 1 else None


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
    """Resolve the ABI destructor slot and emit a freshly generated func_sig."""
    _ = skill_name, old_yaml_map
    target_output = _resolve_target_output(expected_outputs, new_binary_dir, platform)
    if target_output is None:
        if debug:
            print("    Preprocess: expected exactly one in-module CNetworkMessages_dtor output")
        return False

    vtable_path = Path(new_binary_dir) / f"{VTABLE_CLASS}_vtable.{platform}.yaml"
    try:
        vtable_payload = load_yaml_file(vtable_path)
    except Exception:
        if debug:
            print(f"    Preprocess: failed to read {vtable_path.name}")
        return False

    resolved = _resolve_destructor_slot(vtable_payload, platform)
    if resolved is None:
        if debug:
            print(f"    Preprocess: invalid {VTABLE_CLASS} ABI destructor layout for {platform}")
        return False
    vfunc_index, func_va = resolved

    generated = await preprocess_gen_func_sig_via_mcp(
        session=session,
        func_va=func_va,
        image_base=image_base,
        allow_across_function_boundary=False,
        debug=debug,
    )
    required_generated_fields = {"func_va", "func_rva", "func_size", "func_sig"}
    if not isinstance(generated, dict) or not required_generated_fields <= generated.keys():
        if debug:
            print(f"    Preprocess: deterministic func_sig generation failed for {hex(func_va)}")
        return False
    try:
        generated_func_va = int(str(generated["func_va"]), 0)
    except (TypeError, ValueError):
        return False
    if generated_func_va != func_va or not generated.get("func_sig"):
        return False

    payload = {
        "func_name": TARGET_FUNCTION_NAMES[0],
        **generated,
        "vtable_name": VTABLE_CLASS,
        "vfunc_offset": hex(vfunc_index * 8),
        "vfunc_index": vfunc_index,
    }
    write_func_yaml(target_output, payload)
    return True

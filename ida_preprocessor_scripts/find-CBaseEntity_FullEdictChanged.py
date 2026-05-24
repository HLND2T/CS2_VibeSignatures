#!/usr/bin/env python3
"""Preprocess script for find-CBaseEntity_FullEdictChanged skill."""

import os
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CBaseEntity_FullEdictChanged",
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CBaseEntity_FullEdictChanged", "CBaseEntity"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CBaseEntity_FullEdictChanged",
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

# Signature templates -- the 4-byte placeholder is the combined offset
# (CBaseEntity::m_NetworkTransmitComponent + CNetworkTransmitComponent::m_nStateFlags),
# loaded via `mov eax, [reg+disp32]; shr eax, 1`.
# Windows: 8B 81 ?? ?? ?? ?? D1 E8  (mov eax, [rcx+disp32]; shr eax, 1)
# Linux:   8B 87 ?? ?? ?? ?? D1 E8  (mov eax, [rdi+disp32]; shr eax, 1)
_SIG_WINDOWS_TEMPLATE = "8B 81 {b0:02X} {b1:02X} {b2:02X} {b3:02X} D1 E8"
_SIG_LINUX_TEMPLATE = "8B 87 {b0:02X} {b1:02X} {b2:02X} {b3:02X} D1 E8"

_NETWORK_TRANSMIT_COMPONENT_STEM = "CBaseEntity_m_NetworkTransmitComponent"
_STATE_FLAGS_STEM = "CNetworkTransmitComponent_m_nStateFlags"


def _read_offset(yaml_path):
    """Read `offset` from a struct-member YAML file, returning integer or None."""
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            val = data.get("offset")
            if val is not None:
                return int(str(val).strip(), 0)
    except Exception:
        pass
    return None


def _read_struct_offset(new_binary_dir, stem, platform):
    """Read a struct-member offset YAML in the current module directory."""
    yaml_path = os.path.join(new_binary_dir, f"{stem}.{platform}.yaml")
    return _read_offset(yaml_path), yaml_path


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Locate CBaseEntity_FullEdictChanged via dynamic xref signature built from struct offsets."""
    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required")
        return False

    transmit_offset, transmit_yaml = _read_struct_offset(
        new_binary_dir, _NETWORK_TRANSMIT_COMPONENT_STEM, platform,
    )
    if transmit_offset is None:
        if debug:
            print(
                f"    Preprocess: failed to read offset from {os.path.basename(transmit_yaml)}"
            )
        return False

    state_flags_offset, state_flags_yaml = _read_struct_offset(
        new_binary_dir, _STATE_FLAGS_STEM, platform,
    )
    if state_flags_offset is None:
        if debug:
            print(
                f"    Preprocess: failed to read offset from {os.path.basename(state_flags_yaml)}"
            )
        return False

    combined_offset = transmit_offset + state_flags_offset
    if combined_offset < 0 or combined_offset > 0xFFFFFFFF:
        if debug:
            print(
                f"    Preprocess: combined offset 0x{combined_offset:X} out of 32-bit range"
            )
        return False

    # Little-endian 4-byte encoding of the disp32 in `mov eax, [reg+disp32]`.
    b0 = combined_offset & 0xFF
    b1 = (combined_offset >> 8) & 0xFF
    b2 = (combined_offset >> 16) & 0xFF
    b3 = (combined_offset >> 24) & 0xFF

    if platform == "windows":
        sig = _SIG_WINDOWS_TEMPLATE.format(b0=b0, b1=b1, b2=b2, b3=b3)
    elif platform == "linux":
        sig = _SIG_LINUX_TEMPLATE.format(b0=b0, b1=b1, b2=b2, b3=b3)
    else:
        return False

    if debug:
        print(
            "    Preprocess: combined offset "
            f"0x{transmit_offset:X} + 0x{state_flags_offset:X} = 0x{combined_offset:X}, "
            f"xref signature: {sig}"
        )

    func_xrefs = [
        {
            "func_name": "CBaseEntity_FullEdictChanged",
            "xref_strings": [],
            "xref_gvs": [],
            "xref_signatures": [sig],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": [],
        },
    ]

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

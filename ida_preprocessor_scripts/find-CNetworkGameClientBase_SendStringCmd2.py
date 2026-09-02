#!/usr/bin/env python3
"""Preprocess script for find-CNetworkGameClientBase_SendStringCmd2 skill."""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkGameClientBase_SendStringCmd2",
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CNetworkGameClientBase_SendStringCmd2",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]

# vfunc_offset is read at runtime from CNetworkGameClientBase_SendStringCmd YAML,
# then substituted as a little-endian disp32 into the tail-call signature.
_SENDSTRINGCMD_STEM = "CNetworkGameClientBase_SendStringCmd"

# Windows tail wrapper: mov r9d,-1; cmova edx,r9d; jmp qword ptr [rax+OFFSET]
_WINDOWS_CMP = "83 FA 03"  # cmp edx, 3
_WINDOWS_MOV = "41 B9 FF FF FF FF"  # mov r9d, 0FFFFFFFFh
_WINDOWS_JUMP_TEMPLATE = "48 FF A0 {OFFSET}"  # jmp qword ptr [rax+OFFSET]

# Linux member body: ... mov rax,[rax+OFFSET] ...
_LINUX_CMP = "83 FE 03"  # cmp esi, 3
_LINUX_MOV = "BE FF FF FF FF"  # mov esi, 0FFFFFFFFh
_LINUX_LOAD_TEMPLATE = "48 8B 80 {OFFSET}"  # mov rax, [rax+OFFSET]

# The free global-accessor wrapper (g_pNetworkGameClientBase->SendStringCmd) shares the
# exact tail-call signature on Windows but loads a global and null-checks first
# (`mov rcx,[rip+..]; test rcx,rcx; jz`). Exclude it to pin the member thunk.
_WINDOWS_EXCLUDE = "48 8B 0D ?? ?? ?? ?? 48 85 C9 74"


def _read_vfunc_offset(new_binary_dir, platform):
    yaml_path = os.path.join(new_binary_dir, f"{_SENDSTRINGCMD_STEM}.{platform}.yaml")
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            val = data.get("vfunc_offset")
            if val is not None:
                return int(str(val).strip(), 0)
    except Exception:
        pass
    return None


def _format_offset_le(vfunc_offset):
    """Return the 4-byte little-endian disp32 as space-separated uppercase hex."""
    return " ".join(f"{((vfunc_offset >> (8 * i)) & 0xFF):02X}" for i in range(4))


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
    """Locate CNetworkGameClientBase_SendStringCmd2 via the SendStringCmd vfunc tail-call."""
    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required")
        return False

    vfunc_offset = _read_vfunc_offset(new_binary_dir, platform)
    if vfunc_offset is None:
        if debug:
            print("    Preprocess: failed to read vfunc_offset from CNetworkGameClientBase_SendStringCmd YAML")
        return False

    offset_le = _format_offset_le(vfunc_offset)

    if platform == "windows":
        func_xrefs = [
            {
                "func_name": "CNetworkGameClientBase_SendStringCmd2",
                "xref_strings": [],
                "xref_gvs": [],
                "xref_signatures": [
                    _WINDOWS_CMP,
                    _WINDOWS_MOV,
                    _WINDOWS_JUMP_TEMPLATE.replace("{OFFSET}", offset_le),
                ],
                "xref_funcs": [],
                "exclude_funcs": [],
                "exclude_strings": [],
                "exclude_gvs": [],
                "exclude_signatures": [_WINDOWS_EXCLUDE],
            },
        ]
    elif platform == "linux":
        func_xrefs = [
            {
                "func_name": "CNetworkGameClientBase_SendStringCmd2",
                "xref_strings": [],
                "xref_gvs": [],
                "xref_signatures": [
                    _LINUX_CMP,
                    _LINUX_MOV,
                    _LINUX_LOAD_TEMPLATE.replace("{OFFSET}", offset_le),
                ],
                "xref_funcs": [],
                "exclude_funcs": [],
                "exclude_strings": [],
                "exclude_gvs": [],
                "exclude_signatures": [],
            },
        ]
    else:
        return False

    if debug:
        print(f"    Preprocess: SendStringCmd2 xref_signatures (vfunc_offset 0x{vfunc_offset:X}, le {offset_le})")

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

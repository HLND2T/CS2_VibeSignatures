#!/usr/bin/env python3
"""Preprocess script for resolving CCSPlayerController think functions on Linux.

Reads schema structure globals (g_CCSPlayerController_*Think) and extracts the
actual think function pointers stored at offset +0x28 within each schema structure.
"""

import os

import yaml

from ida_analyze_util import (
    parse_mcp_result,
    preprocess_func_sig_via_mcp,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)

# (func_name, corresponding_global_name)
THINK_FUNCTIONS = [
    ("CCSPlayerController_PlayerForceTeamThink", "g_CCSPlayerController_PlayerForceTeamThink"),
    ("CCSPlayerController_ResetForceTeamThink", "g_CCSPlayerController_ResetForceTeamThink"),
    ("CCSPlayerController_ResourceDataThink", "g_CCSPlayerController_ResourceDataThink"),
    ("CCSPlayerController_InventoryUpdateThink", "g_CCSPlayerController_InventoryUpdateThink"),
]

# Offset within the schema structure where the think function pointer is stored
FUNC_PTR_OFFSET = 0x28

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CCSPlayerController_PlayerForceTeamThink",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
    ),
    (
        "CCSPlayerController_ResetForceTeamThink",
        ["func_name", "func_va", "func_rva", "func_size"],# too short to have an unique signature
    ),
    (
        "CCSPlayerController_ResourceDataThink",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
    ),
    (
        "CCSPlayerController_InventoryUpdateThink",
        ["func_name", "func_va", "func_rva", "func_size"],# too short to have an unique signature
    ),
]


async def _read_ptr_via_mcp(session, addr, debug=False):
    """Read a 64-bit pointer from the binary at the given address via IDA MCP."""
    try:
        result = await session.call_tool(
            name="get_int",
            arguments={"queries": {"addr": hex(addr), "ty": "u64"}},
        )
        payload = parse_mcp_result(result)
    except Exception:
        if debug:
            print(f"    Preprocess: get_int failed for addr {hex(addr)}")
        return None

    if isinstance(payload, list) and len(payload) > 0:
        entry = payload[0]
        if isinstance(entry, dict):
            val = entry.get("value")
            if val is not None:
                return int(val) if isinstance(val, int) else int(str(val), 0)
    if debug:
        print(f"    Preprocess: unexpected get_int result for addr {hex(addr)}: {payload}")
    return None


async def _rename_func(session, func_va, func_name, debug=False):
    """Rename a function in IDA (best-effort)."""
    try:
        await session.call_tool(
            name="rename",
            arguments={
                "batch": {"func": {"addr": hex(func_va), "name": func_name}}
            },
        )
    except Exception:
        if debug:
            print(f"    Preprocess: failed to rename {func_name} at {hex(func_va)} (non-fatal)")


async def _resolve_func_from_global(session, gv_va, func_name, image_base, debug=False):
    """Read function pointer at gv_va + FUNC_PTR_OFFSET, generate sig, return YAML payload."""
    ptr_addr = gv_va + FUNC_PTR_OFFSET
    func_va = await _read_ptr_via_mcp(session, ptr_addr, debug=debug)
    if not func_va or func_va == 0:
        if debug:
            print(f"    Preprocess: null func ptr at {hex(ptr_addr)} for {func_name}")
        return None

    if debug:
        print(f"    Preprocess: {func_name} func_ptr at {hex(ptr_addr)} -> {hex(func_va)}")

    # Rename the function in IDA
    await _rename_func(session, func_va, func_name, debug=debug)

    # Generate a unique signature
    sig_info = await preprocess_gen_func_sig_via_mcp(
        session=session,
        func_va=hex(func_va),
        image_base=image_base,
        debug=debug,
    )
    if not sig_info:
        if debug:
            print(f"    Preprocess: failed to generate func_sig for {func_name}")
        return None

    func_rva = hex(func_va - image_base)
    return {
        "func_name": func_name,
        "func_va": hex(func_va),
        "func_rva": func_rva,
        "func_size": sig_info.get("func_size", hex(0)),
        "func_sig": sig_info["func_sig"],
    }


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Resolve think function addresses from schema globals + 0x28 offset."""
    _ = skill_name
    all_ok = True

    for func_name, gv_name in THINK_FUNCTIONS:
        output_filename = f"{func_name}.{platform}.yaml"
        output_path = None
        for p in expected_outputs:
            if os.path.basename(p) == output_filename:
                output_path = p
                break
        if not output_path:
            if debug:
                print(f"    Preprocess: no output path for {output_filename}")
            all_ok = False
            continue

        # --- Fast path: try signature reuse from old YAML ---
        old_yaml_path = old_yaml_map.get(output_filename)
        if old_yaml_path and os.path.exists(old_yaml_path):
            reuse_result = await preprocess_func_sig_via_mcp(
                session=session,
                new_path=output_path,
                old_path=old_yaml_path,
                image_base=image_base,
                new_binary_dir=new_binary_dir,
                platform=platform,
                func_name=func_name,
                debug=debug,
            )
            if reuse_result:
                write_func_yaml(output_path, reuse_result)
                if debug:
                    print(f"    Preprocess: {func_name} resolved via signature reuse")
                continue

        # --- Slow path: read function pointer from global + 0x28 ---
        gv_yaml_path = os.path.join(new_binary_dir, f"{gv_name}.{platform}.yaml")
        if not os.path.exists(gv_yaml_path):
            if debug:
                print(f"    Preprocess: missing global YAML {gv_yaml_path}")
            all_ok = False
            continue

        try:
            with open(gv_yaml_path, "r", encoding="utf-8") as f:
                gv_data = yaml.safe_load(f)
        except Exception:
            if debug:
                print(f"    Preprocess: failed to read {gv_yaml_path}")
            all_ok = False
            continue

        gv_va_str = gv_data.get("gv_va")
        if not gv_va_str:
            if debug:
                print(f"    Preprocess: no gv_va in {gv_yaml_path}")
            all_ok = False
            continue

        gv_va = int(str(gv_va_str), 16)
        payload = await _resolve_func_from_global(
            session, gv_va, func_name, image_base, debug=debug
        )
        if not payload:
            if debug:
                print(f"    Preprocess: failed to resolve {func_name} from global {hex(gv_va)}")
            all_ok = False
            continue

        write_func_yaml(output_path, payload)
        if debug:
            print(f"    Preprocess: generated {output_filename}")
            print(f"    Preprocess: renamed func {hex(int(payload['func_va'], 16))} -> {func_name}")

    return all_ok

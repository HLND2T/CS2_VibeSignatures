#!/usr/bin/env python3
"""Update CS2FOW runtime compatibility data from one symbol snapshot."""

from __future__ import annotations

import re
from pathlib import Path

MODULE_NAME = "CS2FOW"
MODULE_ENABLED = True
GENERATOR_API_VERSION = 2

GAMEDATA_PATH = "gamedata/cs2fow.games.txt"
OUTPUT_PATHS = (GAMEDATA_PATH,)
DOWNLOAD_SOURCES = [
    (
        "https://gitlab.com/karola3vax-group/cs2fow/-/raw/main/gamedata/cs2fow.games.txt?ref_type=heads",
        GAMEDATA_PATH,
    ),
]

SUPPORTED_PLATFORMS = {"windows", "linux"}
ASSIGNMENT_RE = re.compile(
    r"^(?P<prefix>[ \t]*(?P<key>[a-z0-9_]+)[ \t]*=[ \t]*)"
    r"(?P<value>[+-]?\d+)(?P<suffix>[ \t]*(?://.*)?)$"
)

BINARY_FIELDS = {
    "server_binary_size": "size",
    "server_binary_crc32": "crc32",
}

SYMBOL_FIELDS = {
    "recipient_slot_offset": ("server", "CCheckTransmitInfo_m_nPlayerSlot", "struct_member_offset"),
    "checktransmit_full_update_offset": (
        "server",
        "CCheckTransmitInfo_m_bFullUpdate",
        "struct_member_offset",
    ),
    "game_entity_system_offset": ("engine", "CGameResourceService_m_pEntitySystem", "struct_member_offset"),
    "game_event_manager_vtable_rva": ("server", "CGameEventManager_vtable", "vtable_rva"),
    "lookup_bone_rva": ("server", "CBaseModelEntity_FindBone", "func_rva"),
    "get_bone_transform_rva": ("server", "CBaseModelEntity_GetBoneTransform", "func_rva"),
    "create_entity_by_name_rva": ("server", "UTIL_CreateEntityByName", "func_rva"),
    "dispatch_spawn_rva": ("server", "CBaseEntity_DispatchSpawn", "func_rva"),
    "remove_entity_rva": ("server", "UTIL_Remove", "func_rva"),
    "teleport_vtable_index": ("server", "CBaseEntity_Teleport", "vfunc_index"),
    "smoke_volume_offset": ("server", "CSmokeGrenadeProjectile_m_SmokeVolume", "struct_member_offset"),
    "smoke_storage_offset": ("server", "SmokeVolume_m_pStorage", "struct_member_offset"),
    "smoke_frame_offset": ("server", "SmokeVolume_m_nFrame", "struct_member_offset"),
    "smoke_center_offset": ("server", "SmokeVolume_m_vecCenterOrigin", "struct_member_offset"),
    "smoke_start_time_offset": ("server", "SmokeVolume_m_flStartTime", "struct_member_offset"),
}


def _decimal(value, *, label):
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    try:
        parsed = int(value.strip(), 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not an integer: {value!r}") from exc
    if parsed < 0:
        raise ValueError(f"{label} must not be negative: {parsed}")
    return str(parsed)


def _crc32_decimal(value, *, label):
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a CRC32 value")
    try:
        parsed = int(value.strip(), 16) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not a CRC32 value: {value!r}") from exc
    if not 0 <= parsed <= 0xFFFFFFFF:
        raise ValueError(f"{label} is outside the CRC32 range: {parsed}")
    return str(parsed)


def _binary_value(context, platform, metadata_name):
    if context is None:
        raise ValueError("CS2FOW requires generator context")
    server = context.binaries.get("server")
    metadata = server.get(platform) if server else None
    if not metadata or metadata_name not in metadata:
        raise ValueError(f"snapshot binary metadata is missing: server.{platform}.{metadata_name}")
    value = metadata[metadata_name]
    label = f"server.{platform}.{metadata_name}"
    if metadata_name == "crc32":
        return _crc32_decimal(value, label=label)
    return _decimal(value, label=label)


def _symbol_value(yaml_data, platform, module_name, symbol_name, value_name):
    symbol = yaml_data.get(symbol_name)
    if not symbol or symbol.get("library") != module_name:
        raise ValueError(f"snapshot symbol is missing or belongs to the wrong module: {module_name}/{symbol_name}")
    platform_data = symbol.get(platform)
    if not platform_data or value_name not in platform_data:
        raise ValueError(f"snapshot value is missing: {module_name}/{symbol_name}.{platform}.{value_name}")
    return _decimal(
        platform_data[value_name],
        label=f"{module_name}/{symbol_name}.{platform}.{value_name}",
    )


def _replacement_values(yaml_data, platforms, context):
    requested_platforms = tuple(dict.fromkeys(platforms))
    unsupported = sorted(set(requested_platforms) - SUPPORTED_PLATFORMS)
    if unsupported:
        raise ValueError("CS2FOW does not support platforms: " + ", ".join(unsupported))
    if not requested_platforms:
        raise ValueError("CS2FOW requires at least one platform")

    replacements = {}
    metadata = {}
    for platform in requested_platforms:
        for key_prefix, metadata_name in BINARY_FIELDS.items():
            key = f"{key_prefix}_{platform}"
            replacements[key] = _binary_value(context, platform, metadata_name)
            metadata[key] = ("binary_metadata", platform)
        for key_prefix, (module_name, symbol_name, value_name) in SYMBOL_FIELDS.items():
            key = f"{key_prefix}_{platform}"
            replacements[key] = _symbol_value(
                yaml_data,
                platform,
                module_name,
                symbol_name,
                value_name,
            )
            metadata[key] = (value_name, platform)
    return replacements, metadata


def _line_ending(line):
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith(("\r", "\n")):
        return line[:-1], line[-1]
    return line, ""


def _replace_assignments(content, replacements):
    seen = set()
    updated_lines = []
    for line in content.splitlines(keepends=True):
        body, ending = _line_ending(line)
        match = ASSIGNMENT_RE.fullmatch(body)
        key = match.group("key") if match else None
        if key not in replacements:
            updated_lines.append(line)
            continue
        if key in seen:
            raise ValueError(f"CS2FOW gamedata contains duplicate assignment: {key}")
        seen.add(key)
        updated_lines.append(f"{match.group('prefix')}{replacements[key]}{match.group('suffix')}{ending}")

    missing = sorted(set(replacements) - seen)
    if missing:
        raise ValueError("CS2FOW gamedata is missing assignments: " + ", ".join(missing))
    return "".join(updated_lines)


def update(
    yaml_data,
    func_lib_map,
    platforms,
    output_dir,
    alias_to_name_map,
    debug=False,
    *,
    context,
):
    """Update the downloaded flat key=value compatibility file."""
    del func_lib_map, alias_to_name_map
    gamedata_path = Path(output_dir) / GAMEDATA_PATH
    raw = gamedata_path.read_bytes()
    has_bom = raw.startswith(b"\xef\xbb\xbf")
    content = raw.decode("utf-8-sig" if has_bom else "utf-8")
    replacements, metadata = _replacement_values(yaml_data, platforms, context)
    updated_content = _replace_assignments(content, replacements)
    encoded = updated_content.encode("utf-8")
    gamedata_path.write_bytes((b"\xef\xbb\xbf" if has_bom else b"") + encoded)

    updated_symbols = []
    if debug:
        updated_symbols = [
            {"name": key, "type": metadata[key][0], "platform": metadata[key][1]} for key in replacements
        ]
    return len(replacements), 0, updated_symbols, []

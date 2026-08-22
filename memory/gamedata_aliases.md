---
title: gamedata_aliases
type: note
permalink: cs2-vibesignatures/gamedata-aliases
tags:
- gamedata
- alias
- config
---

# Gamedata Aliases

## Overview
Downstream gamedata keys are resolved at generation time from merged config. The snapshot stores canonical names and artifacts only; it has no alias fields.

## Invariants
- `[fact]` `alias` maps a downstream gamedata key to the canonical symbol name.
- `[fact]` `source_alias` is an artifact-filename fallback only; it never becomes a downstream name.
- `[fact]` Generators do not read `gamesymbols/<GAMEVER>.yaml` aliases (there are none) or `gamesymbols/<GAMEVER>.metadata.yaml`.
- `[decision]` Pages alias metadata is a separate freeze of base-config `alias` for the website; gamedata publish recomputes maps from live config + overlay. See [[gamesymbol_metadata]].

## Resolution at publish
For each generator, `update_gamedata.generate_gamedata`:
1. Load `configs/<GAMEVER>.yaml`.
2. If `gamedata-generators/<module>/config.yaml` exists, `merge_configs()` overlays it (same module/symbol: extra fields override, including `alias`).
3. `build_alias_to_name_map(merged)` → `{downstream_key: canonical}` from the `alias` field only.
4. `load_all_yaml_data()` keys `yaml_data` by canonical name; `yaml_data[name]["aliases"]` comes from `downstream_aliases()` = config `alias` + patch compat.

Name match in generators:
- Default: `normalize_func_name_colons_to_underscore(gamedata_key, alias_to_name_map)` then `yaml_data.get(...)`.
- Map miss falls back to replacing `::` with `_`.
- CS2Fixes `Patches` builds a patch-only map from `yaml_data[*].aliases` so patch short names cannot collide with same-named offsets/signatures.

## Artifact load vs downstream names
`source_candidate_names()` tries snapshot files in order: canonical name, then `source_alias`, then patch compat. Config `alias` is **not** a YAML filename candidate.

`PATCH_COMPAT_ALIASES` (`gamedata_symbol_config.py`) is appended for `category=patch` to both downstream aliases and source filenames:
- `CCSPlayer_MovementServices_FullWalkMove_SpeedClamp` → `ServerMovementUnlock`
- `CCSPlayer_MovementServices_CheckJumpButton_WaterPatch` → `CheckJumpButtonWater`, `FixWaterFloorJump`
- `CCSBotManager_AddBot_BotNavIgnore` → `BotNavIgnore`

Those names are also declared in base-config `alias`; the table is a compatibility layer, not the only source.

## Overlay aliases
Per-generator extras currently in `gamedata-generators/*/config.yaml`:
- CS2Fixes: `CTakeDamageInfo_ctor`→`CTakeDamageInfo`; `CBaseEntity_Teleport`→`Teleport`; `ScriptBinding_CBaseModelEntity_SetModel`→`CS_Script_SetModel`
- cs2kz / cs2surf: `s_GameEventManager`→`GameEventManager`
- modsharp: `gameeventmanager`→`g_GameEventManager`
- swiftlys2: `CSource2Server_Init`→`CSource2Server::g_GameEventManager`

## Involved Files
- `gamedata_symbol_config.py` — `downstream_aliases`, `source_candidate_names`, `PATCH_COMPAT_ALIASES`.
- `gamedata_symbol_data.py` — `build_alias_to_name_map`, `merge_configs`, `load_all_yaml_data`.
- `gamedata_utils.py` — `normalize_func_name_colons_to_underscore`.
- `gamedata-generators/*/config.yaml` — overlay aliases.
- `gamedata-generators/CS2Fixes/gamedata.py` — patch-only alias map.

## Relations
- part_of [[update_gamedata]]
- requires [[config_yaml]]
- contrasts_with [[gamesymbol_metadata]]

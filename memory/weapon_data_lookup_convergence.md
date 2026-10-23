---
title: weapon_data_lookup_convergence
type: note
permalink: cs2-vibesignatures/weapon-data-lookup-convergence
---

# Weapon data lookup convergence

## Trigger
Dispatch Build After Bump Merge #620 (run 39972357015) failed exact release artifact verification for 14192: one extra `server/GetCSWeaponDataFromKey.linux.yaml`. PR #1175's successful validation had skipped the optional output after an empty LLM response.

## Root cause and constraints
The old smoke-grenade intermediate helper is inlined in 14192 Linux. Its legacy anchor artifact already pointed to the final `(type, string_key)` lookup at `0xef8b80`. A second LLM chain link followed its tail jump into `0xef8320`, the internal `(table, type, hash)` lookup, and assigned the public name to the wrong function. Optional absence is allowed by planning but does not relax exact presence/byte equality during release rebuilding. Neither a successful IDA step nor a unique signature proves semantic identity.

## Correct approach
Use the bounded deterministic scanner in `ida_preprocessor_scripts/_weapon_data_from_key_common.py` for both active Linux links. Require the string-argument null guard and Murmur seed/multiplier, plus type 1 at candidate call sites. Reject zero or multiple candidates and failed signature generation. Preserve a genuine wrapper when present; when the wrapper collapses, retain the legacy dependency filename while emitting the verified target's semantic name. Avoid hardcoding addresses or accepting an internal tail target by chain depth alone.

## Verification
Six behavioral regressions cover collapsed and genuine wrapper chains, the internal-query false positive, ambiguity, missing input, and signature failure. Two fresh real-MCP replays with empty old maps generate identical canonical artifacts at `0xef8b80`, signature `55 31 D2 48 89 E5 41 57 41 56 41 55 41 54 41 89 FC`, size `0x194`. Both affected 14192 Linux YAMLs have SHA-256 `c179d4db9a640c837078fee2d6278909061b228e6f28880c9340ef6843e55ff4`. Inventory is 4010 files; other 4008 files match the failed run. See `docs/ida_validation_failure-14192.md` for run IDs and evidence.

## Scope
Linux GetCSWeaponDataFromKey and its legacy smoke-grenade anchor. Windows helper handling and the quarantined inlined finder remain unchanged. An old immutable run cannot consume a working-tree repair: publish from a new source commit containing both generators and artifacts.

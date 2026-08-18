---
title: _igamesystem_dispatch_common
type: note
permalink: cs2-vibesignatures/igamesystem-dispatch-common
---

# _igamesystem_dispatch_common

## Overview
`ida_preprocessor_scripts/_igamesystem_dispatch_common.py` is the shared preprocess entry for IGameSystem dispatch-style skills. The design is deterministic: collect all dispatch calls first, then map targets by stable `vfunc_index`/`vfunc_offset` ordering.

## Current Design
### 1) Collect all dispatch entries
- `_build_dispatch_py_eval(...)` collects all candidates from the source function (or resolved internal wrapper).
- Windows path: scans `lea rdx, callback`, then parses callback `call/jmp [reg+disp]`.
- Linux path: scans `mov esi/rsi, odd_imm` + next `call`, computes `vfunc_off = imm - 1`.
- Only non-negative, 8-byte aligned offsets are accepted.

### 2) Strict count validation
- `expected_dispatch_count` controls the required total entry count.
- Validation requires `len(entries) == expected_dispatch_count`.
- If omitted:
  - without `dispatch_rank`: defaults to `target_count`
  - with `dispatch_rank`: defaults to `max(dispatch_rank) + 1`

### 3) Stable mapping with dispatch_rank
- `target_specs` fields:
  - `target_name` (required)
  - `rename_to` (optional)
  - `dispatch_rank` (optional)
- If `dispatch_rank` is used:
  - all specs must provide it
  - ranks must be unique and non-negative
  - entries are sorted by `(vfunc_index, vfunc_offset)`
  - each target picks by rank
- If `dispatch_rank` is not used:
  - mapping uses scan order for selected entries
  - `expected_dispatch_count` must equal `target_count`

## Public API Snapshot
`preprocess_igamesystem_dispatch_skill(...)` relevant args:
- `target_specs`
- `multi_order` (`scan` / `index`)
- `expected_dispatch_count=None`
- `debug=False`

## Behavior Notes
- Fail-fast on validation/extraction mismatch (`False` return).
- `multi_order == "index"` is honored for multi-target mapping.
- If `dispatch_rank` is present, stable index sorting is forced even with `multi_order="scan"`.
- Internal/callback renaming remains best-effort (non-fatal).

## Updated Callers (current)
### SpawnGroup series
- `find-IGameSystem_OnPreSpawnGroupLoad.py`
  - `dispatch_rank=0`
  - `EXPECTED_DISPATCH_COUNT=2`
- `find-IGameSystem_OnPostSpawnGroupLoad.py`
  - `dispatch_rank=1`
  - `EXPECTED_DISPATCH_COUNT=2`
- `find-IGameSystem_OnPostSpawnGroupUnload.py`
  - `dispatch_rank=1`
  - `EXPECTED_DISPATCH_COUNT=2`
- `find-IGameSystem_OnPreSpawnGroupUnload.py`
  - single-target default mapping

### ClientPreEntityThink case
- `find-IGameSystem_OnClientPreEntityThink.py`
  - observed dispatch indices: `22 / 23 / 24`
  - `IGameSystem_OnClientPreEntityThink` uses `dispatch_rank=0` (index 22)
  - `EXPECTED_DISPATCH_COUNT=3`

## Rationale
Mapping now relies on deterministic index ordering plus strict entry-count assertions, which is more stable under compiler/reordering differences.

### SpawnGroupPrecache / SpawnGroupUncache
- `find-IGameSystem_OnSpawnGroupPrecache.py`
  - source: `CSpawnGroupMgrGameSystem_OnSpawnGroupPrecache`
  - single-target default mapping (1 dispatch)
- `find-IGameSystem_OnSpawnGroupUncache.py`
  - source: `CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown`
  - `dispatch_rank=0`
  - `EXPECTED_DISPATCH_COUNT=2`

## De-inline fallback + dedup (14168)

`_build_dispatch_py_eval` and the collect step were hardened for two 14168 codegen changes seen in the `CLoopModeGame_OnServer*AsyncPostTickWork` family:

- **De-inline fallback (Windows).** When the source-function scan yields **0**
  entries, the per-event dispatcher was split into separate callee functions
  (e.g. `sub_180BCAA30`/`sub_180BCA960`). The script then walks the source's
  direct callees **in call order** and scans those carrying the
  `mov rax, gs:58h` marker (`65 48 8B 04 25 58 00 00 00`), aggregating their
  entries. Result JSON gains `deinlined_dispatchers` (list of hex VAs) for
  debug. Trigger is "0 source entries" (Linux stays inlined → never fires;
  the gs:58h marker is Windows-only).
- **Dedup by `vfunc_offset` (Linux).** 14168 routes index resolution through a
  helper (e.g. `sub_1719D00(&guard, imm, 0)`) that reuses the same
  `mov esi, imm; call` shape as `IGameSystem_DispatchCall`, so one event can
  surface multiple times. `_dedup_entries_by_offset` (in
  `preprocess_igamesystem_dispatch_skill`, before the count check) keeps the
  first occurrence per offset. Safe/no-op for already-unique scans.
- The generated py_eval now defines helper functions, so it MUST include the
  `globals().update(locals())` bridge (see [[py_eval]]).

`find-IGameSystem_OnServerBeginAsyncPostTickWork` became a 2-target producer
(`MULTI_ORDER="index"`, mirroring the End `-AND-` sibling) because 14168
inserted a NEW event `OnServerPreBeginAsyncPostTickWork` at vtable idx 41,
pushing the real `OnServerBeginAsyncPostTickWork` down to idx 42 (the same
insertion shifted End Pre/Post 42/43 -> 43/44). Index-order maps
target[0]=Pre (idx 41), target[1]=Begin (idx 42) -- do NOT assume the old
index maps to the same event across a gamever. The skill file keeps its
original (non-`-AND-`) name but declares both outputs. Validated end-to-end
on 14168 windows+linux (Pre==IGameSystem_vtable[41], Begin==[42]). Tests:
`tests/test_igamesystem_dispatch_common.py`.

## Files Involved
- `ida_preprocessor_scripts/_igamesystem_dispatch_common.py`
- `ida_preprocessor_scripts/find-IGameSystem_OnPreSpawnGroupLoad.py`
- `ida_preprocessor_scripts/find-IGameSystem_OnPostSpawnGroupLoad.py`
- `ida_preprocessor_scripts/find-IGameSystem_OnPostSpawnGroupUnload.py`
- `ida_preprocessor_scripts/find-IGameSystem_OnPreSpawnGroupUnload.py`
- `ida_preprocessor_scripts/find-IGameSystem_OnSpawnGroupPrecache.py`
- `ida_preprocessor_scripts/find-IGameSystem_OnSpawnGroupUncache.py`
- `ida_preprocessor_scripts/find-IGameSystem_OnClientPreEntityThink.py`

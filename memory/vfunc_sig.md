---
title: vfunc_sig
type: note
permalink: cs2-vibesignatures/vfunc-sig
---

# vfunc_sig

## Overview
`vfunc_sig` is the virtual-call relocation signature used when `func_sig` is unavailable or unstable. It now supports the same conservative cross-function-boundary generation switch as `gv_sig`, while remaining default-closed.

## Field Context
- Related YAML fields: `vfunc_sig`, `vtable_name`, `vfunc_index`, `vfunc_offset`, `vfunc_sig_max_match`.
- Auxiliary generation metadata: `vfunc_sig_va`, `vfunc_sig_disp`, `vfunc_inst_length`, `vfunc_disp_offset`, `vfunc_disp_size`.
- Optional generation/persistence field: `vfunc_sig_allow_across_function_boundary`.

## Generation Principle
- Canonical auto-generation is implemented by `preprocess_gen_vfunc_sig_via_mcp` in `ida_analyze_util.py`.
- Input anchor is the known virtual-call instruction address `inst_va` and the expected slot displacement `vfunc_offset`.
- Signature starts at the virtual-call instruction itself (`vfunc_sig_disp = 0`).
- The first instruction remains fully fixed, including the displacement bytes that encode the slot identity; subsequent instructions may wildcard volatile operands and branch displacements.
- Default behavior is fail-closed at the owning function boundary (`limit_end = min(f.end_ea, target_inst + max_sig_bytes)`).
- Optional directive `vfunc_sig_allow_across_function_boundary: true` enables collection past `f.end_ea` through the shared `_build_signature_boundary_py_eval_helpers()` logic.
- Cross-boundary collection uses the same conservative rules as `gv_sig`: same executable segment only, only `0xCC` / `0x90` padding may appear between functions, zero-padding handoff directly to the next IDA code head is allowed, and decoding resumes only at an IDA-marked code head.
- Directive parsing is strict via `_normalize_generate_yaml_desired_fields`; bare directives, duplicate directives, and non-`true` values are rejected.
- `vfunc_sig_max_match` remains an explicit directive and still requires `vfunc_sig` to be requested.
- Candidate acceptance uses `find_bytes(limit=max_match_count + 1)` and requires:
  - `1 <= match_count <= max_match_count`
  - the target `inst_va` is included in the match set
- The shortest accepted candidate becomes `vfunc_sig`.

## Usage Method
- In `preprocess_func_sig_via_mcp`, `vfunc_sig` remains a fallback relocation path when old YAML has no `func_sig`.
- Required metadata:
  - `vfunc_sig`
  - `vtable_name`
  - and `vfunc_index` or `vfunc_offset`
- Flow:
  1. Unique-/bounded-match `vfunc_sig` in the new binary.
  2. Load or generate target vtable YAML.
  3. Resolve function VA via `vtable_entries[vfunc_index]`.
  4. Query function info and emit function YAML with vfunc metadata.
- In `preprocess_common_skill`, LLM/direct generation paths pass `vfunc_sig_allow_across_function_boundary` into `_preprocess_direct_func_sig_via_mcp` and `_build_enriched_slot_only_vfunc_payload_via_mcp`; the final YAML writes `vfunc_sig_allow_across_function_boundary: true` only when the directive is explicitly enabled.

## Downstream Use
- Dist gamedata modules mainly consume `vfunc_index` / `vfunc_offset` metadata, not `vfunc_sig` directly.
- `vfunc_sig` is primarily used by analysis/preprocess relocation pipelines.

## Practical Notes
- Use `vfunc_sig` when function-head signatures are weak but vtable slot identity is stable.
- Keep `vfunc_index` / `vfunc_offset` internally consistent (`offset = index * 8` in current 64-bit assumptions).
- Slot `0x0` may be implicit in machine code such as `call qword ptr [rax]`; `preprocess_gen_vfunc_sig_via_mcp` accepts this only for `call`/`jmp` memory operands without encoded displacement and reports `vfunc_disp_size: 0`.
- `vfunc_sig_allow_across_function_boundary` expands generation breadth only; it does not change the slot-specific first-instruction requirement or the vtable-based relocation flow, except for the explicit implicit-zero-slot case.
- Reject non-unique or over-broad signatures.
- `vfunc_sig`/`vfunc_sig_disp` may legitimately differ between two runs that picked different vcall sites for the same slot; PR and Release validation tolerate exactly that while pinning `vfunc_offset`/`vfunc_index` and `func_va`. Read [[anchor_drift]] before relying on these fields being reproducible.

## SetOwner: a unique old signature can migrate to a sibling call (#1088)

- Trigger: 14184 Linux `CBaseEntity_SetOwner` retained slot 52 (`0x1a0`), while the live setter is slot 53 (`0x1a8`).
- Root cause/constraint: the old seven-byte signature `4C 8B A8 A0 01 00 00` still uniquely matches, but inside
  `0x15816c0`, not the reference caller `CCSPlayer_WeaponServices_EquipWeapon` (`0x15f7c60`). The slot-only fast path
  used to carry the old index forward without checking the caller or target identity. This reproduces a sufficient
  failure path; historical run logs are not available to establish which path originally wrote the artifact.
- Correct practice: `_set_owner_anchor.py` requires a current EquipWeapon site whose CBaseEntity slot resolves to
  a two-argument function comparing the incoming owner against an entity-handle lookup (`>> 9`, `& 0x1ff`).
  The finder checks both old-signature reuse and LLM results against these sites; missing/ambiguous evidence fails closed.
- Validation: 14184 live Linux anchor `0x15f7cd6` resolves slot 53 to `0x1881fc0`; Windows `0x180b00845` resolves slot 54
  to `0x180d094c0`. The Linux signature regenerated by the normal signature helper is
  `4C 8B A8 A8 01 00 00 48 85 F6`. `tests/test_set_owner_anchor.py` covers stale/foreign anchors, slot mismatches,
  ambiguous evidence, callee inspection, and finder integration. Corrected pinned values must be explicitly committed;
  do not relax the anchor-drift contract.
- Scope/limits: this semantic guard is SetOwner-specific. Static inspection found 195 distinct symbols declaring
  `found_vcall`, but did not establish a second incorrect target; that is not a semantic certification of those symbols.
  A binary scan of 333 statically resolvable platform artifacts found nine signatures outside their declared reference
  caller (confirmed against IDB function chunks): Linux `IEngineService_GetName`, `IEngineService_GetServiceDependencies`,
  `IGameResourceService_FreeGameResourceManifest`, `ILoopModeFactory_GetLoopModeType`, `ILoopModeFactory_Shutdown`,
  `CBasePlayerPawn_OnTakeDamage_Dead`, `CBasePlayerPawn_OnTakeDamage_Dying`, `IVEngineServer2_GetClientSteamID`, and Windows
  `CBasePlayerPawn_OnTakeDamage_Dead`. These are semantic-audit candidates, not confirmed wrong slots: another caller can
  legitimately dispatch the same method. Do not globally reject all foreign-caller signatures or infer identity from
  a class-wide Windows/Linux slot delta.
  Historical reference VAs/offsets are examples, not current binary facts. Hex-Rays omits the owner argument at the
  Linux indirect call even though assembly loads RSI from `[r12+0x38]`; inspect the callee and machine code instead of
  rejecting a reference solely on inferred caller argument counts.

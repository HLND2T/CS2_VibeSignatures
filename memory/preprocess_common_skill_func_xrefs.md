---
title: preprocess_common_skill_func_xrefs
type: note
permalink: cs2-vibesignatures/preprocess-common-skill-func-xrefs
---

# preprocess_common_skill func_xrefs

## Summary
- `preprocess_common_skill` only accepts `dict`-style `func_xrefs`
- The allowed fields are fixed to:
  - `func_name`
  - `xref_strings`
  - `xref_gvs`
  - `xref_signatures`
  - `xref_funcs`
  - `exclude_funcs`
  - `exclude_strings`
  - `exclude_gvs`
  - `exclude_signatures`
  - `exclude_callees`
- The positive sources `xref_strings` / `xref_gvs` / `xref_signatures` / `xref_funcs` cannot all be empty at the same time

## Contract
- The old tuple schema is no longer supported; any match is treated as invalid configuration immediately
- `exclude_strings` and `exclude_gvs` are global exclusion sets: they are subtracted after the positive intersection
- `exclude_callees` is the inverse of `xref_funcs`: it subtracts candidates that CALL the named function(s) (callers of the callee, collected via `_collect_xref_func_starts_for_ea` on the callee's `func_va`). Use it when the collider is unnamed (so `exclude_funcs`, which drops the func itself, cannot address it) and is separated only by a callee the target lacks. Depends on the callee's current-version func YAML (`func_va`); list it in `expected_input`
- `exclude_signatures` is checked only within the remaining candidate functions; a match excludes that candidate function
- Missing hits for `exclude_strings` and `exclude_gvs` are not treated as failures; they are simply treated as empty exclusion sets
- Each element in `xref_gvs` / `exclude_gvs` can be either a gv symbol name or an explicit `0x...` address literal

## Operational notes
- When `xref_gvs` / `exclude_gvs` use symbol names, they depend on the corresponding YAML `gv_va`; when they use explicit `0x...` addresses, xrefs are queried directly by EA
- `xref_funcs` / `exclude_funcs` depend on the corresponding YAML `func_va`
- `_can_probe_future_func_fast_path` only checks func/gv symbols that truly depend on YAML; explicit `0x...` addresses do not block the fast path
- Therefore, a gv-xref configuration made entirely of explicit addresses can work even without `new_binary_dir`; but once symbol-based gv / func dependencies are mixed in, the corresponding YAML files must still already exist
- `CCSPlayer_MovementServices_ProcessMovement` uses `CPlayer_MovementServices_s_pRunCommandPawn` as the gv-xref fallback source

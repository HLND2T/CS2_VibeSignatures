---
title: anchor_drift
type: note
permalink: cs2-vibesignatures/anchor-drift
---

# Anchor Drift

## Overview
`gamesymbol_snapshot_lib/anchor_drift.py` decides whether a rebuilt `bin_artifacts` payload that differs from Git truth
is a legal resampling of the same symbol. An `LLM_DECOMPILE` producer lets the model pick one reference instruction and
expands a deterministic signature from it, so two equally rule-conformant runs may select different instructions. Only
the fields describing *how* a symbol was located may differ; identity and the resolved address/offset stay byte-exact.

## Contract
- `gv`: anchor `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`; pinned `gv_name`, `gv_va`, `gv_rva`.
- `vfunc`: anchor `vfunc_sig`, `vfunc_sig_disp`; pinned `func_name`, `func_va/rva/size`, `func_sig`, `vtable_name`, `vfunc_offset`, `vfunc_index`, `vfunc_slot_size`.
- `structmember`: anchor `offset_sig`, `offset_sig_disp`; pinned `struct_name`, `member_name`, `offset`, `size`.
- `func`, `vtable`, `patch`: no anchor group. Their signatures are anchored at the resolved address, and a `patch`
  without `patch_va` has nothing but `patch_sig` to identify it.
- Search-policy switches (`*_max_match`, `*_allow_across_function_boundary`) are never anchors: tolerating them accepts a
  different search, not an equivalent sampling of the same one.
- `require_keys` gate: a spec applies only when the resolved fact is present on both sides, so a payload whose signature
  is its only truth keeps the byte-exact gate.
- Key-set changes, unparseable payloads, explicit-null numeric anchors, and incoherent globals
  (`gv_inst_disp + 4 > gv_inst_length`, zero `gv_inst_length`) all fail closed.

## Consumers
- `release_artifact_rebuild.py::_verify_release_rebuild` - accepts drift, then binds the release to the **committed**
  inventory digest rather than the rebuilt one.
- `release_bundle.py::build_release_bundle` - publishes snapshot/gamedata/archives from tracked `bin_artifacts` in both
  binding modes, so a drifted rebuild never ships bytes the checkout does not own.
- `trusted_artifact_pr.py::_validate_isolated_rebuild` - accepts drift per artifact and substitutes the rebuilt payload's
  own sha256 into the producer-group `output_sha256` gate, so an accepted drift cannot launder a payload the run did not
  write. Inherited (not re-executed) paths stay byte-exact against the base tree.

## Notes
- Both sides of a comparison are already canonical (`canonical_symbol_yaml_bytes`); the numeric validation is fail-closed
  defense in depth, not normalization.
- Every accepted drift is printed as `Anchor drift accepted for <path>: <field> <before> -> <after>`.
- Field provenance per category is documented in [[symbol_yaml]], [[gv_sig]], [[vfunc_sig]], and [[offset_sig]].

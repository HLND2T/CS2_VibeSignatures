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

# offset_sig

## Overview
`offset_sig` is the relocation signature used to recover struct-member offsets across versions. It now supports the same conservative cross-function-boundary generation switch as `gv_sig`, while remaining default-closed.

## Field Context
- Related YAML fields: `struct_name`, `member_name`, `offset`, `size`, `offset_sig`, `offset_sig_disp`.
- Optional generation/persistence field: `offset_sig_allow_across_function_boundary`.

## Generation Principle
- Canonical auto-generation is implemented by `preprocess_gen_struct_offset_sig_via_mcp` in `ida_analyze_util.py`.
- Input anchor is the known `offset_inst_va` plus the expected `offset`; `size` is carried through when available.
- Signature is built forward from the target instruction, and current auto-generation emits `offset_sig_disp = 0`.
- Volatile operand bytes and branch displacements are wildcarded; caller-specified extra wildcard offsets are also supported.
- Default behavior is fail-closed at the owning function boundary (`limit_end = min(func.end_ea, target_inst + max_sig_bytes)`).
- Optional directive `offset_sig_allow_across_function_boundary: true` enables collection past `func.end_ea` through the shared `_build_signature_boundary_py_eval_helpers()` logic.
- Cross-boundary collection uses the same conservative rules as `gv_sig`: same executable segment only, only `0xCC` / `0x90` padding may appear between functions, zero-padding handoff directly to the next IDA code head is allowed, and decoding resumes only at an IDA-marked code head.
- Directive parsing is strict via `_normalize_generate_yaml_desired_fields`; bare directives, duplicate directives, and non-`true` values are rejected.
- Candidate acceptance requires:
  - exactly one `find_bytes(limit=2)` match
  - matched address equals `offset_inst_va`
- The shortest accepted candidate becomes `offset_sig`.

## Usage Method
- In `preprocess_struct_offset_sig_via_mcp`, old `offset_sig` is reused to recover the new `offset`.
- Flow:
  1. Load `struct_name`, `member_name`, `offset_sig`, optional `offset_sig_disp`, optional `size`.
  2. Unique-match `offset_sig` -> `sig_addr`.
  3. Compute instruction address: `inst_addr = sig_addr + offset_sig_disp` (default `0`).
  4. Decode instruction and inspect operand positions (`offb/offo`) and candidate sizes.
  5. Extract displacement/immediate candidates; prefer candidates matching the old offset when available.
  6. Emit new YAML with updated `offset`, carrying `offset_sig` and optional metadata.
- In `preprocess_common_skill`, the struct-member direct generation path passes `_struct_gen_opts.get("offset_sig_allow_across_function_boundary", False)` into `preprocess_gen_struct_offset_sig_via_mcp` and writes `offset_sig_allow_across_function_boundary: true` only when the directive is explicitly enabled.

## Practical Notes
- Multi-hit `offset_sig` is rejected.
- Non-zero `offset_sig_disp` means the signature starts before the target instruction, but current auto-generation prefers `0`.
- `offset_sig_allow_across_function_boundary` expands generation breadth only; the relocation path and offset re-derivation logic are unchanged.
- Weak signatures (too short / too wildcarded) reduce long-term reliability.

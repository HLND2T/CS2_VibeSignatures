---
name: fix-cppheaders
description: |
  Use when hl2sdk_cs2 C++ headers must be repaired to match the latest vtable or record-layout YAML references.
  Runs run_cpp_tests.py to obtain layout diffs, maps failing cpp_tests entries to their configured headers, edits only
  those headers, and repeats validation until the differences are resolved. Triggers: fix cpp headers, fix-cppheaders,
  repair vtable layout, repair record layout, header layout differences.
disable-model-invocation: true
---

# Fix C++ Headers

## Overview

Repair `hl2sdk_cs2` declarations from compiler-versus-YAML layout differences. Treat
`run_cpp_tests.py` as the source of truth for both the initial diff and final verification.

Resolve `GAMEVER` from the user's explicit request or `CS2VIBE_GAMEVER`; use only
`configs/$GAMEVER.yaml` for test definitions and fail if it is missing.

## Constraints

- Edit only header paths listed in the failing `configs/<GAMEVER>.yaml` `cpp_tests` entry.
- Require every edited header to be under `hl2sdk_cs2/`.
- Preserve existing names and style when the reference exposes only a slot or offset.
- Keep compiler declarations for gaps in incomplete reference YAMLs unless surrounding index shifts prove removal.
- Name unknown virtual slots consistently with nearby declarations, such as `unk_001`; when only a known function name is
  available, use `virtual void FunctionName() = 0;` until a reliable prototype is known.
- Interpret `Class_dtor` and `Class_vdtor` reference entries as virtual destructors for `Class`.
- Do not edit reference YAMLs, generated files under `bin/`, cpp test sources, or comparison code to hide a difference.
- Do not invoke an external agent runner. This SKILL owns the repair loop directly.
- Stop and report a blocker when the diff is ambiguous, the configured header is missing, or a required edit is outside
  `hl2sdk_cs2/`.

## Workflow

1. Determine the game version from the user's request. If omitted, read `CS2VIBE_GAMEVER` from `.env`.
2. Resolve the immutable symbol snapshot. Use a caller-provided actual candidate when available; otherwise use the
   published historical snapshot at `gamesymbols/<gamever>.yaml`. Never read reference YAML directly from `bin`.
3. Run the complete comparison with debug details:

   ```powershell
   uv run run_cpp_tests.py -gamever <gamever> -configyaml configs/<gamever>.yaml -snapshot <snapshot> -debug
   ```

4. For each test reporting layout differences, find its `cpp_tests` entry in `configs/<GAMEVER>.yaml` and read its `symbol`,
   `headers`, target, aliases, and reference modules.
5. Read the configured headers and the complete diff sections:
   - `Current vtable entries` versus `YAML reference vtable entries`
   - `Current record members` versus `YAML reference struct members`
6. Make the smallest declaration-only edit that aligns the header with the reference. Typical edits are reordering,
   adding, or removing virtual declarations; correcting inheritance; and adjusting record members or padding.
7. Re-run the same command with the same snapshot. If differences remain, use the new output rather than the previous
   diff and repeat.
8. Finish only when the command exits successfully with zero compile failures, invalid items, and layout differences.

## Failure Handling

- If compilation fails after an edit, inspect the compiler error, repair the edited declaration, and rerun.
- If unrelated pre-existing failures prevent a clean full run, verify the affected test output as far as the runner permits
  and report the unrelated failures verbatim.
- If `headers` is absent or empty, do not guess an edit target. Report the test name and request a config correction.
- If multiple headers are configured, trace the declared symbol before choosing the file; do not edit every header blindly.

## Completion Report

Report the headers changed, the layout mismatches corrected, and the exact final verification command and result.

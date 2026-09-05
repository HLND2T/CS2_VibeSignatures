---
title: run_cpp_tests
type: note
permalink: cs2-vibesignatures/run-cpp-tests
---

# run_cpp_tests

## Overview
`run_cpp_tests.py` deterministically compiles and validates C++ layouts against an explicit immutable snapshot candidate derived from validated `bin_artifacts`. It probes clang targets, compares vtable/record layouts, reports exact differences, and returns non-zero on validation failure.
## Responsibilities

- Parse config path, mandatory snapshot path, game version, clang path, C++ standard, and debug options.
- Open the snapshot through `SnapshotSymbolStore` and reject version, config-digest, schema, or canonical-byte mismatch.
- Validate `cpp_tests` entries and compile supported targets.
- Compare vtable layouts when `fdump-vtable-layouts` is configured.
- Compare record layouts when `fdump-record-layouts` is configured.
- Compare every configured `reference_module` and report structured differences.
- Return failure for compile errors, invalid test entries, or layout differences.

## Header Repair Boundary
- Use `.claude/skills/fix-cppheaders/SKILL.md` for header repair.
- Build or receive one release-local candidate from the validated artifact tree, then run `uv run run_cpp_tests.py -gamever <gamever> -configyaml configs/<gamever>.yaml -snapshot <candidate> -debug`.
- `cpp_tests[].headers` maps a failing test to allowed `hl2sdk_cs2` edit targets.
- Never fall back to tracked `gamesymbols/` or per-symbol YAML in `bin/`; never edit `bin_artifacts` to hide a header mismatch.
## Involved Files
- `run_cpp_tests.py`
- `cpp_tests_util.py`
- `configs/<GAMEVER>.yaml`
- `.claude/skills/fix-cppheaders/SKILL.md`
- explicit release-local candidate snapshot
- `gamesymbol_store.py` / `SnapshotSymbolStore`
## Notes

- `additional_compiler_options` and `additional_compile_options` are both accepted.
- Unsupported target triples are skipped rather than failed.
- Missing `symbol`, `cpp`, or `target`, and missing C++ sources, are invalid test failures.
- If target-to-platform mapping fails, compilation can pass while comparison is skipped with notes.

## Callers

- CLI: `uv run run_cpp_tests.py -gamever <gamever> -snapshot <snapshot> [-debug]`
- Header repair: invoke the `fix-cppheaders` SKILL.

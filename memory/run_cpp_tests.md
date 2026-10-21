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
- `cpp_tests[].headers` maps a failing test to allowed `s2sdk` edit targets.
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

## s2sdk compilation compatibility
- Trigger: C++ tests fail after migrating from hl2sdk to s2sdk (`a54d726d1693ffffe59f101f480d6d76c79a7fc6`).
- Root cause: engine interfaces moved into `public/engine2`, convars into `public/tier0`, and INetChannel into `public/networksystem`. Legacy test include-guard overrides and local CPlayerUserId/ChangeAccessorFieldPathIndex_t/NetChannelBufType_t definitions conflict with SDK declarations.
- Correct approach: include the real SDK headers, remove obsolete fake definitions/guard overrides, and keep only an opaque CPlayerBitVec forward declaration where the SDK references the game-side type. INetworkGameServer uses GetMaxClients to request its layout because PreWorldUpdate is absent in this SDK.
- Configuration: route each cpp_tests.headers entry to its actual defining header; engine service/loop tests need `s2sdk/common` for language.h, network-system tests need `s2sdk/public/mathlib`, and protobuf-dependent tests need the existing `cpp_tests/stubs` directory. Match SDK header casing exactly.
- Verification: compile every distinct command from all configs on Windows/MSVC and Linux/Itanium, then parse each emitted vtable/record dump to confirm the requested symbols exist. Compilation and dump presence do not establish snapshot-backed ABI equivalence.
- Scope: cpp_tests sources and compiler configuration only; do not modify the SDK or expected bin_artifacts to hide ABI differences.

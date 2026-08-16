---
title: pack_snapshot
type: note
permalink: cs2-vibesignatures/pack-snapshot
---

# Pack Snapshot

## Overview
Repository skill that rebuilds and atomically republishes the canonical tracked game-symbol snapshot `gamesymbols/<GAMEVER>.yaml` from a versioned `bin/<GAMEVER>/` tree against the current `configs/<GAMEVER>.yaml`. Defined in `.claude/skills/pack-snapshot/SKILL.md`. Bypasses the gamedata/candidate/C++ validation gate; use only when refresh of the snapshot alone is required.

## Responsibilities
- Resolve `GAMEVER` (caller value or `CS2VIBE_GAMEVER`) and resolve `configs/<GAMEVER>.yaml` via `analysis_config.resolve_analysis_config`.
- Load a fresh `SnapshotContract` with `LATEST_CONFIG_DIGEST_VERSION` (currently 2), which recomputes `config_sha256` from the current config.
- Collect actual YAML files under `bin/<GAMEVER>/`, reject any missing `required_paths`, accept `optional_paths` only when present, and reject undeclared YAML in strict mode.
- Build a canonical snapshot document at the latest schema version, run a round-trip self-check, and atomically write `gamesymbols/<GAMEVER>.yaml`.

## Involved Files & Symbols
- `.claude/skills/pack-snapshot/SKILL.md` - skill invocation contract.
- `gamesymbol_snapshot_lib.operations.pack_snapshot` - the single function used; returns canonical bytes and writes the file.
- `gamesymbol_snapshot_lib.config.load_contract` - rebuilds contract with `LATEST_CONFIG_DIGEST_VERSION` and recomputes `config_sha256`.
- `gamesymbol_snapshot_lib.operations.build_actual_document` + `_schema_for_digest` - selects the latest schema version for digest v2.
- `gamesymbol_snapshot_lib.operations.collect_actual_files` - enforces required/optional/undeclared YAML rules.
- `gamesymbol_snapshot_lib.codec.canonical_snapshot_bytes` / `parse_snapshot_bytes` - canonical serialization and self-check.

## Architecture
```text
configs/<GAMEVER>.yaml
  --> load_contract(LATEST_CONFIG_DIGEST_VERSION) --> SnapshotContract(config_sha256 recomputed)
  --> collect_actual_files(bin/<GAMEVER>)          --> required present, optional included, undeclared rejected (strict)
  --> build_snapshot_document(latest schema)       --> document with config_digest_version=2 + schema_version=latest
  --> canonical_snapshot_bytes + parse self-check
  --> atomic_write gamesymbols/<GAMEVER>.yaml
```

Because the rebuilt snapshot always addresses `LATEST_CONFIG_DIGEST_VERSION` and the latest schema version, it automatically reflects any newly added or removed skills in the config. The resulting `gamesymbols/<GAMEVER>.yaml` header carries the freshly computed `config_sha256`, so a previously trusted same-version snapshot becomes untrusted-by-contract after a config change (see [[restore_from_snapshot]] for the `--force-base-snapshot` escape hatch).

## Dependencies
- `bin/<GAMEVER>/` must already contain every `required_output` YAML for every active skill; this skill never invokes IDA preprocessors or regenerates symbol YAML. New skills must have their `expected_output` produced first, or `pack_snapshot` raises `Missing required symbol YAML`.
- `configs/<GAMEVER>.yaml` resolvable via `resolve_analysis_config`.

## Notes
- `pack_snapshot` writes directly to `gamesymbols/<GAMEVER>.yaml`; it does not stage or commit. The caller is responsible for committing.
- It bypasses the candidate/gamedata/C++ validation gate; for release-grade refresh use [[post_change_update]] instead.
- Strict `required_paths` enforcement means an optional-only new skill can be packed without producing its files, but any `expected_output` entry missing from `bin/<GAMEVER>/` aborts the pack.
- Round-trip and canonical self-checks guarantee the written bytes reparse identically; failures raise `SnapshotSchemaError` or `SnapshotMismatchError`.

## Callers
- Manual snapshot refresh after edits to `bin/<GAMEVER>` YAML or `configs/<GAMEVER>.yaml` when gamedata + C++ validation is not required.
- Used as the primitive underlying `gamesymbol_candidate.py build`'s candidate construction, but invoked here against the tracked `gamesymbols/` path directly.

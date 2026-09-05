---
title: pack_snapshot
type: note
permalink: cs2-vibesignatures/pack-snapshot
---

# Pack Snapshot

## Overview
`gamesymbol_snapshot_lib.operations.pack_snapshot` builds a release-local canonical snapshot from explicit binary and source-owned artifact roots. The snapshot is a derived candidate used by gamedata/C++/Release packaging; it is never written to a tracked `gamesymbols/` namespace or treated as Git truth.
## Responsibilities
- Resolve an explicit GAMEVER/config, binary root, artifact root, and output path.
- Load the exact snapshot contract and collect per-symbol payloads only from `bin_artifacts/<GAMEVER>/` (or an isolated validated actual root).
- Collect binary integrity metadata only from `bin/<GAMEVER>/`.
- Enforce required/optional/formal inventory and canonical snapshot serialization.
- Atomically write the explicit release-local candidate and round-trip verify its bytes.
## Involved Files & Symbols
- `gamesymbol_snapshot_lib.operations.pack_snapshot` - dual-root pack primitive.
- `gamesymbol_snapshot_lib.config.load_contract` - binary/artifact root contract.
- `gamesymbol_snapshot_lib.operations.collect_actual_files` - strict artifact inventory.
- `gamesymbol_snapshot_lib.operations.collect_binary_metadata` - binary-only identity.
- `gamesymbol_snapshot_lib.codec.canonical_snapshot_bytes` / `parse_snapshot_bytes` - canonical codec.
- `gamesymbol_candidate.py`, `gamesymbol_snapshot_lib.candidate.build_candidate_snapshot` - guarded release-local lifecycle.
## Architecture
```text
configs/<GAMEVER>.yaml + binary root + validated artifact root
  -> SnapshotContract
  -> strict source-owned payload inventory
  -> exact binary metadata
  -> canonical snapshot document
  -> explicit release-local output + round-trip verification
```

The candidate is immutable evidence for gamedata and C++ validation. Release rebuilds derive it from the fresh actual tree only after exact equality with tracked Git artifacts.
## Dependencies
- Complete canonical `bin_artifacts/<GAMEVER>/` or a validated isolated rebuild root.
- Exact configured binaries under `bin/<GAMEVER>/` when binary metadata is required.
- Explicit config and output path; no tracked snapshot default.
## Notes
- `gamesymbol_snapshot.py pack` requires explicit `-snapshot`; `gamesymbol_candidate.py build` additionally guards candidate/session identity.
- Snapshot compatibility restore is historical/rollback-only, requires an explicit snapshot, and may write only a checkout-external artifact root.
- Never publish or commit the derived snapshot to `gamesymbols/`; immutable Release assets are the durable distribution surface.
## Callers
- `gamesymbol_candidate.py build` during PR evidence and Release bundle construction.
- Historical migration/rollback tooling with explicit isolated paths.
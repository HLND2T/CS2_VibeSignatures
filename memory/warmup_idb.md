---
title: warmup_idb
type: note
permalink: cs2-vibesignatures/warmup-idb
---

# Warmup IDB

## Overview
`.github/workflows/warmup-idb.yml` is the reusable producer for neutral warm IDA databases. It prepares configured binaries, reuses or publishes one immutable verified generation under `PERSISTED_WORKSPACE/idb-cache/<GAMEVER>`, and returns its exact identity to PR/Release consumers. It never carries source-owned YAML.
## Responsibilities
- Resolve configured binary identities and IDA kernel/runtime for an exact GAMEVER/source.
- Reuse a matching immutable generation or force a complete warmup on cache miss.
- Publish only configured binaries and required IDA database payload after inventory validation.
- Restore exact generation IDs for consumers and fail closed on damage, identity drift, locks, or runtime mismatch.
- Synchronize accepted-bin as an exact configured-binary positive allowlist while excluding YAML, IDA/BinSync mutable state, and undeclared side files.
- Serialize same-GAMEVER producers and prune stale incoming/aged generation directories conservatively.
## Involved Files & Symbols
- `.github/workflows/warmup-idb.yml` - caller-only reusable producer with same-GAMEVER concurrency.
- `warmup_idb.py`, `warmup_idb_worker.py` - bounded full auto-analysis workers.
- `idb_cache.py` - identity, immutable generation publication, READY pointer, restore, and pruning.
- `release_workflow_lib/sync_accepted_bin.py`, `release_workflow_lib/binary_cache.py` - exact binary-only accepted cache.
- `.github/workflows/pr-self-runner.yml`, `.github/workflows/build-on-self-runner.yml` - exact-generation consumers.
## Architecture
```text
GAMEVER + configured binary hashes + IDA runtime
  -> verified cache hit or forced warmup
  -> immutable generation inventory
  -> exact generation returned to caller
  -> binary-only restore
  -> strict -require_warm_idb analysis
```

Source-owned artifact content is deliberately absent from cache identity and payload; consumers load expected artifacts from Git separately.
## Dependencies
- Protected self-hosted Windows runner with IDA/idalib and configured binaries/depot access.
- `PERSISTED_WORKSPACE/idb-cache/<GAMEVER>` and binary-only `PERSISTED_WORKSPACE/bin/<GAMEVER>`.
- `IDB_WARMUP_MAX_CONCURRENCY` and optional memory bound.
## Notes
- Cache identity binds configured binary path/size/hash plus IDA runtime, not artifact bytes.
- Accepted-bin restore/sync uses a positive configured-binary allowlist and excludes `*.yaml`/`*.yml`, IDA databases, BinSync repositories/sidecars, and undeclared files.
- The removed release-staging/promote-bin path is historical only; warmup no longer feeds any YAML promotion gate.
- READY is only an atomic convenience pointer; callers consume the returned immutable generation ID/cache key.
- Warm IDB is neutral performance state. Release-local `-rename` modifies a copy and never writes back to the warm generation.
## Callers
- `.github/workflows/pr-self-runner.yml` before isolated affected-group rebuild.
- `.github/workflows/build-on-self-runner.yml` before fresh full Release rebuild.
- No manual dispatch surface: only repository-owned caller workflows may select a source identity.

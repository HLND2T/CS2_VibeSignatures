---
title: warmup_idb
type: note
permalink: cs2-vibesignatures/warmup-idb
---

# Warmup IDB

## Overview
`.github/workflows/warmup-idb.yml` is the reusable producer for neutral warm IDA databases. It prepares configured binaries, reuses or publishes one immutable verified generation under `PERSISTED_WORKSPACE/idb-cache-v2/<GAMEVER>`, and returns its exact identity to PR/Release consumers. It never carries source-owned YAML.
## Responsibilities
- Resolve the canonical source-owned binary lock and IDA kernel/runtime for an exact GAMEVER/source.
- Reuse a matching immutable generation or force a complete warmup on cache miss.
- Publish only configured binaries and required IDA database payload after inventory validation.
- Restore exact generation IDs for consumers and fail closed on damage, identity drift, locks, or runtime mismatch.
- Synchronize accepted-bin as an exact configured-binary positive allowlist while excluding YAML, IDA/BinSync mutable state, and undeclared side files.
- Serialize same-GAMEVER producers and prune stale incoming/aged generation directories conservatively.
## Involved Files & Symbols
- `.github/workflows/warmup-idb.yml` - caller-only reusable producer with same-GAMEVER concurrency.
- `warmup_idb.py`, `warmup_idb_worker.py` - bounded full auto-analysis workers.
- `idb_cache.py` - locked probe/publish/restore/prune and required lease CLI arguments.
- `idb_cache_leases.py` - GAMEVER file locks, persistent lease validation, expiry and release.
- `tests/test_idb_cache.py` - deterministic interleaved warmup/prune regression, lease failures, cross-process restore and locks.
- `release_workflow_lib/sync_accepted_bin.py`, `release_workflow_lib/binary_cache.py` - exact binary-only accepted cache.
- `.github/workflows/pr-self-runner.yml`, `.github/workflows/build-on-self-runner.yml` - exact-generation consumers.
## Architecture
```text
GAMEVER + configured binary hashes + IDA runtime
  -> GAMEVER file lock: verify/reuse or publish immutable generation
  -> persist lease bound to repository/run/attempt + generation/key/manifest digest
  -> return exact generation/key + lease ID/SHA-256 to downstream job
  -> same lock: require lease, verify generation, copy all binaries/IDBs, verify identity
  -> atomically release this lease only after full success
```

Source-owned artifact content is deliberately absent from cache identity and payload; consumers load expected artifacts from Git separately. `prune_cache` takes the same lock and retains every generation with an active lease in addition to READY/latest-three/minimum-age retention.
## Dependencies
- Protected self-hosted Windows runner with IDA/idalib and configured binaries/depot access.
- `PERSISTED_WORKSPACE/idb-cache-v2/<GAMEVER>` and binary-only `PERSISTED_WORKSPACE/bin/<GAMEVER>`.
- `IDB_WARMUP_MAX_CONCURRENCY` and optional memory bound.
## Notes
- Cache identity binds configured binary path/size/hash plus IDA runtime, not artifact bytes. The producer verifies those bytes
  against the source lock before probe/publish and exports the lock digest to PR/Release consumers.
- Accepted-bin restore/sync uses a positive configured-binary allowlist and excludes `*.yaml`/`*.yml`, IDA databases, BinSync repositories/sidecars, and undeclared files.
- The removed release-staging/promote-bin path is historical only; warmup no longer feeds any YAML promotion gate.
- READY is only an atomic convenience pointer; callers consume the returned immutable generation ID/cache key.
- Warm IDB is neutral performance state. Release-local `-rename` modifies a copy and never writes back to the warm generation.
## Callers
- `.github/workflows/pr-self-runner.yml` before isolated affected-group rebuild.
- `.github/workflows/build-on-self-runner.yml` before fresh full Release rebuild.
- No manual dispatch surface: only repository-owned caller workflows may select a source identity.

## Cross-job generation lifetime (2026-09-25)
- Trigger: warmup selects an old generation, other workflows move READY and prune before the consumer restores; restore reports `published IDB cache generation is incomplete`.
- Root cause: READY and latest-three/seven-day retention do not express pending consumers. Producer-only workflow concurrency does not cover downstream wait/copy. CS2 prunes before probe, so a later warmup can delete a prior selection after an intervening producer moves READY.
- Correct approach: persistent unique leases are created under the same per-GAMEVER filesystem lock used by pruning and restore. Consumers use producer outputs directly; no downstream re-probe. Lease digest binds repository/run/attempt and exact generation/cache key/manifest. Every configured binary and IDB must restore successfully before releasing that lease.
- Failure/operations: 36-day TTL, one-hour extra prune clock grace; failed/abandoned producers expire. Unreadable/corrupt leases fail closed. Released/expired/missing/mismatched leases reject restore. Rerun the full workflow including producer after successful restore followed by analysis failure, or a changed GitHub attempt. New `idb-cache-v2/` isolates payload/READY/leases/locks from old pruners; old namespace is not migrated or deleted automatically.
- Verification: the deterministic regression failed before the fix on the missing generation; 31 focused tests passed on Windows, including cross-process/workspace CLI restore and lock contention, partial copy failure, multiple independent leases, expiry and reparse defenses. Real dual-runner SMB interleaving remains an operational validation step.
- Scope: ordinary PR/Release, bootstrap, and source-artifact bridge warmup/consumer paths. Release evidence is archival and does not depend on live lease state.

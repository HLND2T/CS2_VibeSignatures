---
title: warmup_idb
type: note
permalink: cs2-vibesignatures/warmup-idb
---

# Warmup IDB

## Overview
`.github/workflows/warmup-idb.yml` is the required reusable producer for warm IDA databases. It prepares configured binaries independently, runs `warmup_idb.py` only on a cache miss, and publishes one immutable, verified generation under `PERSISTED_WORKSPACE/idb-cache/<GAMEVER>` for PR and release consumers.
## Responsibilities
- Resolve configured binaries for an exact GAMEVER and immutable source SHA.
- Derive cache identity from configured binary paths/hashes plus the IDA kernel version.
- Reuse a verified matching generation; otherwise force-invalidate local IDA side files and warm every configured binary.
- Publish binary plus `.i64` payloads only after the complete inventory validates.
- Prune stale incoming directories and aged generations for the current GAMEVER without deleting the READY or newest retained generations.
- Return the exact immutable generation and cache key to the caller so later READY changes cannot redirect an in-flight consumer.
- Require each consumer to match the producer IDA kernel version before restoration.
- Fail the caller when preparation, warmup, publication, restoration, or strict IDB validation fails; CI has no inline auto-analysis fallback.
## Involved Files & Symbols
- `.github/workflows/warmup-idb.yml` - reusable/manual cache producer and per-GAMEVER concurrency boundary.
- `warmup_idb.py` - bounded worker orchestration, forced invalidation, timeout, and memory controls.
- `warmup_idb_worker.py` - one-binary warm worker and IDA kernel-version probe.
- `idb_cache.py` - cache identity, immutable generation publication, inventory verification, retention pruning, READY pointer, and explicit-generation restore.
- `ida_analyze_bin.py` - `-require_warm_idb` strict consumer mode.
- `pr_validation_version.py` - resolves the exact PR validation GAMEVER before invoking the producer.
- `.github/workflows/build-on-self-runner.yml` - required producer caller and explicit generation consumer.
- `.github/workflows/pr-self-runner.yml` - required producer caller and explicit generation consumer.
- `tests/test_idb_cache.py` - publication, tamper rejection, and generation-stability tests.
- `tests/test_warmup_idb_workflow.py` - reusable workflow contract.
## Architecture
Caller GAMEVER/source SHA -> reusable warmup workflow -> isolated binary preparation -> binary/IDA cache identity -> verified generation hit or forced full warmup -> immutable inventory-verified generation publication -> exact-generation restore by PR/release -> strict `require_warm_idb` analysis.
## Dependencies
- Protected `win64` environment and `[self-hosted, windows, x64]` runner with IDA/idalib on `python` PATH.
- `PERSISTED_WORKSPACE`, persisted `cs2_depot`, and Steam credentials for new versions without a Release archive.
- `IDB_WARMUP_MAX_CONCURRENCY` and optional `IDB_WARMUP_MAX_MEMORY_MIB` environment variables.
- [[build-on-self-runner]] and [[pr-self-runner]] callers.
## Notes
- Cache-key formula: `sha256(canonical_json{gamever, ida_version, binaries})`, where `binaries` is the list of configured-binary records, each `{module, platform, path, size, sha256}`. It is derived from the configured binary set + IDA kernel version only; the analysis-config file bytes themselves are **not** hashed into the key.
- The binary record list comes from `iter_configured_binaries`, which reads `configs/<GAMEVER>.yaml` `modules[].path_windows`/`path_linux` — i.e. only the *declared* binaries participate, not the whole `bin/<GAMEVER>/` tree.
- Therefore a config edit that only changes non-binary-list fields (analysis parameters, IDA script settings) leaves the cache key unchanged and does **not** trigger re-warmup, even though actual IDB output may differ. Only changes that alter the declared module/path/platform set produce a new key. This is a deliberate contract: the key binds *what* gets analyzed, not *how*.

- The old release path was not actually disconnected: workspace `.i64` files were copied by `stage-build` into `release-staging`, then the merged generated-output PR caused `promote-bin` to transactionally replace `PERSISTED_WORKSPACE/bin/<GAMEVER>`. Merely finishing the build was insufficient; generated-output merge and promotion were the old visibility gate. Current staging excludes all IDA database artifacts, so the accepted tree no longer receives that second copy.
- After every successful warmup run (cache hit or miss), the workflow's `sync-accepted-bin` step mirrors the consumed `bin/<GAMEVER>` (excluding all IDA database side files) into `PERSISTED_WORKSPACE/bin/<GAMEVER>` idempotently and transactionally, so accepted bin follows the warmup lifecycle instead of only the merge-time promotion gate. `promote_bin` remains the verification gate and becomes a same-hash no-op when warmup already wrote identical bytes; the warmup, promotion, unmerged cleanup, and abandonment workflows share one per-GAMEVER concurrency group, while both writers also retain the same per-GAMEVER file lock as a defensive backstop. See `release_workflow_lib/sync_accepted_bin.py`.
- The only supported cache source is an explicit immutable generation returned by this workflow; PR/release baseline copies also exclude the complete tracked IDA suffix set.
- Generation directories are immutable. READY is an atomic convenience pointer; callers restore the returned generation ID and cache key, so a later READY update cannot create a cross-workflow race.
- Each producer run prunes `.incoming-*` directories older than 24 hours. It retains the three newest generations and the READY generation, and only removes other generations after seven days so in-flight explicit-generation consumers have a safety window.
- Pruning is intentionally scoped to the GAMEVER being produced. Retired `idb-cache/<GAMEVER>` roots are never deleted automatically; runner operators must periodically remove unused version roots after confirming that no active PR or release run references their explicit generations.
- Cache identity is binary-content and IDA-version based, not GAMEVER-only. A config change that changes the configured binary set produces another key; unrelated source changes reuse the existing generation.
- Restore compares the consumer's local IDA kernel version with the producer manifest before copying payload files. Workflows also require `python` and `idalib-mcp` to resolve from the same installation directory.
- Warmup is no longer best-effort in CI. Any worker failure, missing `.i64`, residual lock, inventory mismatch, or restore mismatch fails the caller before analysis.
- `ida_analyze_bin.py -require_warm_idb` rejects a missing database and does not delete/rebuild a database that fails binary identity verification.
- Worker concurrency remains process-level: each bare-idalib worker owns one database and uses no MCP port.
- GitHub concurrency serializes a GAMEVER producer and the manifest probe makes repeated calls idempotent; a superseded pending GitHub run can still be canceled by Actions scheduling and must be rerun by its caller.
## Callers
- `.github/workflows/build-on-self-runner.yml` - `warmup-idb` reusable job before `build`.
- `.github/workflows/pr-self-runner.yml` - `pr-warmup-idb` reusable job before `pr-validate` for non-bump PRs.
- Manual `workflow_dispatch` for an exact GAMEVER and source SHA.

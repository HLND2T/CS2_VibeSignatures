---
title: warmup_idb
type: note
permalink: cs2-vibesignatures/warmup-idb
---

# Warmup IDB

## Overview
`warmup_idb.py` warms every configured binary's IDA database (`<binary>.i64`) ahead of the release analyze step, so `ida_analyze_bin.py` reuses the existing database and skips IDA's initial auto-analysis pass. It is a pure optimization wired into `.github/workflows/build-on-self-runner.yml` as the best-effort `warmup-idb` step between `init-binaries` and `analyze`.

## Responsibilities
- Enumerate configured binaries via `init_gamebin.iter_configured_binaries` for one GAMEVER.
- Skip binaries that are already warm (a packed `.i64`/`.idb` exists and no `.id0` lock remains).
- Warm the rest with bare-idalib worker processes, bounded by `--max-concurrency`.
- When a memory budget is configured, delay new workers until aggregate Job commit has enough headroom.
- Enforce the configured aggregate process-tree budget with a nested Windows Job Object.
- Bound every worker with `--worker-timeout-seconds` so a stuck IDA analysis cannot block the release analyze step indefinitely.
- Invalidate a binary's database side files whenever a worker fails, retrying cleanup and reporting any residual files so no failure is silently treated as a safe fallback.

## Involved Files & Symbols
- `warmup_idb.py` - orchestrator: discovery, warm check, bounded fan-out, memory-controller activation, invalidation on failure.
- `warmup_memory.py` - Windows Job Object wrapper and memory-aware worker admission gate.
- `warmup_idb_worker.py` - one-binary worker: `idapro.open_database(run_auto_analysis=True)` -> `ida_auto.auto_wait()` -> `ida_loader.save_database(None, 0)` -> `idapro.close_database()`.
- `.github/workflows/build-on-self-runner.yml` - step `warmup-idb` with `continue-on-error: true`.
- `init_gamebin.py` - `iter_configured_binaries`.
- `analysis_config.py` - `resolve_analysis_config`.
- `tests/test_warmup_idb.py` - warm check, concurrency parsing, invalidation, worker success/failure paths.
- `tests/test_build_self_runner_workflow.py` - contract: warmup precedes analyze and is best-effort.

## Architecture
```text
binaries (config) -> warm check -> pending subset
                  -> memory admission gate (aggregate Job commit)
                  -> N bare-idalib worker processes (bounded concurrency)
                  -> each: open -> auto_wait -> save -> close
                  -> failure: invalidate side files -> warn, continue
```

## Dependencies
- `python` on PATH resolves to an idalib (IDAPRO) interpreter; `uv run` executes the repo script.
- `IDB_WARMUP_MAX_CONCURRENCY` configuration variable on the `win64` GitHub environment, explicitly mapped through the workflow job `env` (default 2 when unset).
- `IDB_WARMUP_MAX_MEMORY_MIB` configuration variable on the `win64` GitHub environment, explicitly mapped through the workflow job `env`; `32768` is the recommended budget for a Hyper-V VM with at least 48 GiB maximum RAM on the dedicated 64 GiB host.
- Bare idalib API, mirroring idalib-mcp's `open_database`/`auto_wait`/`save_database`/`close_database` semantics.

## Notes
- Concurrency is process-level, not thread-level: idalib opens one database per process, so each worker is a separate bare-idalib process with no MCP server and no 13337 port contention.
- Memory controls are opt-in for backward compatibility. When `IDB_WARMUP_MAX_MEMORY_MIB` is unset, warmup logs that memory-aware admission and the hard Job limit are disabled.
- The configured budget is the Windows Job hard limit. New workers pause at 85% of that budget, reserve at least 4 GiB for the next worker, and launch no faster than one worker every five seconds so Hyper-V Dynamic Memory can react.
- Guest free physical memory is deliberately not an admission threshold: Hyper-V Dynamic Memory may keep the idle Guest buffer small, so such a threshold can deadlock before the first worker creates demand. The Job budget must therefore stay below the VM maximum with OS headroom; completed workers wake waiting launches immediately.
- Job Object initialization or sampling failures are fail-closed: no uncapped warmup worker is launched, while the workflow's existing best-effort step lets analyze fall back to its normal inline path.
- Worker failures normally degrade to inline analysis: any non-zero exit, launch error, timeout, or unexpected orchestration error invalidates that binary's `.i64/.id0/.id1/.id2/.nam/.til`. Cleanup is retried three times; any residual path is reported explicitly instead of being treated as a safe fallback.
- Each worker is limited to 1,800 seconds by default; `--worker-timeout-seconds` can override the limit for direct invocations.
- A half-written locked database is never opened by analyze: warmup invalidates failed workers first, and `ida_analyze_bin.py` independently refuses to start on a residual `.id0` lock.
- Cache identity is the GAMEVER directory and the `.i64`/`.id0` physical state, not a content hash: each gamever tag pins a distinct depot manifest, so a gamever directory maps to one set of binary bytes, and content mismatch is caught by analyze's `input_sha256` guard.
- Bare-idalib save semantics match idalib-mcp `idb_save`: in-place `save_database(None, 0)` after `auto_wait()`, then `close_database()`.

## Callers
- `.github/workflows/build-on-self-runner.yml` - step `warmup-idb` (best-effort, before `analyze`).

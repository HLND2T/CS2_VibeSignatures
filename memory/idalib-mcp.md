---
title: idalib-mcp
type: note
permalink: cs2-vibesignatures/idalib-mcp
---

# idalib-mcp

## Overview

`ida_analyze_bin.py` owns one `idalib-mcp` supervisor per binary. In ida-pro-mcp 2.0.0 the supervisor intentionally starts a detached `idalib_server` worker, so stopping the supervisor alone cannot release an open IDB. On Windows a repository launcher joins a kill-on-close Job before spawning the supervisor; its descendants share that Job.

## Responsibilities

- Start the owned MCP supervisor, bind and verify the exact target database, then run analysis.
- Request targeted `qexit` only for a verified owned worker. Wait up to 60 seconds for IDB handle release before stopping the launcher.
- On Windows, force-stop the per-binary Job when graceful quit fails. Verify the supervisor port and IDB handles are released; cleanup failure aborts the run even with `-skip_error`.
- Quarantine only unpacked IDB side files created by the current launch after forced cleanup. Preserve packed `.i64`/`.idb` and all pre-existing side files.

## Involved Files & Symbols

- `ida_analyze_bin.py` — `ManagedMcpProcess`, `start_idalib_mcp`, `quit_ida_gracefully`, `stop_idalib_mcp_process`, IDB side-file checks/quarantine.
- `ida_mcp_job_launcher.py` — per-launch Windows Job owner and analyzer-parent watcher.
- `windows_job.py` — shared ctypes Job API; `warmup_memory.py` uses it for warmup memory controls.
- `ida_mcp_session.py` — owned database selection and MCP session binding.
- `generate_reference_yaml.py` — reuses the same owned startup and cleanup path.
- `tests/test_ida_mcp_job_launcher.py` and `tests/test_ida_analyze_bin.py` — process-tree and cleanup regression tests.

## Architecture

```mermaid
flowchart TD
    A[Analyzer or reference generator] --> B[ManagedMcpProcess]
    B --> C[Windows Job launcher]
    C --> D[idalib-mcp supervisor]
    D --> E[Detached idalib_server worker]
    E --> F[Verified target IDB]
    F --> G[Targeted qexit and IDB release wait]
    G --> H[Stop launcher and verify port/IDB release]
    H --> I[Quarantine new unpacked parts after forced stop]
```

## Dependencies

- Installed `idalib-mcp` executable and IDA/idalib; `ida-pro-mcp 2.0.0` uses a supervisor plus detached worker.
- Windows Job Object API via the standard-library `ctypes`; no new Python dependency.
- `.id0` is an unpacked IDA database component, not a disposable lock marker. A pre-existing `.id0` blocks startup until its ownership and recovery are resolved.

## Notes

- Job ownership is scoped to one launcher/binary. Do not assign the analyzer process itself to this Job or kill an attached external IDA process.
- The launcher watches its analyzer parent. Parent exit closes the launcher's only Job handle, killing the owned tree.
- An exited launcher is not by itself cleanup proof: verify the supervisor port and exclusive access to `.id0` candidates before restart or IDB invalidation.
- Only a current-run forced exit may move new `.id0/.id1/.id2/.nam/.til` files into `.ida-aborted/<binary-name>/<run-id>/`. Pre-existing or ambiguous files remain untouched and cause an explicit error.
- The packed `.i64` survives forced cleanup; `-require_warm_idb` still rejects a genuinely missing warm database.
- Other platforms retain their existing subprocess launch behavior.

## Callers

- `ida_analyze_bin.process_binary` starts one owned MCP process for each pending module/platform binary.
- `generate_reference_yaml.autostart_mcp_session` uses the same startup and cleanup helpers for `-auto_start_mcp`.

## Source

This CS2-specific lifecycle note supersedes the earlier GoldSrc-derived description.

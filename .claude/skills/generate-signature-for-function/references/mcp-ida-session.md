# IDA MCP Session Bootstrapping and IDB Save Discipline

Shared guidance for every skill that talks to `ida-pro-mcp`. The `ide`-backed tools
(`py_eval`, `decompile`, `rename`, `get_bytes`, ...) only exist after an IDB is attached, so
resolve the session in this order **before** the first such call.

## 1. Bootstrap order — prefer `idb_list` → `idb_open` → script fallback

1. **`mcp__ida-pro-mcp__idb_list`** — list attached sessions. If the target `.i64`
   (or its source binary) is already open, reuse that session: pass the returned
   `database` id to every later tool call and do **not** re-open it.
2. **`mcp__ida-pro-mcp__idb_open`** — only when step 1 shows the target is *not* open.
   Pass the `.i64` path (or the binary). Default `idle_ttl_sec` is 600 s; a worker opened
   this way is owned by the MCP endpoint, so the save rule in §2 applies to it.
3. **Script fallback** — only when the `13337` MCP endpoint is unreachable (`idb_list` /
   `idb_open` cannot connect). Fall back to the repository-owned `idalib-mcp` lifecycle:
   - `uv run generate_reference_yaml.py ... -auto_start_mcp -binary <path> -platform <windows|linux> -debug`
   - `uv run ida_analyze_bin.py ...`

**Never call `mcp__ida-pro-mcp__open_file`.** It switches the IDA GUI document and can
silently move the session onto an unintended binary. Use `idb_open` for headless idalib
workers instead.

**Owned-session boundary.** An agent fallback launched by `agent_runner.py` is handed a
verified *owned* endpoint whose worker the runner opened and will save. When `idb_list`
shows the assigned database already attached there, **reuse it and do not close it** —
closing the runner's session would strand later skills that share that endpoint. Only
close a session you opened yourself in step 2.

## 2. Hard save rule — idle TTL does NOT save

A worker that exits on idle TTL (default 600 s, refreshed by each JSON-RPC call) **does not
save**. Every change the session made — renames, comments, `define_func`, type edits — is
lost on that self-exit.

- Before finishing, call **`mcp__ida-pro-mcp__idb_close`** with `save=True` on the database
  you opened.
- If the session must stay open for later reuse, call **`mcp__ida-pro-mcp__idb_save`**
  instead and still close with `save=True` when the work is done.
- Never leave a mutated IDB to idle out.

This matches the repository's code: `warmup_idb_worker.py` explicitly runs
`save_database(None, 0)` before `close_database()`, mirroring idalib-mcp's `idb_save`.

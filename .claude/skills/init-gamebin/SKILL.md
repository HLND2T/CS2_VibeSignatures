---
name: init-gamebin
description: Initialize this repository's disposable local game binaries for an exact GAMEVER from download.yaml or its latest entry. Use only when explicitly asked to initialize gamebin/bin state for a CS2 game version.
disable-model-invocation: true
---

# Initialize Game Binaries

Use the repository-root script as the only entry point for downloading, merging, and depot fallback.
Never overwrite an existing binary, substitute an unlisted version, or continue after a failed step. This skill handles
only disposable binary/IDA state: never restore snapshot YAML into `bin/` or hydrate tracked `bin_artifacts`. Source-owned
symbol truth is already versioned under `bin_artifacts/<GAMEVER>/`.

## Select GAMEVER

1. Extract an exact `GAMEVER` from the user's request. Resolve `latest` only when the user explicitly requests latest.
2. If the user did not specify a version, run:

   ```powershell
   uv run init_gamebin.py versions
   ```

   Tell the user which entry is latest and ask: `Which GAMEVER do you want to initialize?`
   Wait for an explicit version before continuing.
3. Reject values absent from `download.yaml`; do not guess or silently use latest.

## Decide IDB Download

A rebuilt Release also publishes `gamebin-with-idb-<GAMEVER>.7z`, its warm IDA databases. Downloading
it skips the slow, resource-heavy local warmup. Decide before preparing binaries:

1. Probe whether the selected GAMEVER publishes the archive:

   ```powershell
   uv run init_gamebin.py check-idb <GAMEVER>
   ```

2. If the probe exits 0 (available), **ask** the user whether to download the IDB-bundled gamebin and
   wait for an explicit yes/no.
   - Yes → prepare with `--with-idb`. The warm databases are merged into `bin/<GAMEVER>` and the
     "Warm Up IDB" step below is **skipped** (the binaries are already warm).
   - No → prepare without the flag and keep the "Warm Up IDB" step below.
3. If the probe exits 1 (unavailable), tell the user which GAMEVER publishes no warm IDB archive and
   why, then prepare without the flag and keep the "Warm Up IDB" step below. Do not retry.

A tracked (rebuild-free) release is published without any IDA analysis and therefore never carries this
archive; `--with-idb` also fails loudly for a GAMEVER whose Release declares none.

## Prepare Binaries

Run from the owning repository root with the IDB download decision applied:

```powershell
uv run init_gamebin.py prepare <GAMEVER-or-latest> [--with-idb]
```

`--with-idb` downloads, verifies, and merges the published warm IDA databases without overwriting existing files.
The script prepares missing binaries from the verified Release archive or Steam depot fallback, then checks the
complete configured binary tree against its source-owned binary lock.

If the command fails, stop immediately and report its exact error as:

```text
<skill_error>ERROR REASON</skill_error>
```

Do not attempt an alternate download, edit `.env`, or proceed to analysis.

## Warm Up IDB (optional)

Skip this whole section when the user chose to download the IDB-bundled gamebin (`--with-idb`): every
configured database was already merged from the Release, so warmup is unnecessary.

Otherwise, after binary preparation succeeds, ask whether to warm the IDA databases for the selected GAMEVER.
Warmup runs full IDA auto-analysis on every configured binary (via `warmup_idb.py`) and leaves
`<binary>.i64` beside each binary so later analysis is fast. It is slow and resource-heavy, so it is
opt-in.

1. Resolve a Python interpreter with idalib — the same probe the workflows use:

   ```powershell
   $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
   & $pythonExe warmup_idb_worker.py --print-ida-version
   ```

   If the probe fails or prints no version, tell the user IDB warmup is skipped and why (no Python
   with idalib available), then finish without warming.
2. If the interpreter is available, **ask** the user whether to warm the IDB databases for `<GAMEVER>`
   and wait for an explicit yes/no. Never warm without explicit consent.
   - Yes → run the warmup producer from the owning repository root:

     ```powershell
     uv run python warmup_idb.py <GAMEVER> --python "$pythonExe"
     ```

     Already-warm databases (an existing `.i64`/`.idb` with no `.id0` lock) are skipped; add `--force`
     only if the user wants every configured database invalidated and re-warmed. If the command fails,
     stop and report its exact error to user.

     Do not silently continue after a failed warmup.
   - No → skip warmup and finish.

Report the selected GAMEVER, binary preparation result, warm IDB merge (if any), and optional warmup
result. State that symbol truth remains under tracked `bin_artifacts/`; the merged `.i64` databases are disposable
workspace state, not source truth. Do not offer snapshot restoration or IDB renaming.

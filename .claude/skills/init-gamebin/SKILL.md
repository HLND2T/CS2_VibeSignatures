---
name: init-gamebin
description: Initialize this repository's local game binaries and per-binary BinSync auto-recovery sidecars for an exact GAMEVER from download.yaml or its latest entry, then delegate symbol YAML restoration to restore-from-snapshot. Use only when explicitly asked to initialize or restore gamebin/bin state for a CS2 game version.
disable-model-invocation: true
---

# Initialize Game Binaries

Use the repository-root script as the only entry point for downloading, merging, depot fallback, and BinSync recovery setup.
Never overwrite an existing binary, substitute an unlisted version, or continue after a failed step. Delegate all symbol
snapshot behavior to the project-level `$restore-from-snapshot` skill; do not call `gamesymbol_snapshot.py` or restore
YAML locally in this skill.

## Select GAMEVER

1. Extract an exact `GAMEVER` from the user's request. Resolve `latest` only when the user explicitly requests latest.
2. If the user did not specify a version, run:

   ```powershell
   uv run init_gamebin.py versions
   ```

   Tell the user which entry is latest and ask: `Which GAMEVER do you want to initialize?`
   Wait for an explicit version before continuing.
3. Reject values absent from `download.yaml`; do not guess or silently use latest.

## Decide BinSync

BinSync recovery is opt-in. Decide whether to enable it before preparing binaries:

1. Probe availability from the owning repository root:

   ```powershell
   uv run init_gamebin.py check-binsync
   ```

2. If the probe exits 1 (unavailable), tell the user BinSync initialization is skipped and why
   (`BinSync unavailable: <reason>`), then proceed to preparation **without** enabling BinSync.
3. If the probe exits 0 (available), **ask** the user whether to enable BinSync and wait for an
   explicit yes/no. Never enable BinSync without explicit consent, and never skip the probe.
   - Yes → prepare with `--binsync enable`.
   - No → prepare with `--binsync skip` (or omit the flag).

## Prepare Binaries

Run from the owning repository root with the BinSync decision applied:

```powershell
uv run init_gamebin.py prepare <GAMEVER-or-latest> --binsync <enable|skip>
```

Without `--binsync`, BinSync is skipped and never probed. `--binsync enable` probes first and **fails**
(instead of skipping) when the environment cannot run BinSync. The script checks existing binaries,
downloads and non-overwritingly merges `gamebin-<GAMEVER>.7z` when needed, and uses
the Steam depot fallback only for a missing Release asset. After every configured Windows and Linux binary exists, it:

1. Resolves targets in first-seen config order, Windows before Linux, and deduplicates repeated real binary paths.
2. Preflights every target before making BinSync changes: strict existing sidecars, matching local `.bsproj` repositories,
   and GitHub remote/default-branch/`binary_hash` state.
3. Uses `gh` to read public repositories without requiring `HLND2T` organization permissions. Only an explicit HTTP 404
   is treated as missing; every other API failure stops the command.
4. Creates a missing `HLND2T/CS2_VibeSignatures_binsync_<GAMEVER>_<MODULE_FILENAME>` repository as public. Creation
   requires an authenticated `gh` user with permission to create repositories in `HLND2T`.
5. Restores a newly created or empty remote from every local `binsync/*` branch when a valid unlocked
   `<MODULE_FILENAME>.bsproj` exists. Otherwise it creates the standard BinSync `Root commit`, `binsync/__root__`, and
   `binsync/<OS_USER>` branches. It sets the default branch only for a newly created or previously empty repository.
6. Writes `<MODULE_FILENAME>.binsync.json` only after the remote validates successfully. The sidecar uses the current OS
   user as a fallback, the canonical HTTPS remote, explicit `<MODULE_FILENAME>.bsproj`, the binary MD5,
   `force_user: false`, and `auto_clone: true`.

The script never reads or writes `BinSyncDLConfig.toml`, never clones missing `.bsproj` repositories into `bin/`, and
never fetches or pushes an already-valid remote/local pair. IDA's BinSync auto-recovery performs the later clone.

Existing sidecars must contain exactly the six expected fields and match semantically. Existing local repositories must
have the expected `origin`, `binsync/__root__`, and `binary_hash`. Existing non-empty remotes must already use
`binsync/__root__` as their default branch and expose the matching `binary_hash`. Stop on any conflict; never overwrite,
move, delete, repair, or change the default branch of existing state. A local `binsync.lock` is allowed for read-only
validation, but it blocks restoring a missing or empty remote from that local repository.

If the command fails, stop immediately and report its exact error as:

```text
<skill_error>ERROR REASON</skill_error>
```

Do not attempt an alternate download, edit `.env`, or proceed to symbol restoration.

## Restore Symbol YAML

After binary preparation succeeds, invoke the project-level `$restore-from-snapshot` skill with the selected GAMEVER.
Follow that skill's trusted restore, base-snapshot suggestion, explicit yes/no confirmation, and result handling exactly.
Do not duplicate its commands or safety rules here.

After restoration finishes, report its result together with the selected GAMEVER and the script's BinSync summary. Finish
without offering or running IDB renaming.

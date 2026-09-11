---
name: trigger-release-build
description: Safely dispatch an immutable source-owned Release verification or publication from the current origin/main SHA. Use only when explicitly asked to verify, publish, or rebuild a game version.
disable-model-invocation: true
---

# Trigger Release Build

Use the bundled script as the only remote-operation entry point. Do not construct an ad-hoc `gh workflow run`
command, accept a user-supplied SHA, move a tag, edit a Release, cancel work, or bypass CI source-artifact preflight.

The local script checks repository/auth access, version selection, duplicate work, and the current `origin/main` SHA.
It does not create a temporary worktree or run full source-artifact preflight locally. Both workflows retain their CI
source-artifact gates before building or publishing; artifact validation failures are reported in the Actions run.

## Procedure

1. Confirm both release choices with the user **before any remote work**. Ask two separate questions and do not
   dispatch until both are answered explicitly — never choose on the user's behalf, never preselect an option, and never
   infer an answer from a previous run.
   - Build path: the standard `release` workflow (fresh `-force_all` rebuild, proves the artifacts can be rebuilt)
     versus the manual `rebuild-free` emergency path (binds the tracked `bin_artifacts/<GAMEVER>` and does not prove
     rebuildability).
   - Publication: `verify-only` (verify candidates without publishing), `publish` (publish without replacing existing
     content), or `republish` (replace an existing mutable Release in place, retaining its ID and tag name).
   In Claude Code, ask with the `AskUserQuestion` tool, offering the available choices on each question.
2. Extract the requested game version, or use `latest` only when the user explicitly asks for the latest version.
3. Map the confirmed answers onto the script flags: `--mode <verify-only-or-publish-or-republish>`, plus `--workflow rebuild-free`
   only when the user chose that path. Omit `--workflow` for the standard `release` workflow.
4. Run from any directory with the confirmed mode stated explicitly:

   ```powershell
   uv run python .claude/skills/trigger-release-build/scripts/trigger_release_build.py <GAMEVER-or-latest> --mode <verify-only-or-publish-or-republish> [--workflow <release-or-rebuild-free>]
   ```

5. Report the script's selected version, publication mode, workflow, full `SOURCE_SHA`, commit subject, and Actions run
   URL.
6. If the script refuses the operation, surface its exact safety reason and stop. Do not bypass repository, auth,
   version, duplicate-work, or `origin/main` checks. Do not bypass a failed CI source-artifact gate.

`publish` preserves existing content and supports exact-byte retries. Select `republish` only when the user explicitly
requests replacement: it moves the tag to the selected source, updates metadata and assets, and temporarily makes the
Release a draft. Upload/verification failures leave a draft for a rerun to resume; do not silently switch modes or retry
with a different source. A fresh dispatch uses the then-current `origin/main`, so use the existing Actions run's rerun
when the same bundle is required. A missing target requires `publish`; GitHub immutable Releases cannot be republished.
Any requested generator/config change must already be merged into `origin/main` with its complete
`bin_artifacts/<GAMEVER>` tree.

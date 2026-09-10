---
name: trigger-release-build
description: Safely dispatch an immutable source-owned Release verification or publication from the current origin/main SHA. Use only when explicitly asked to verify, publish, or rebuild a game version.
disable-model-invocation: true
---

# Trigger Release Build

Use the bundled script as the only remote-operation entry point. Do not construct an ad-hoc `gh workflow run`
command, accept a user-supplied SHA, move a tag, edit a Release, cancel work, or bypass source-artifact preflight.

## Procedure

1. Confirm both release choices with the user **before any remote work**. Ask two separate questions and do not
   dispatch until both are answered explicitly — never choose on the user's behalf, never preselect an option, and never
   infer an answer from a previous run.
   - Build path: the standard `release` workflow (fresh `-force_all` rebuild, proves the artifacts can be rebuilt)
     versus the manual `rebuild-free` emergency path (binds the tracked `bin_artifacts/<GAMEVER>` and does not prove
     rebuildability).
   - Publication: `verify-only` (verify candidates without publishing) versus `publish` (run the protected publishers;
     published content is immutable).
   In Claude Code, ask with the `AskUserQuestion` tool, offering both choices on each question.
2. Extract the requested game version, or use `latest` only when the user explicitly asks for the latest version.
3. Map the confirmed answers onto the script flags: `--mode <verify-only-or-publish>`, plus `--workflow rebuild-free`
   only when the user chose that path. Omit `--workflow` for the standard `release` workflow.
4. Run from any directory with the confirmed mode stated explicitly:

   ```powershell
   uv run python .claude/skills/trigger-release-build/scripts/trigger_release_build.py <GAMEVER-or-latest> --mode <verify-only-or-publish> [--workflow <release-or-rebuild-free>]
   ```

5. Report the script's selected version, publication mode, workflow, full `SOURCE_SHA`, commit subject, and Actions run
   URL.
6. If the script refuses the operation, surface its exact safety reason and stop. Do not bypass repository, auth,
   version, source-artifact, duplicate-work, or `origin/main` checks.

Published content is immutable. A retry dispatches the same source identity and relies on the protected publishers'
exact-byte idempotency; it never selects a republish/clobber mode. Any requested generator/config change must already be
merged into `origin/main` with its complete `bin_artifacts/<GAMEVER>` tree.

---
name: trigger-release-build
description: Safely dispatch an immutable source-owned Release verification or publication from the current origin/main SHA. Use only when explicitly asked to verify, publish, or rebuild a game version.
disable-model-invocation: true
---

# Trigger Release Build

Use the bundled script as the only remote-operation entry point. Do not construct an ad-hoc `gh workflow run`
command, accept a user-supplied SHA, move a tag, edit a Release, cancel work, or bypass source-artifact preflight.

## Procedure

1. Extract the requested game version, or use `latest` only when the user explicitly asks for the latest version.
2. Select `verify-only` for a non-publishing rebuild/verification. Select `publish` only when the user explicitly asks
   to publish or retry publication.
3. Run from any directory with the mode stated explicitly:

   ```powershell
   uv run python .claude/skills/trigger-release-build/scripts/trigger_release_build.py <GAMEVER-or-latest> --mode <verify-only-or-publish>
   ```

4. Report the script's selected version, publication mode, full `SOURCE_SHA`, commit subject, and Actions run URL.
5. If the script refuses the operation, surface its exact safety reason and stop. Do not bypass repository, auth,
   version, source-artifact, duplicate-work, or `origin/main` checks.

Published content is immutable. A retry dispatches the same source identity and relies on the protected publishers'
exact-byte idempotency; it never selects a republish/clobber mode. Any requested generator/config change must already be
merged into `origin/main` with its complete `bin_artifacts/<GAMEVER>` tree.

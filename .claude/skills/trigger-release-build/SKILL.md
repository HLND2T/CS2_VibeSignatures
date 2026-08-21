---
name: trigger-release-build
description: Safely dispatch a new release build or same-version republish from the immutable current origin/main SHA. Use only when explicitly asked to publish, rebuild, or republish a game version.
disable-model-invocation: true
---

# Trigger Release Build

Use the bundled script as the only remote-operation entry point. Do not construct an ad-hoc `gh workflow run`
command, accept a user-supplied SHA, move a tag, edit a Release, cancel work, or merge an output PR.

## Procedure

1. Extract the requested game version, or use `latest` only when the user explicitly asks for the latest version.
2. Run from any directory:

   ```powershell
   uv run python .claude/skills/trigger-release-build/scripts/trigger_release_build.py <GAMEVER-or-latest>
   ```

3. Report the script's selected version, selected mode, full `SOURCE_SHA`, commit subject,
   and Actions run URL.
4. If the script refuses the operation, surface its exact safety reason and stop. Do not bypass repository, auth,
   version, tag/Release, duplicate-work, or `origin/main` checks.

The script derives the mode from remote state: use `mode=new` only when both the tag and Release are absent, and use
`mode=republish` only when both exist. Reject mixed states and do not accept a user-supplied mode. Any requested
generator/config change must already be merged into `origin/main`.

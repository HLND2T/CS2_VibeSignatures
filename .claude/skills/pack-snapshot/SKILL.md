---
name: pack-snapshot
description: Pack configured symbol YAML from a versioned bin directory into the canonical tracked game-symbol snapshot and verify it against the same analysis config. Use when explicitly asked to pack, rebuild, refresh, or verify a repository game-symbol snapshot for one GAMEVER.
---

# Pack Snapshot

Use the bundled script as the only entry point. It resolves `configs/<GAMEVER>.yaml`, atomically writes
`gamesymbols/<GAMEVER>.yaml`, and immediately verifies the snapshot against `bin/<GAMEVER>`.

## Resolve GAMEVER

Use an exact GAMEVER from the user's request. If omitted, read `CS2VIBE_GAMEVER` from `.env`; if it is absent or empty,
ask the user and wait. Do not infer `latest` or substitute another version.

Require both `configs/<GAMEVER>.yaml` and the configured symbol YAML inputs under `bin/<GAMEVER>`. Preserve unrelated
worktree changes and never stage or commit files.

## Pack And Verify

Run from the repository root:

```powershell
uv run python .claude/skills/pack-snapshot/scripts/pack_snapshot.py <GAMEVER>
```

The command replaces only `gamesymbols/<GAMEVER>.yaml`. Treat `Snapshot verification: passed` as the completion marker.
If the command fails, stop and report its exact error inside:

```text
<skill_error>ERROR REASON</skill_error>
```

On success, report the snapshot path and byte size printed by the script, then run `git status --short` and report the
tracked files changed by this operation.

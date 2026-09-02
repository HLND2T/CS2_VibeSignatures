---
name: restore-from-snapshot
description: Restore versioned symbol YAML from a canonical same-version snapshot, optionally replace trusted YAML. Use when asked to restore, unpack, hydrate, or seed game-symbol YAML from tracked snapshots, including when delegated by init-gamebin. Never restore symbols from a different, older GAMEVER snapshot into a newer target.
---

# Restore From Snapshot

Use the bundled script as the only entry point. Restore only from an exact same-version snapshot. Never restore symbol YAML
from a different, older GAMEVER snapshot into a newer target.

## Resolve GAMEVER

Use an exact target GAMEVER from the caller or user. If omitted, read `CS2VIBE_GAMEVER` from `.env`; if it is absent or
empty, ask the user and wait. Reject versions absent from `download.yaml`.

## Restore Trusted Snapshot

Run from the repository root:

```powershell
uv run python .claude/skills/restore-from-snapshot/scripts/restore_from_snapshot.py <GAMEVER>
```

When `gamesymbols/<GAMEVER>.yaml` exists, the script restores without overwriting different YAML and then verifies the
complete target against `configs/<GAMEVER>.yaml`. Do not retry with replacement after a conflict unless the user
explicitly requests replacement. For an explicit trusted replacement, run:

```powershell
uv run python .claude/skills/restore-from-snapshot/scripts/restore_from_snapshot.py <GAMEVER> --replace
```

## When Trusted Snapshot Is Unavailable

When the trusted command reports `Symbol snapshot: unavailable; no YAML restored`, do not offer or perform a forced restore
from a previous or base snapshot. A snapshot for one GAMEVER is never a valid source for a different version, so restoring
an older `gamesymbols/<BASE_GAMEVER>.yaml` into a newer `bin/<GAMEVER>` is never allowed.

Report that no YAML was restored and finish successfully. Do not use `--force-base-snapshot` under any circumstances.

## Handle Result

Treat only these outputs as success:

- `Symbol snapshot: restored and verified`
- `Symbol snapshot: restored and round-trip verified`
- `Symbol snapshot: restored and verified with replacement`
- `Symbol snapshot: unavailable; no YAML restored` (expected when no same-version snapshot exists; do not substitute,
  and never fall back to an older GAMEVER snapshot)

If the command fails, stop and report its exact error inside:

```text
<skill_error>ERROR REASON</skill_error>
```

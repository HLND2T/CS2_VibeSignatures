---
name: restore-from-snapshot
description: Restore versioned symbol YAML from a canonical same-version snapshot, optionally replace trusted YAML, or explicitly force a different base GAMEVER snapshot after user confirmation while skipping target trust checks. Use when asked to restore, unpack, hydrate, or seed game-symbol YAML from tracked snapshots, including when delegated by init-gamebin.
---

# Restore From Snapshot

Use the bundled script as the only entry point. Keep trusted same-version restoration separate from cross-version forced
restoration, and never describe a forced base restore as trusted or verified.

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

## Offer Forced Base Restore

When the trusted command reports `Symbol snapshot: unavailable; no YAML restored` and prints
`Suggested base snapshot: gamesymbols/<BASE_GAMEVER>.yaml`, ask exactly:

`Force restore gamesymbols/<BASE_GAMEVER>.yaml to bin/<GAMEVER> without trust checks? (yes/no)` /
`是否跳过信任检查，强制将 gamesymbols/<BASE_GAMEVER>.yaml 还原到 bin/<GAMEVER>？(yes/no)` depending on the
user's preferred language. Wait for an explicit yes or no.

- If the user answers no, report that no YAML was restored and finish successfully.
- If the user answers yes, warn that symbol addresses may be stale, then run:

  ```powershell
  uv run python .claude/skills/restore-from-snapshot/scripts/restore_from_snapshot.py <GAMEVER> --force-base-snapshot <BASE_GAMEVER>
  ```

The forced mode skips target GAMEVER, config digest, contract, and verification checks. It still validates snapshot
schema, base filename/payload consistency, safe relative YAML paths, and real target directories. It deletes and replaces
only `.yaml` files under `bin/<GAMEVER>`; binaries and IDA databases remain unchanged. Never pass the force option without
the user's explicit yes.

## Handle Result

Treat only these outputs as success:

- `Symbol snapshot: restored and verified`
- `Symbol snapshot: restored and round-trip verified`
- `Symbol snapshot: restored and verified with replacement`
- `Symbol snapshot: force-restored without trust checks from gamesymbols/<BASE_GAMEVER>.yaml`
- `Symbol snapshot: unavailable; no YAML restored` after the user answers no or no base suggestion exists

If the command fails, stop and report its exact error inside:

```text
<skill_error>ERROR REASON</skill_error>
```

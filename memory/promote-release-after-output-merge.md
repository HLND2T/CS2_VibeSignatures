---
title: promote-release-after-output-merge
type: note
permalink: cs2-vibesignatures/promote-release-after-output-merge
---

# Promote Release After Output Merge

## Overview
The promotion workflow accepts only a trusted merged generated-output PR, archives accepted versioned gamedata directly, promotes private bin transactionally, verifies Release assets, and authorizes completed-stage cleanup.

## Responsibilities
- Verify repository/Bot/branch/merge-parent/PR-index identities and allowed paths.
- Verify schema-4 manifests, accepted `gamedata/<GAMEVER>/`, generator contract, and staged bin.
- Archive without gamedata generation or live upstream access.
- Apply immutable tag rules and upload/download-hash-check Release assets.
- Write durable completion records and run idempotent cleanup.

## Involved Files & Symbols
- `.github/workflows/promote-release-after-output-merge.yml` - promotion.
- `.github/workflows/cleanup-completed-release-staging.yml` - scheduled fallback.
- `release_workflow_lib/promotion.py` - `verify_promotion`, `promote_bin`, `finalize_promotion`, `cleanup_completed`.
- `release_workflow_lib/manifests.py` - provenance and tracked-output verification.

## Architecture
```text
merged output PR -> verify accepted Git + staged bin -> archive gamedata/<GAMEVER>
 -> promote bin -> publish and verify assets -> durable completion record
 -> cleanup-trash rename -> delete heavy stage
```

## Dependencies
- Accepted output merge, immutable source config, persisted staging/bin, GitHub tags/Releases.
- Protected `win64` environment.

## Notes
- Archives never recreate `dist/...`.
- Delayed cleanup does not require current accepted bin to retain the old build.
- Interrupted deletion resumes from the exact completion-record-bound trash path.
- Staging excludes entire BinSync `.bsproj` directories and regenerable `.binsync.json` sidecars. Promotion therefore
  accepts only durable bin state; a later republish recreates sidecars from validated remotes and lets BinSync recover
  local repositories through `auto_clone`.
- Release-workflow tree removal clears a Windows read-only attribute and retries only after `PermissionError`.

## Callers
- Generated-output `pull_request.closed`.
- Scheduled/manual completed-staging cleanup.

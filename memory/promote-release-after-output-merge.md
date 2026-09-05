---
title: promote-release-after-output-merge
type: note
permalink: cs2-vibesignatures/promote-release-after-output-merge
---

# Promote Release After Output Merge

## Status
Historical / superseded after the source-owned artifacts cutover. Retained only to interpret old generated-output PR and promotion receipts.

## Overview
The removed promotion workflow accepted a merged generated-output PR, reconstructed private staging, promoted accepted bin, and published Release assets. The active pipeline has no output PR or merge-triggered promotion; protected publishers consume hosted-verified candidates from a fresh rebuild of immutable source truth.
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
- Historical responsibilities, paths, and recovery markers below are not active operating instructions.
- Current BinSync publication is fast-forward-only and isolated from the main-repository Release publisher.
- Current Release assets are immutable and derived from `source SHA + binary identity + bin_artifacts`; same-version clobber is forbidden.
- See [[build-on-self-runner]] and [[project_overview]].
## Callers
- Generated-output `pull_request.closed`.
- Scheduled/manual completed-staging cleanup.

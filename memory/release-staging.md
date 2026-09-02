---
title: release-staging
type: note
permalink: cs2-vibesignatures/memory/release-staging
tags:
- release
- staging
- ci-cd
---

# Release Staging

## Status
Historical / superseded after the source-owned artifacts cutover. This note records the removed generated-output/release-staging design for archaeology and rollback only; do not use it as an operating procedure.

## Overview
Before the source-owned cutover, the release build staged analyzed private-bin state and waited for a generated-output PR merge before promotion. The active pipeline no longer creates this staging transaction, output branch, READY/PROMOTION markers, or accepted-bin YAML correctness source.
## On-disk location
- Root: `$PERSISTED_WORKSPACE\release-staging` (`PERSISTED_WORKSPACE` is a GitHub secret configured on the win64 self-hosted runner, not a repo path).
- Build dir per candidate: `release-staging\<gamever>\<build_id>\` where `build_id = <run_id>-<run_attempt>`.
- PR index: `release-staging\pr-index\<pr_number>.json` — maps output-PR number -> staging identity (gamever/build_id/pr_head_sha/output_branch).
- Completed records: `release-staging\completed\<gamever>\<build_id>.json`.
- Locks: `release-staging\locks\<gamever>.lock` — shared by promote-bin and warmup sync-accepted-bin.
- Cleanup trash: `release-staging\cleanup-trash\<gamever>\<build_id>`.

## Contents of a build dir
- `bin\<gamever>\` — durable copy of the analyzed bin tree (copied with `shutil.copy2`), **excluding all IDA
  database suffixes** (`.i64 .idb .id0 .id1 .id2 .nam .til`), entire BinSync `.bsproj` directories, and regenerable
  `.binsync.json` sidecars.
- `manifest.json` — pending private manifest (schema v4):
  - tracked fields: `schema_version/gamever/release_tag/mode/build_id/source_sha/candidate_sha256/bin_manifest_sha256/tracked_output_manifest_sha256/workflow_run_url/analysis_config_path/analysis_config_sha256/analysis_config_contract_digest_version/analysis_config_contract_sha256/gamedata_path/gamedata_manifest_sha256/generator_contract_sha256`
  - pending-only fields: `repository` / `output_branch` (`gamesymbols/build/<gamever>/<build_id>`) / `pr_head_sha` (null until `finalize_stage`) / `bin_files` (per-file `path+size+sha256` inventory) / `tracked_files` (git-index inventory of `gamesymbols/<gamever>.yaml` + `gamedata/<gamever>/**`).
- `READY` — marker file containing the SHA-256 of `manifest.json`; written only after `pr_head_sha` binding in `finalize_stage`.
- After merge, promotion adds markers: `PROMOTION_STARTED`, `PROMOTED.json`, `PROMOTION_COMPLETE`.

## Why staging keeps game binaries (dll/so)
The binaries are **not** redundant storage; three roles depend on them:
1. **Promote-bin transaction source** — `promote_bin` verifies the staged bin inventory against `bin_manifest_sha256` and transactionally swaps it into `PERSISTED_WORKSPACE/bin/<gamever>` (accepted bin) via incoming/backup `os.replace`.
2. **Release asset source** — `reconstruct_workspace` restores staged bin into the checkout `bin/<gamever>`; `gamebin-<gamever>.7z` ships only `*.dll`/`*.so` while `gamedata-<gamever>.7z` excludes them. Both archives are published to the GitHub Release.
3. **Snapshot<->binary hash anchor** — `verify_promotion` cross-checks the snapshot binary metadata (`gamesymbols/<gamever>.yaml`) against the staged bin files, proving symbols match the exact analyzed bytes.

## Relationship with warmup `sync-accepted-bin` (write path overlaps, roles differ — not redundant)
- Both write `PERSISTED_WORKSPACE/bin/<gamever>`, share the per-GAMEVER lock, and exclude recoverable IDA/BinSync state.
- `sync-accepted-bin` (last step of `warmup-idb.yml`): idempotent **freshness mirror** of the consumed workspace `bin/<gamever>` after every warmup run; no build identity, no gate markers. Keeps accepted bin usable as the next warmup restore source / oldgamever baseline before the release PR merges.
- `promote-bin` (on output-PR merge): the **verification gate** that binds accepted bin to the immutable release identity (build_id / candidate_sha256 / bin_manifest_sha256) and writes durable audit records.
- Same-hash fast path: `promote_bin` becomes a no-op when warmup already wrote identical bytes (`promotion.py` `if inventory_sha256(...) == expected_hash: return`).
- Sync uses uuid-named incoming/backup; promote uses deterministic `.<gamever>.<build_id>.incoming/.backup` (recovery paths used by abandon).

## Involved Files & Symbols
- `release_workflow_lib/staging.py` — `stage_build`, `finalize_stage`, `write_pr_index`, `staging_directory`, `load_indexed_pending`.
- `release_workflow_lib/promotion.py` — `verify_promotion`, `promote_bin`, `reconstruct_workspace`, `finalize_promotion`, `cleanup_completed`.
- `release_workflow_lib/sync_accepted_bin.py` — `sync_accepted_bin`.
- `release_workflow_lib/manifests.py` — `build_tracked_manifest`, `TRACKED_FIELDS`.
- `release_workflow_lib/hashing.py` — `file_inventory`, `inventory_sha256`, `tracked_output_inventory`.
- `.github/workflows/build-on-self-runner.yml` — `stage-pending` / `create-output-pr` steps.
- `.github/workflows/promote-release-after-output-merge.yml` — `verify` / `reconstruct` / `create-archives` / `promote-bin` steps.

## Notes
- Historical details below describe the removed v4 staging protocol and may help interpret old runs or Git history.
- Active releases use tracked `bin_artifacts`, fresh isolated rebuilds, hosted candidate verification, protected BinSync publication, and immutable Release publication; see [[build-on-self-runner]].
- Do not recreate `release-staging`, generated-output branches, tracked snapshot/gamedata promotion, or promote-bin commands in normal workflows.
---
title: pr-self-runner
type: note
permalink: cs2-vibesignatures/pr-self-runner
---

# pr-self-runner

## Overview
`.github/workflows/pr-self-runner.yml` owns deterministic validation for same-repository PRs. A full path validates an
immutable merge ref on the self-hosted Windows runner, then stages analyzed YAML for merge-time promotion. It builds
temporary snapshot/gamedata candidates only to feed the C++ ABI gate and contract checks; it does NOT publish snapshot
or gamedata back to the PR head. A stable terminal job named `pr-validate` requires the full path to pass.

## Responsibilities
- Normalize `pull_request` events into PR number, immutable head/base/source SHAs, ref, user, title, validation path,
  and GAMEVER selection.
- Reject forks/generated-output PRs on the full path.
- Reject PRs that add, modify, copy, or rename a versioned analysis config to any GAMEVER other than the latest tag in
  `download.yaml`, before warm-cache dispatch.
- Run `pr-warmup-idb` only for non-bump `validation_path=full` runs.
- Restore the explicit warm-cache generation, validate reparse/cache/IDA identity, and analyze with
  `ida_analyze_bin.py -require_warm_idb`.
- Build one immutable symbol candidate and matching isolated gamedata candidate, then run C++ ABI tests against the
  exact symbol bytes.
- Stage analyzed `bin/<GAMEVER>/**/*.yaml` before any remote write so merge finalization remains unchanged.

## Involved Files & Symbols
- `.github/workflows/pr-self-runner.yml` - jobs `pr-preflight`, `pr-warmup-idb`, `pr-validate-full`, stable
  `pr-validate`, and `finalize-pr-workspace`.
- `.github/workflows/warmup-idb.yml` - reusable immutable cache producer.
- `pr_validation_version.py` - resolves the exact full-path validation GAMEVER from the pinned base.
- `idb_cache.py`, `ida_analyze_bin.py`, `gamesymbol_candidate.py`, `gamedata_candidate.py`,
  `run_cpp_tests.py` - full validation and candidate lifecycle.
- `tests/test_pr_self_runner_workflow.py` - DAG and behavior contracts.

## Architecture
1. Pull-request preflight checks out `refs/pull/<PR>/merge`, resolves cache eligibility and immutable source SHAs, and
   resolves the exact validation GAMEVER from the pinned base.
2. Full non-bump runs consume an explicit warm-cache generation and perform baseline restore/invalidation, repository
   tests, strict IDA analysis, candidate/gamedata build, and C++ validation.
3. Full success stages analyzed YAML and cleans candidate state; no commit or push back to the PR head occurs.
4. The terminal `pr-validate` job requires `pr-preflight` and `pr-validate-full` to both succeed; merged-PR
   finalization (`finalize-pr-workspace`) promotes the latest staged analyzed YAML into accepted persisted bin.

## Dependencies
- GitHub PR merge refs and API, protected `win64` environment, self-hosted Windows runner, Ubuntu hosted runner.
- `contents: read` only - publication is release-pipeline only.
- `PERSISTED_WORKSPACE/idb-cache/<GAMEVER>` and `PERSISTED_WORKSPACE/pr-yaml-staging/<PR>`.

## Notes
- Snapshot/gamedata publication was removed from this workflow (#803); `gamesymbols/<GAMEVER>.yaml` now advances only
  at release time via [[build-on-self-runner]].
- No workflow-level `concurrency` of its own; same-GAMEVER warmup exclusion is inherited from [[warmup_idb]]'s job-level `warmup-idb-<repo>-<gamever>` group (`queue: max`).
- Merge-time YAML promotion runs via `release_workflow.py promote-staged-yaml`, which takes the shared per-GAMEVER lock (`release-staging/locks/<gamever>.lock`) so it cannot race `sync_accepted_bin` or `promote_bin`.
- Candidate/config/generator inputs needed after checkout are copied below runner temp.
- Bump-download PRs retain lightweight validation (format plus config existence checks only). The scheduled bump workflow
  uses the protected `win64` environment's `HLND2T_GH_TOKEN` for branch pushes and PR API calls so `pull_request` runs
  are not parked at `action_required` by the `GITHUB_TOKEN` recursion guard.
- Bump classification accepts the legacy `github-actions[bot]` author for already-open PRs and trusted same-repository
  `OWNER` / `MEMBER` / `COLLABORATOR` authors for PAT-created PRs, while still requiring the canonical branch and title
  prefixes.
- Generated-output `gamesymbols/build/` PRs are excluded from every job here by the same author rule, because
  [[build-on-self-runner]] now creates them with the `win64` environment's `HLND2T_GH_TOKEN`. Their required
  `pr-validate` check comes from `validate-generated-output-pr.yml` instead.
- Reference-YAML orphans are a **warning, not an error** (`gamesymbol_snapshot_lib/pr_validation.py`
  `_reference_change_nodes`). An added/modified `ida_preprocessor_scripts/references/**.yaml` with no HEAD consumer
  emits `warning: <action> orphan reference had no HEAD consumer: <path>` and invalidates nothing, mirroring the
  pre-existing deleted-orphan warning. Consumers come only from literal `"reference_yaml_paths"` entries inside
  `LLM_DECOMPILE` specs of an *active* contract node, so the former hard `error[orphan_active_reference]` failed two
  legitimate cases: an xref-based finder shipping reference YAML purely as documentation for its Agent fallback
  SKILL.md, and a consumer declared only in a newer `configs/<GAMEVER>.yaml` while validation runs against the older
  base GAMEVER's contract (e.g. PR #884: finder in `configs/14178.yaml`, `GAMEVER=14177b`). Base-side consumers still
  contribute invalidation nodes when a modified reference loses its HEAD consumer.

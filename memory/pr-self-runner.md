---
title: pr-self-runner
type: note
permalink: cs2-vibesignatures/pr-self-runner
---

# pr-self-runner

## Overview
`.github/workflows/pr-self-runner.yml` owns deterministic validation and publication for same-repository PRs. A full
path validates an immutable merge ref on the self-hosted Windows runner, publishes the exact guarded snapshot/gamedata
candidate as a bot commit on the PR head, then explicitly dispatches an Ubuntu-only lightweight recheck for the new
head. A stable terminal job named `pr-validate` aggregates exactly one valid path.

## Responsibilities
- Normalize `pull_request` and `workflow_dispatch` events into PR number, immutable head/base/source SHAs, ref, user,
  title, validation path, and GAMEVER selection.
- Reject forks/generated-output PRs on the full path and reject untrusted/manual published-recheck dispatches.
- Run `pr-warmup-idb` only for non-bump `validation_path=full` runs.
- Restore the explicit warm-cache generation, validate reparse/cache/IDA identity, and analyze with
  `ida_analyze_bin.py -require_warm_idb`.
- Build one immutable symbol candidate and matching isolated gamedata candidate, then run C++ ABI tests against the
  exact symbol bytes.
- Stage analyzed `bin/<GAMEVER>/**/*.yaml` before any remote write so merge finalization remains unchanged.
- Checkout the exact PR head, publish `gamesymbols/<GAMEVER>.yaml` plus `gamedata/<GAMEVER>/`, enforce allowed paths
  and both digests, create the canonical bot provenance commit, recheck the remote head, push normally, and dispatch
  `published-recheck`.
- Recheck the live PR, actor/sender, commit parent/base/message, allowed paths, snapshot digest, and gamedata manifest on
  Ubuntu without warmup, IDA, rebuilds, C++ tests, staging, or publication.

## Involved Files & Symbols
- `.github/workflows/pr-self-runner.yml` - jobs `pr-preflight`, `pr-warmup-idb`, `pr-validate-full`,
  `pr-published-recheck`, stable `pr-validate`, and `finalize-pr-workspace`.
- `.github/workflows/warmup-idb.yml` - reusable immutable cache producer.
- `pr_validation_version.py` - resolves the exact full-path validation GAMEVER from the pinned base.
- `pr_published_recheck.py` - published commit/API/path/digest verifier and worktree publication guard.
- `idb_cache.py`, `ida_analyze_bin.py`, `gamesymbol_candidate.py`, `gamedata_candidate.py`,
  `run_cpp_tests.py` - full validation and candidate lifecycle.
- `tests/test_pr_self_runner_workflow.py`, `tests/test_pr_published_recheck.py` - DAG and behavior contracts.

## Architecture
1. Pull-request preflight checks out `refs/pull/<PR>/merge`; dispatch preflight validates required inputs and checks out
   the expected bot head.
2. PR preflight classifies a canonical bot publication commit from the immutable PR head and selects
   `published-recheck` when its provenance and validated base match; otherwise it selects `full`. Dispatch verification
   queries the live PR and applies the same provenance checks, with base drift selecting `full`.
3. Full non-bump runs consume an explicit warm-cache generation and perform baseline restore/invalidation, repository
   tests, strict IDA analysis, candidate/gamedata build, and C++ validation.
4. Full success stages analyzed YAML, switches from the merge ref to the exact PR head, publishes the same candidate
   bytes, creates H2 with H1 as its sole parent, cleans candidate state, checks the remote still points to H1, pushes,
   and explicitly dispatches H2.
5. Published recheck repeats API/provenance/path/digest verification on Ubuntu and emits verified head/base/digests.
6. The terminal `pr-validate` job accepts only one successful internal path; merged-PR finalization continues promoting
   the latest staged analyzed YAML into accepted persisted bin.

## Dependencies
- GitHub PR merge refs and API, protected `win64` environment, self-hosted Windows runner, Ubuntu hosted runner.
- `contents: write` and `actions: write` are scoped to `pr-validate-full`; read permissions remain elsewhere.
- `PERSISTED_WORKSPACE/idb-cache/<GAMEVER>` and `PERSISTED_WORKSPACE/pr-yaml-staging/<PR>`.

## Notes
- A bot publication push can also produce a `pull_request.synchronize` run; preflight verifies its canonical provenance
  and routes that event to the same lightweight recheck instead of repeating full validation.
- Explicit `workflow_dispatch --ref <PR_HEAD_REF>` remains mandatory after full publication and is the recovery path
  when a bot push event is suppressed or delayed.
- Concurrency is separated into `full` and `recheck-<expected_head_sha>` groups.
- Candidate/config/generator inputs needed after checkout are copied below runner temp.
- Idempotent publisher reruns verify an already-pushed H2 and only redispatch it.
- Head drift rejects push; base drift rejects lightweight reuse and returns to the full merge-ref path.
- Bump-download PRs retain lightweight full-path validation and do not publish symbol outputs.

---
title: Warm IDB lease identity must not encode the run attempt
type: guide
permalink: cs2-vibesignatures/lessons/warm-idb-lease-identity-must-not-encode-run-attempt
tags:
- cs2vibesignatures
- ci
- idb-cache
- lease
- rerun
---

# Warm IDB lease identity must not encode the run attempt

## Symptom
`validate-full (<gamever>) / validate` fails at `Restore current-run IDB lease from S3` with
`Restore s3 cache failed: Cache item not found` then `Required S3 cache could not be restored.` (the step is `required: true`).
The `validate` job never reaches the analysis stage.

## Trigger signal
The run was produced by **"Re-run failed jobs"** (not "Re-run all jobs"), i.e. `run_attempt > 1`.

## Root cause
A partial re-run only re-executes the failed `validate` job; the already-successful `warmup` producer job is
**carried over verbatim** (its `started_at`/`completed_at` and entire log are byte-identical across attempts).
`warmup` therefore keeps publishing the lease under the attempt it originally ran in, while `validate` resolves
the selection for the new attempt. With `GITHUB_RUN_ATTEMPT` baked into both the lease object key and the lease
owner document, the two sides disagree on every re-run:

| | warmup (producer, wrote) | validate (consumer, read) |
|---|---|---|
| attempt | 1 | 2 |
| lease key | `...-shared-lease-<gamever>-<run_id>-1-<lease_id>` | `...-shared-lease-<gamever>-<run_id>-2-<lease_id>` |

## Constraint
`run_attempt` is **transport metadata, not transaction identity**; a rerun attempt must not change candidate
identity. Lease ids are already per-run `uuid4().hex`, so run identity is fully carried by `run_id` alone and
attempts inside one run can never need to be distinguished.

## Correct approach
`GITHUB_RUN_ATTEMPT` must not appear in any warm IDB lease identity:
- `ci_s3_cache.selection_layout` key: `{prefix}-lease-{gamever}-{run_id}-{lease_id}` (no attempt segment).
- `idb_cache_leases.LeaseOwner`: `{repository, run_id}` only — `owner == owner.document()` is an exact-equality
  gate, so key-only fixes still fail with `IDB lease repository/run mismatch`.
- Do not thread `--run-attempt` from `ci_runner.idb()` into `idb_cache.py`.

## Distinguishing from the sibling failure
The first attempt of the same run failed *earlier* and for an unrelated reason:
`CI idb-restore failed: Runner tool *** is unavailable on the host PATH` (`ci_runner.host_tool`). A re-run that
fixes nothing therefore converts an environment failure into a lease-key failure — do not assume both failures
share one cause.

## Verification
- Reproduce directly: with the old code, `selection_layout(..., run_id="100", run_attempt="1")` and
  `run_attempt="2"` return **different** lease keys; after the fix they are equal.
- Regression coverage: `tests/test_ci_s3_cache.py::test_lease_identity_ignores_re_run_attempts`,
  `tests/test_idb_cache.py::test_same_run_consumer_outlives_a_failed_attempt_rerun`.

## Scope
`.github/workflows/{warmup-idb,pr-self-runner,source-artifact-*-bridge}.yml` warm IDB producer/consumer pairs
plus `ci_s3_cache.py` / `idb_cache.py` / `idb_cache_leases.py` / `ci_runner.py`.

## See also
[[build-on-self-runner]] (stable transaction identity note), [[warmup_idb]], [[ci-windows-long-paths]],
[[pr-self-runner]].

---
title: source-artifact-required
type: note
permalink: cs2-vibesignatures/source-artifact-required
---

# source-artifact-required

## Overview
`.github/workflows/source-artifact-required.yml` is the PR / Merge Queue gate workflow. Its first job `bind-source-artifact-plan` loads a default-branch trusted planner, analyzes the untrusted prospective merge tree read-only, and emits a plan bound to the exact merge tree that routes all downstream validation (`light` / `full` / `bootstrap_required`). It triggers on `pull_request_target` + `merge_group` and only runs on `HLND2T/CS2_VibeSignatures`.

## Responsibilities
- Checkout the prospective tree as data only (`persist-credentials: false`): PR events use `refs/pull/{N}/merge`, merge_group uses its head SHA; nothing from the tree is executed.
- Resolve immutable event identity (`identity` step, pwsh): base/head/merge SHA plus `same-repository`; merge_group proves PR membership through the GitHub API (or the `gh-readonly-queue/.../pr-N-<sha>` head-ref regex) and accepts only same-repo PRs targeting the default branch; PR base must be the default branch; the checked-out HEAD must equal the event merge SHA.
- Checkout the trusted planner from `base-sha` into `.trusted-planner`; the bridge (`trusted_pr_context.py` + `trusted_artifact_pr.py`) is mandatory after the source-owned cutover — a missing bridge fails the job.
- Build the plan: `trusted_pr_context.py build` -> trusted context JSON, then `trusted_artifact_pr.py plan` -> plan JSON; publish job outputs and upload the plan as the immutable artifact `trusted-source-artifact-plan-<run_id>-<run_attempt>` (7-day retention).
- Route downstream: `bootstrap_required` -> `bootstrap-new-gamever` (pull_request_target + same-repo only); `light` -> `test-prospective-tree`; `full` -> `test-prospective-tree` plus per-GAMEVER `validate-full` matrix -> `pr-self-runner.yml` (same-repository only; forks fail closed).
- Terminal gates: `source-artifact-required` (stable required check aggregating binding/bootstrap/tests/full) and `pr-validate-merge-group` for the merge queue.

## Plan document (trusted_artifact_pr.py)
- Fields: `schema_version`, `event_kind`, `mode`, `base_sha`/`head_sha`/`merge_sha`/`merge_tree_sha`, `trusted_context_sha256`, `configured_game_versions`, `affected_game_versions`, `download_sha256`, `sdk_gitlink_sha`, base/merge analysis-source inventories, `changed_paths`, `impact` (release/gamedata/cpp/pages path-prefix flags), per-GAMEVER `game_versions` reports (`invalidated_paths`, `bootstrap_required`, `prior_gamever`), and the `plan_sha256` digest.
- Mode selection: any version with `bootstrap_required` -> `bootstrap_required`; any version with `invalidated_paths` -> `full`; otherwise `light`.
- `validate_trusted_artifact_plan` re-derives `plan_sha256` and rejects modes outside the three-value set; downstream workers reload and re-verify the plan, so plan drift fails closed.

## Involved Files & Symbols
- `.github/workflows/source-artifact-required.yml` - jobs `bind-source-artifact-plan`, `bootstrap-new-gamever`, `test-prospective-tree`, `validate-full`, `source-artifact-required`, `pr-validate-merge-group`.
- `trusted_pr_context.py` - trusted event context binding (repo root, event kind, base/head/merge refs, context digest).
- `trusted_artifact_pr.py` - `build_trusted_artifact_plan`, `validate_trusted_artifact_plan`, `load_trusted_artifact_plan`, `prepare_isolated_rebuild` (requires a full plan).
- `source_artifact_policy.yaml` - `mode: source-owned`, `artifact_root: bin_artifacts`; loaded from the trusted side.
- `.github/workflows/pr-self-runner.yml`, `.github/workflows/bootstrap-new-gamever-artifacts.yml` - routed downstream workers.

## Architecture
```text
pull_request_target / merge_group event
  -> checkout prospective tree as data (persist-credentials: false)
  -> immutable identity (base/head/merge SHA, same-repository)
  -> checkout base-owned planner at base-sha
  -> trusted context + plan bound to exact merge tree (plan_sha256)
  -> mode routing: light | full | bootstrap_required
  -> hosted tests (+ self-hosted full validation) or new-GAMEVER bootstrap
  -> stable required check source-artifact-required / pr-validate
```

## Design Intent
- `pull_request_target` trust boundary: the event runs base-branch workflow code with secret read access, so the PR tree is data only and every executed planner/policy byte comes from the immutable base SHA — a PR cannot influence its own validation routing by editing workflows, planner code, or policy.
- Immutable binding: the plan is bound to the exact prospective tree (`merge_tree_sha`) and self-hashed (`plan_sha256`); downstream jobs receive both via job outputs and the uploaded plan artifact and fail closed on drift, so planned tree = validated tree = merged tree (the merge queue revalidates the exact tree).
- Fail-closed everywhere: missing trusted bridge, fork + full mode, obsolete bootstrap-published head, invalid mode.
- Stable required checks: the multi-branch pipeline exposes fixed check names to branch protection.

## Dependencies
- Same-repository PR for full validation; fork PRs needing isolated IDA analysis must be mirrored to a same-repository branch.
- Required Workflow / ruleset trust root outside the repository so prospective workflow edits cannot self-report success.
- Related notes: [[post_change_candidate_lifecycle]] (lifecycle overview), [[pr-self-runner]] (full-validation worker), [[binary_lock]], [[project_overview]].

## Notes
- [fact] Empirically verified (two-version fixture, 2026-09-06): with `configs/14177.yaml` + `configs/14178b.yaml`, a shared-analysis change yields `mode=full, affected_game_versions=["14178b"]` and empty invalidation for the old version. Consequence of the latest-only maintenance scope: a PR editing only `bin_artifacts/<old GAMEVER>/**` routes to `light` mode — no producer rebuild validation for old-version artifact edits (same behavior with or without the workflow pin).

- [fact] Job outputs consumed downstream: `validation-mode`, `plan-sha256`, `merge-tree-sha`, `base-sha`, `head-sha`, `merge-sha`, `bootstrap-gamever`, `bootstrap-prior-gamever`, `plan-artifact-name`, `affected-versions`, `same-repository`.
- [fact] `bootstrap_required` always fails the terminal check by design: the bootstrap publisher appends `bin_artifacts/<GAMEVER>/**` to the bound PR head, making the validated head obsolete; the PR must be revalidated after `pull_request.synchronize`.
- [fact] Since commit `445e7312` (2026-09-06) the `validate-full` matrix derives unconditionally from `plan.affected_game_versions`; the hardcoded `["14178b"]` literal added by `92592fc9` was removed as redundant. Latest-only scoping lives entirely in the trusted planner (`maintained_versions` in `trusted_artifact_pr.py`, from `440f46e7`): every invalidation path is gated on `maintained`, so full mode always affects exactly the newest configured GAMEVER and GAMEVER rotation follows `configs/` without a workflow bump. `prepare_isolated_rebuild` still fails closed when the matrix gamever is not the plan's single affected target.
- [fact] `test-prospective-tree` runs `format_repo_files.py --check` plus all `tests/run_test_suite.py` suites (unit, repository-contract, redis-integration, release-integration, all) on the merge SHA with recursive submodules.

- [fact] Since the base-inherited-selected bridge (branch `dev-base-inherited-selected`, 2026-09-06) the plan schema is **4** and carries a top-level `execution_strategy` (`fresh-full-v1` default | `base-inherited-selected-v1`), sourced from the base-owned `source_artifact_policy.yaml` optional key `execution_strategy`. Each maintained GAMEVER report now partitions outputs into `execute_groups` / `execute_nodes` / `inherit_paths` / `inherited_absent_groups` / `removed_paths` (old `affected_producer_groups` / `selected_alternative_nodes` names removed; consumers updated: verifier, `new_gamever_artifact.py` bootstrap check, tests). The execution closure adds same-session prerequisite back-propagation. `pr-self-runner.yml` routes its execute step on `preparation.execution_strategy`: selected runs `ida_analyze_bin.py -selected_execution <manifest>` against a seeded actual root; fresh-full keeps `-force_all` with an empty root. Selected routing is enabled by the independent policy activation after Phase-D (2026-09-07); the parser still defaults to fresh-full when the key is absent. The PR worker explicitly uses CS2VIBE_STRING_MIN_LENGTH=4. Selected evidence cannot impersonate full: independent report domain `source2-selected-execution:v1`, and `release_artifact_rebuild.py` still demands force-all v2.

- [fact] Phase-D evidence: run 34031704261 passed PR/new-symbol+finder (6 groups), artifact-only (3), cross-stage (14), and fresh-full (3529); the shared-runtime selected sample retained 2195 succeeded nodes but skipped one Linux producer via the in-session skip_if_exists check. PR #931 fixed the missing `and not force_all` guard, covering both pre-existing and in-session marker cases. The records-only verifier extraction preserves production report identity/validity requirements.
- [fact] One-off continuation run 34067782997 restored the exact original warm generation and binary lock, retained the old successful evidence, and retried only CFlashbangProjectile_Spawn_NetworkStateChangedNotify on Linux (53.203 seconds). All 3529 groups are covered and the repaired 3526-file inventory equals the validated full baseline. The new proof is explicitly cross-run migration evidence, not a production PR/release attestation; the original failed report remains unchanged.
- [fact] Measured PR sample: producer 109.578 s, prepare/restore/producer/verify/downstream total 466.687 s; full baseline 7204.719 s / 7604.359 s. These totals exclude shared planning, runner provisioning and queue time. Shared-runtime changes still select all groups. Continuous base inheritance risk and release fresh-full requirements remain as documented.
- [fact] PR #926 merged on 2026-09-07 at e80b418a4689abdf3de1b569217ffb9511a8053c, satisfying the cleanup gate. The subsequent cleanup patch removes phase-d-validation.yml, phase_d_validation.py, phase_d_resume.py and temporary helper tests/registration. The executor fix, permanent regression test, selected policy, handoff and evidence links are retained.

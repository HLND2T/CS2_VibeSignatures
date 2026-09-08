---
title: pr-self-runner
type: note
permalink: cs2-vibesignatures/pr-self-runner
---

# pr-self-runner

## Overview
`.github/workflows/pr-self-runner.yml` is the reusable self-hosted full-validation worker selected by the trusted default-branch bridge. It rebuilds affected source-owned artifacts in a checkout-external root and proves exact equality with prospective Git blobs; it never stages outputs for later promotion or writes the PR branch.
## Responsibilities
- Consume the trusted bound plan and exact source/tree identity rather than PR-supplied routing.
- Restore binary-only accepted state and the exact immutable warm IDB generation with credentials disabled.
- Route on the base-owned execution strategy. With `base-inherited-selected-v1`, seed only the exact base Git-blob inheritance whitelist, execute the plan closure with `-selected_execution <manifest> -require_warm_idb`, and independently verify inherited bytes and exact execution coverage. With `fresh-full-v1`, require an empty checkout-external root and run every producer with `-force_all`. `-oldartifactdir bin_artifacts` remains signature reuse only; it is not a seed source.
- Verify attempted/winning alternatives, full formal inventory, canonical bytes, exact Git blob identity, and unchanged checkout artifacts.
- Build release-local snapshot/gamedata candidates and run C++ evidence gates without tracking or publishing them.
- Fail closed for forks, plan drift, unknown paths, missing cache identity, incomplete closure, or artifact byte drift.
## Involved Files & Symbols
- `.github/workflows/source-artifact-required.yml` - trusted caller and terminal `source-artifact-required`/`pr-validate` gates.
- `.github/workflows/pr-self-runner.yml` - isolated full-validation worker.
- `trusted_pr_context.py`, `trusted_artifact_pr.py` - bound plan/preparation/verification.
- `.github/workflows/warmup-idb.yml`, `idb_cache.py` - immutable neutral IDB generation.
- `ida_analyze_bin.py`, `bin_artifact_contract.py` - forced rebuild and artifact contract.
- `gamesymbol_candidate.py`, `gamedata_candidate.py`, `run_cpp_tests.py` - downstream evidence.
## Architecture
```text
trusted prospective-tree plan
  -> self-hosted binary/warm-IDB restore
  -> checkout-external actual artifact root
  -> force selected producer groups
  -> execution evidence + full canonical inventory
  -> exact comparison with prospective Git blobs
  -> release-local snapshot/gamedata/C++ evidence
  -> stable required check
```
## Dependencies
- Base-owned planner/policy and exact base/head/merge/tree SHAs.
- Same-repository payload for full validation; forks remain hosted-only and fail closed when analysis is required.
- Binary-only `PERSISTED_WORKSPACE/bin/<GAMEVER>`, immutable warm IDB generation, IDA/LLM secrets scoped to the analysis worker.
## Notes
- `bin_artifacts` is expected Git truth; `bin/` and persisted workspaces must not supply YAML correctness input.
- Checkout uses `persist-credentials: false`; the worker has no source-branch, BinSync, tag, or Release publication credential.
- Merge Queue membership must be resolved through trusted GitHub metadata before any self-hosted invocation.
- [fact] Cost structure (measured 2026-09-05, run 33973053680): the force-all producer step takes ~1h58m of the ~2h07m validate job. The driver `_execute_analysis` (`ida_analyze_bin.py:5070`) is fully serial — 13 modules x 2 platforms = 26 sequential IDA/MCP sessions, ~2348 skill executions at ~3s average each — even though `ExecutionPlan` already builds stage/job dependency edges that a parallel scheduler could honor. The same cost repeats at PR time and again at merge-queue revalidation (`max-parallel: 1`).

- [fact] Policy activation after Phase-D (2026-09-07) selects `base-inherited-selected-v1`; `mode=full`/the `validate-full` job name still denote the self-hosted route, not a force-all command. The worker explicitly sets `CS2VIBE_STRING_MIN_LENGTH=4` as used in the real comparison. Since PR #950 (2026-09-08) the value is defined once at workflow-level `env:` of all four win64 producer workflows (`pr-self-runner.yml`, `build-on-self-runner.yml`, `bootstrap-new-gamever-artifacts.yml`, `source-artifact-full-bridge.yml`) and jobs inherit it directly — the initial attempt referenced it in job-level env via `${{ env.* }}`, which actionlint rightly rejects (env context is not available inside a job-level `env:` mapping; available contexts there are github/inputs/matrix/needs/secrets/strategy/vars), so never re-add per-job `${{ env.X }}` references. Producer sessions must keep minlen=4 so bootstrap/release artifacts byte-match PR validation; do not rely on runner-local `.env` or the code default.
- [fact] Runs 34031704261 and its one-node continuation 34067782997 verify the migration samples; see [[source-artifact-required]] and `docs/plans/full-analysis-performance-handoff.md` for preserved failure/provenance limits. The #926 sample executes 6 groups (109.578 s producer) and inherits 3520 files; full baseline executes 3529 groups (7204.719 s producer). Shared-runtime invalidation remains full execution, and release continues to require fresh-full evidence.

## Failure evidence and drift diagnostics (#944)
- Trigger: PR prepare/execute/verify fails, or downstream candidate/C++ validation fails after a rebuild. A producer can exit before verify or preparation.json exists; a verify-only upload condition loses partial evidence.
- `artifact_diagnostics.py` owns raw flat YAML enumeration, bounded missing/extra/changed/unreadable rendering and allowlisted failure bundle writes. `trusted_artifact_pr.py` resolves the bound merge Git blobs and fixed staging layout; `release_artifact_rebuild.py` adapts the same helpers to release source Git blobs. Checkout and materialized expected bytes are not diagnostic baselines.
- PR prepare/verify append diagnostics at the failure boundary and accept `--diagnostics-dir`. Independent `diagnose` handles partial or downstream failures using workflow-supplied staging/GAMEVER/plan digest; corrupt preparation bytes are saved but cannot redirect evidence reads. The CLI does not create successful validation evidence on failure.
- Bundle: `verification-error.txt`, `diagnostics.json`, `trusted-plan.json`, `preparation.json`, `selected-execution-<GAMEVER>.json` when relevant, `execution-reports/<GAMEVER>.selected.json` or `.force-all.json`, and matching `actual/bin_artifacts/<GAMEVER>/<module>/*.yaml` / `expected/bin_artifacts/...` trees. Metadata records source provenance, strategy, bindings, phase, run identity and collection errors.
- Bounds: 40 diff lines and 16,000 characters per file, 1 MiB text diff input, five file details, 64,000 diagnostic characters including bounded path lists. Non-UTF-8/binary/newline-only changes retain byte facts. Unsafe paths, case collisions, links/reparse points and incomplete reads are reported without following them; unrelated files such as IDBs are excluded.
- Workflow collects into a fresh unique directory after failure and uploads `trusted-pr-rebuild-diagnostics-<run_id>-<run_attempt>-<GAMEVER>` for 30 days. Diagnostics failures remain secondary to the original rejection; success evidence upload behavior is unchanged.
- Validation: focused unittest coverage in `tests.test_artifact_diagnostics`, `tests.test_trusted_artifact_pr`, `tests.test_release_artifact_rebuild`, plus workflow static checks. This bridge changes trusted roots; live producer/verify failure samples must use a subsequent PR with the new trusted base. Real self-runner evidence has not been executed as part of the local implementation.

- Local test environment caveat: a `.env` value `CS2VIBE_STRING_MIN_LENGTH=4` is loaded during aggregate discovery (module-level `load_dotenv()` in `ida_analyze_bin.py`, imported via `gamesymbol_snapshot_lib.config`) and used to break two IDA mock tests (`test_collect_xref_func_starts_for_string_uses_substring_by_default`, `test_py_eval_extracts_standard_and_extended_registration_calls`) by flipping the generated py_eval string enumeration onto the netnode-guarded `strings.setup` branch. Fixed on PR #950's branch (2026-09-08): both tests now wrap code generation in `patch.dict(os.environ, {"CS2VIBE_STRING_MIN_LENGTH": ""}, clear=True)` (empty == unset in `_resolve_ida_string_min_length_config`), so aggregate and direct runs pass with or without a local `.env`; runner production keeps minlen=4 via the workflow-level env pinning. Any future test asserting the default string-enumeration path needs the same env isolation.

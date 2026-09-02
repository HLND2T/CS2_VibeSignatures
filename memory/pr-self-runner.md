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
- Prepare a fresh artifact root, copy only unaffected prospective artifacts, and run selected producer groups with `-force_all -require_warm_idb`.
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
- A Required Workflow/ruleset or independent trust root is still needed to prevent a prospective workflow edit from forging the required check.
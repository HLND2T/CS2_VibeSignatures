---
title: post_change_candidate_lifecycle
type: note
permalink: cs2-vibesignatures/post-change-candidate-lifecycle
---

# Workflow-Owned Post-Change Candidate Lifecycle

## Overview
`/create-pr` delivers source/config/reference changes together with their computed canonical `bin_artifacts` closure. A default-branch trusted planner binds the exact base/head/prospective tree; full validation rebuilds affected producer groups outside the checkout and compares the complete actual inventory with Git blobs. Snapshot/gamedata candidates exist only as release-local validation inputs and Release assets.
## Responsibilities
- `/create-pr`: preserve the explicitly staged source-owned change set and reject tracked legacy/Release output namespaces.
- `source-artifact-required.yml`: load base-owned planner/policy, bind the prospective tree, route light/full/bootstrap-required outcomes, and provide stable required checks.
- `pr-self-runner.yml`: restore exact warm IDB state, force selected producer groups in an isolated artifact root, verify execution evidence/exact bytes, and derive candidate/gamedata/C++ evidence.
- `bootstrap-new-gamever-artifacts.yml`: produce an empty-root full artifact candidate and let the protected hosted publisher fast-forward only the matching bump branch.
- `build-on-self-runner.yml`: after merge, independently rebuild the complete GAMEVER and produce credential-free Release/BinSync candidates.
## Involved Files & Symbols
- `.claude/skills/create-pr/SKILL.md` - source-owned PR delivery contract.
- `trusted_pr_context.py`, `trusted_artifact_pr.py`, `source_artifact_policy.yaml` - trusted planning and isolation contract.
- `.github/workflows/source-artifact-required.yml`, `.github/workflows/pr-self-runner.yml` - PR and Merge Queue gates.
- `.github/workflows/bump-download.yml`, `bump_download_candidate.py` - protected branch seed/synchronize publisher.
- `.github/workflows/bootstrap-new-gamever-artifacts.yml`, `new_gamever_artifact.py` - two-pass new-version bootstrap.
- `gamesymbol_candidate.py`, `gamedata_candidate.py`, `run_cpp_tests.py` - release-local downstream evidence.
## Architecture
```text
source + computed artifact closure -> PR head
  -> base-owned plan for prospective tree
    -> light hosted checks, or
    -> isolated affected-group rebuild -> exact bytes -> candidate/gamedata/C++ evidence
  -> source-artifact-required + pr-validate
  -> Merge Queue exact-tree revalidation
  -> Release fresh full rebuild and protected publication
```
## Dependencies
- Same-repository PR or hosted-only fork policy; forks needing full analysis fail closed.
- Exact Git trees/blobs, configured binary identity, warm IDB generation, and self-hosted analysis runner.
- External required-workflow/ruleset trust root so prospective workflow edits cannot self-report success.
## Notes
- No analyzed-YAML staging, merge-time bin promotion, generated-output PR, or tracked snapshot/gamedata publication remains.
- `bin_artifacts` A/M/D/R and downstream closure are author deliverables; CI independently recomputes them.
- Source writes have exactly two hosted exceptions under the protected `artifact-bootstrap` environment: the bump
  publisher creates/synchronizes one new `bump-download/<GAMEVER>` using only `download.yaml` plus the seeded config; the
  bootstrap publisher appends only `bin_artifacts/<GAMEVER>/**` to the still-bound PR head.
- Neither source publisher can satisfy the required check; the artifact-bearing head must pass normal validation.
- The trusted plan selects one complete prior source-owned GAMEVER, or explicit `null` for no baseline; bootstrap passes
  that identity explicitly and binds it into the force-all report, candidate manifest, and hosted verification.
- Release gamedata generation is offline and source-owned: generator baselines live under each module's `templates/`,
  mutable `DOWNLOAD_SOURCES` are rejected by candidate builds, and the hosted Release verifier fresh-rebuilds from the
  verified snapshot before comparing every output hash.
- BinSync candidate schema v3 binds a hosted-recomputed source selection projection
  (repository/module/platform/category/symbol, artifact Git-blob digest, and raw RVA). The local exporter consumes the same
  builder. Windows lift bias and IDA-lowered TOML remain binary/runtime evidence, not Git source truth.

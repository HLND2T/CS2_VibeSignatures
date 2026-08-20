---
title: build-on-self-runner
type: note
permalink: cs2-vibesignatures/build-on-self-runner
---

# Build On Self Runner

## Overview
`.github/workflows/build-on-self-runner.yml` validates an exact release source, requires a published warm IDB cache generation, builds immutable symbol/gamedata candidates, stages the private bin tree without IDA databases, and creates the generated-output PR. The PR merge remains the promotion gate for accepted release state, but warm-cache publication is available earlier and independently.
## Responsibilities
- Resolve exact `GAMEVER`, `SOURCE_SHA`, mode, and legacy-bootstrap policy.
- Call [[warmup_idb]] as a required reusable job and receive an immutable generation/cache key.
- Copy accepted persisted analysis state without IDA database files, verify the consumer IDA kernel version, then restore binaries and `.i64` only from the returned generation.
- Run `ida_analyze_bin.py -require_warm_idb`; cache absence, damage, or identity failure blocks release analysis.
- Build and validate immutable symbol/gamedata candidates.
- Stage the analyzed private bin tree without IDA database artifacts, then create an immutable generated-output PR.
## Involved Files & Symbols
- `.github/workflows/build-on-self-runner.yml` - release caller, strict cache restore, analysis, staging, and output-PR creation.
- `.github/workflows/warmup-idb.yml` - required reusable producer.
- `idb_cache.py` - explicit generation restore.
- `ida_analyze_bin.py` - strict `-require_warm_idb` analysis.
- `release_workflow_lib/staging.py` - `stage_build`, `finalize_stage`, and full private-bin inventory.
- `release_workflow_lib/promotion.py` - later transactional accepted-bin promotion.
- `tests/test_build_self_runner_workflow.py` - caller/restore/strict-analysis contracts.
## Architecture
Preflight -> required reusable warm-cache producer -> consumer IDA identity check -> exact generation restore -> strict analysis -> immutable symbol and gamedata validation -> IDB-free private-bin staging -> generated-output PR. After that PR merges, [[promote-release-after-output-merge]] verifies the staged inventory and transactionally replaces accepted `PERSISTED_WORKSPACE/bin/<GAMEVER>`.
## Dependencies
- [[warmup_idb]] and its published `PERSISTED_WORKSPACE/idb-cache/<GAMEVER>` generation.
- `configs/<GAMEVER>.yaml`, `gamedata-generators/`, accepted persisted YAML state, and protected Windows runner.
- [[promote-release-after-output-merge]].
## Notes
- The build no longer runs best-effort warmup inline and never consumes `.i64` from accepted `PERSISTED_WORKSPACE/bin/<GAMEVER>`.
- `stage-build` excludes `.i64`, legacy `.idb`, and all known IDA side files before building the private inventory. Promotion therefore removes any historical accepted IDB copies instead of duplicating the warm-cache payload.
- Output PR paths remain exactly the requested snapshot, `gamedata/<GAMEVER>/**`, and release manifest.
## Callers
- `repository_dispatch.types: [build-on-self-runner]`.
- Machine-oriented `workflow_dispatch`.

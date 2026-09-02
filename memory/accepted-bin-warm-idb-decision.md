---
title: accepted-bin-warm-idb-decision
type: decision
permalink: cs2-vibesignatures/memory/accepted-bin-warm-idb-decision
tags:
- release
- ci-cd
- storage
- decision
---

# Keep Accepted Bin: warm IDB cache vs accepted bin (2026-08-22)

## Status
Updated for the source-owned artifacts cutover. Historical release-staging/promote-bin conclusions are superseded; the retained decision is only that a binary-only accepted cache remains useful.

## Decision
Keep `PERSISTED_WORKSPACE/bin/<GAMEVER>` as a disposable, exact configured-binary cache distinct from warm IDB generations. It may contain only configured binaries and explicitly allowlisted side files; per-symbol YAML, snapshots, gamedata, manifests, IDA databases, and BinSync working state are forbidden. The cache is never source or Release truth.
## Context / trigger
PR and Release workers need exact binaries while warm IDB generations remain prunable performance state. Source-owned per-symbol history now lives in Git under `bin_artifacts`, so accepted-bin no longer serves an oldgamever YAML baseline or promotion target.
## Analysis (useful conclusions)
- Warm generations atomically bind configured binary bytes, IDA runtime, and neutral `.i64` payload; they are immutable and prunable.
- Accepted-bin keeps reusable binary bytes across runs/versions and reduces depot/Release downloads, but it is fully recoverable.
- `sync_accepted_bin` compares SHA-256 inventories and enforces the configured positive allowlist; same path/size is not identity.
- Release full rebuild reads expected per-symbol artifacts from Git, not accepted-bin. Release-local rename state is never written back to warm generations.
- The removed `release-staging`, generated-output PR, and `promote_bin` mechanisms are historical only.
### Where the current-version binaries live (4 copies)
Historical: the pre-cutover design counted warm generation, accepted bin, staged bin, and Release gamebin copies. Active releases have no durable release-staging copy.
### warm IDB cache vs accepted bin
Current distinction: warm IDB is an immutable binary+neutral-IDB generation; accepted-bin is an exact configured-binary-only cache. Both are recoverable and neither contains source-owned YAML.
### Stripping staged gamebin (feasible but low value)
Superseded: active Release candidates are transient Actions Artifacts after fresh rebuild/hosted verification; there is no staged-bin promotion transaction.
### Moving `promote` to GitHub-hosted runners (boundary)
Superseded: hosted verifier and protected publishers now consume exact candidates. The self-hosted builder has no publication credential; accepted-bin maintenance remains local cache work, not a release promotion gate.
### Why state lives on the local runner (for future reference)
Current persisted state is limited to recoverable binary/IDB caches and cleanup receipts. Durable publication state lives in Git source truth, remote BinSync refs, and immutable GitHub Releases.
## Constraints
- Binaries are immutable per GAMEVER and all cache reuse is exact-hash verified.
- accepted-bin cleanup is recoverable and receipt-backed; legacy YAML is ignored before cleanup and rejected afterward.
- The self-hosted worker does not gain publication authority merely because it can access persisted caches.
## Revisit triggers

Disk pressure from idb-cache, or changed bandwidth/storage costs, may reopen the de-dup decision.

## See also
[[build-on-self-runner]], [[warmup_idb]], [[project_overview]], [[release-staging]] (historical).
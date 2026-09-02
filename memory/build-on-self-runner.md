---
title: build-on-self-runner
type: note
permalink: cs2-vibesignatures/build-on-self-runner
---

# Build On Self Runner

## Overview
`.github/workflows/build-on-self-runner.yml` is the credential-minimized Release producer for an immutable default-branch source SHA. It performs a fresh full `-force_all -rename` rebuild against tracked `bin_artifacts`, derives release-local assets and a credential-free BinSync candidate, then hands exact bytes to hosted verification and protected publishers.
## Responsibilities
- Preflight an allowlisted repository/source SHA, complete GAMEVER artifact inventory, binary/download/SDK identity, and immutable version transaction.
- Restore binary-only accepted state and the exact warm IDB generation.
- Rebuild the complete GAMEVER in an empty checkout-external artifact root and compare every byte with Git truth.
- Apply rename/comment side effects only to release-local IDB/BinSync state; prove no remote ref changed during build.
- Generate snapshot, metadata, gamedata, C++ evidence, archives, checksums, Release manifest, and canonical BinSync bundles.
- Upload stable run-id candidate artifacts for hosted verification; hold no source/BinSync/Release write credential.
## Involved Files & Symbols
- `.github/workflows/build-on-self-runner.yml` - preflight, warmup, build, verify, and publisher DAG.
- `release_source_preflight.py`, `release_artifact_rebuild.py` - immutable source and fresh rebuild contracts.
- `release_bundle.py` - exact archive/manifest construction and hosted verification.
- `binsync_candidate.py`, `binsync_verify.py`, `binsync_publish.py` - credential-free candidate, hosted proof, protected fast-forward publication.
- `release_publish.py`, `.github/workflows/publish-release-bundle.yml` - immutable tag/assets publisher.
- `pages_release_input.py` - published Release to Pages handoff.
## Architecture
```text
immutable main SHA preflight
  -> exact warm IDB restore
  -> empty-root full -force_all -rename rebuild
  -> actual artifacts == Git blobs
  -> release-local snapshot/gamedata/C++/archives + BinSync bundles
  -> hosted verification
  -> protected fast-forward BinSync publish
  -> protected immutable Release publish
  -> Pages from published assets
```
## Dependencies
- Complete tracked `bin_artifacts/<GAMEVER>` and configured binary/download/SDK identity.
- Binary-only accepted cache and immutable warm IDB generation.
- Separate hosted verifier, `binsync-release` environment, `release` environment, and external repository rulesets.
## Notes
- No generated-output branch/PR, release-staging correctness source, or accepted-bin YAML promotion remains.
- Stable transaction identity is `run_id`; rerun attempt is transport metadata and must not change candidate identity.
- Self-hosted build has read-only source access and no publication credentials. BinSync and Release publishers are isolated.
- Same-version published assets are exact-idempotent only; different content must use a new version.
## Callers
- Provenance-verified release dispatch for an immutable default-branch source SHA.
- Explicit authorized recovery reruns using the same stable transaction identity.
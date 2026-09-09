---
title: build-on-self-runner
type: note
permalink: cs2-vibesignatures/build-on-self-runner
---

# Build On Self Runner

## Overview
`.github/workflows/build-on-self-runner.yml` is the credential-minimized Release producer for an immutable default-branch source SHA. It performs a fresh full `-force_all -rename` rebuild against tracked `bin_artifacts`, derives release-local assets and a credential-free BinSync candidate, then hands exact bytes to hosted verification and protected publishers.
## Responsibilities
- Preflight an allowlisted repository/source SHA, complete GAMEVER artifact inventory, binary/download identity, and the
  exact `hl2sdk_cs2` gitlink stored in that source commit.
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
- Complete tracked `bin_artifacts/<GAMEVER>`, source-owned `binary_locks/<GAMEVER>.json`, and exact SDK gitlink identity.
- Binary-only accepted cache and immutable warm IDB generation.
- Separate hosted verifier, `binsync-release` environment, `release` environment, and external repository rulesets.
## Notes
- No generated-output branch/PR, release-staging correctness source, or accepted-bin YAML promotion remains.
- Stable transaction identity is `run_id`; rerun attempt is transport metadata and must not change candidate identity.
- Self-hosted build has read-only source access and no publication credentials. BinSync and Release publishers are isolated.
- Release preflight, warmup, and required accepted-bin restore must agree on the same [[binary_lock]] digest. Release preparation
  checks local binary bytes before analysis and again afterward; hosted Release/BinSync verifiers reload the lock from the
  immutable source SHA.
- C++ validation and the gamedata archive always use the source commit's SDK gitlink; mutable `cs2-<GAMEVER>` branches are
  never runtime Release inputs.
- Same-version published assets are exact-idempotent only; different content must use a new version.
- Preflight parses its JSON with `ConvertFrom-Json -DateKind String`. PowerShell 7 (Json.NET) otherwise coerces the
  ISO-8601 `source_publish_time` into `[datetime]`, so both the format check and the `GITHUB_OUTPUT` value fail.
- The self-hosted Windows runner defines a machine-level `url.http://HZVM:8080/.insteadOf=https://github.com/` git
  proxy and hands out 8.3 short-name temp roots, so tests and path guards must not pin a proxy host or compare a raw
  spelling against a resolved path.
- `source_artifact_mode=tracked` (only from the manual, protected `rebuild-free-release.yml`) skips the fresh
  `-force_all -rename` rebuild and binds the tracked `bin_artifacts/<GAMEVER>` instead: it proves the published
  artifacts equal that source SHA's tracked truth, but never proves they can be rebuilt. The automatic
  `tag-bump-after-merge` path never sets the input, so it always rebuilds.
- Missing per-module BinSync remotes for an unpublished GAMEVER are provisioned by
  `init_gamebin.py ensure-binsync-remotes <gamever> --user release-automation`, which reads the authoritative md5 from
  tracked `binary_locks/<GAMEVER>.json` and needs no binary download; it runs on `ubuntu-latest` in the protected
  `binsync-remotes` environment to bypass the HZVM proxy.
## Callers
- Provenance-verified release dispatch for an immutable default-branch source SHA.
- Explicit authorized recovery reruns using the same stable transaction identity.

---
title: binary_lock
type: note
permalink: cs2-vibesignatures/binary-lock
tags:
- release
- binary-identity
- source-owned
---

# binary_lock

## Overview
`binary_lock.py` defines the canonical source-owned identity for every configured GAMEVER binary. Each `binary_locks/<GAMEVER>.json` binds the config target set and complete hashes to the exact `download.yaml` depot manifests and optional branch.

## Responsibilities
- Validate canonical JSON, exact schema, safe paths, target coverage, hash shapes, and download identity.
- Load locks from immutable Git blobs at a bound source SHA.
- Measure configured local binaries and reject any size/hash drift from the source lock.
- Gate accepted-bin sync/restore and warm-IDB publication; propagate the digest to PR and Release consumers.
- Supply the complete nested binary inventory and lock digest to Release candidates.
- Support the one-shot historical snapshot migration and deterministic audit check.

## Involved Files & Symbols
- `binary_lock.py` - `build_binary_lock`, `load_binary_lock_from_revision`, `verify_binary_root`.
- `binary_locks/<GAMEVER>.json` - source-owned per-version locks.
- `source_binary_lock_bootstrap.py` - historical snapshot migration/check tool.
- `release_artifact_rebuild.py` - pre/post-analysis local binary verification.
- `release_bundle.py` - hosted source-lock recomputation and candidate inventory comparison.

## Architecture
```text
source SHA: config + download.yaml + binary lock
  -> self-hosted local binary exact comparison
  -> fresh analysis and candidate construction
  -> candidate binary_lock_sha256 + full inventory
  -> hosted lock reload from immutable Git blob
  -> exact inventory comparison
  -> archive publication gates
```

## Dependencies
- `configs/<GAMEVER>.yaml` binary target contract and `download.yaml` depot selection.
- `binary_hashing.hash_file` and canonical JSON helpers.
- Immutable Git object access for hosted verification.

## Notes
- The initial 16 locks came from historical snapshot blobs at `1e69d6b963ce6e2e4b9277910de4071343901486`; 256/256 current configured binaries matched.
- GAMEVERs 14167-14172 are historical snapshot backfills, not external cryptographic proof of Steam provenance.
- New GAMEVER enrollment uses the bump producer's fresh checkout-external depot/bin root and atomically publishes the lock
  with `download.yaml` plus the seeded config before accepted-bin or warm-IDB cache reuse.
- `bin/`, accepted-bin, and warm IDB remain disposable caches and never define expected binary identity.
- `init_gamebin.py prepare` performs a final lock comparison after local, Release-archive, or depot initialization; direct
  callers therefore cannot treat a complete but wrong binary tree as ready.

## Callers
- Release rebuild preparation and verification.
- Accepted-bin restore/sync, warm-IDB production, trusted PR workers, and Release source preflight.
- Release bundle build, hosted verification, and Pages schema consumers.

## Published gamebin can be incomplete for the current config

- Trigger: 14192 warmup initializes 30/32 configured entries from a verified 20-file Release archive, but `worldrenderer.dll` and `libworldrenderer.so` remain missing.
- Root cause: a Release manifest describes its original published inventory; later source configs and binary locks can require additional modules. Archive integrity does not establish current config coverage.
- Correct approach: after merging a verified Release, check current config coverage and supplement missing files through the configured exact-manifest Steam depot path. Preserve existing binaries and keep the final source binary lock comparison. Invalid manifests/archives must still fail directly.
- Verification: regression coverage for complete/partial Releases, failed supplementation and invalid archives; verify the real published archive plus source-locked supplemental files against the current full binary lock.
- Scope: `init_gamebin.py prepare`, including CI warmup and other callers using published gamebin fallback.

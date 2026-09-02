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
- Supply the complete nested binary inventory and lock digest to Release and BinSync candidates.
- Support the one-shot historical snapshot migration and deterministic audit check.

## Involved Files & Symbols
- `binary_lock.py` - `build_binary_lock`, `load_binary_lock_from_revision`, `verify_binary_root`.
- `binary_locks/<GAMEVER>.json` - source-owned per-version locks.
- `source_binary_lock_bootstrap.py` - historical snapshot migration/check tool.
- `release_artifact_rebuild.py` - pre/post-analysis local binary verification.
- `release_bundle.py`, `binsync_candidate.py` - hosted source-lock recomputation and candidate inventory comparison.

## Architecture
```text
source SHA: config + download.yaml + binary lock
  -> self-hosted local binary exact comparison
  -> fresh analysis and candidate construction
  -> candidate binary_lock_sha256 + full inventory
  -> hosted lock reload from immutable Git blob
  -> exact inventory comparison
  -> archive/BinSync publication gates
```

## Dependencies
- `configs/<GAMEVER>.yaml` binary target contract and `download.yaml` depot selection.
- `binary_hashing.hash_file` and canonical JSON helpers.
- Immutable Git object access for hosted verification.

## Notes
- The initial 16 locks came from historical snapshot blobs at `1e69d6b963ce6e2e4b9277910de4071343901486`; 256/256 current configured binaries matched.
- GAMEVERs 14167-14172 are historical snapshot backfills, not external cryptographic proof of Steam provenance.
- New GAMEVER enrollment must use a fresh checkout-external depot download before accepted-bin or warm-IDB cache reuse.
- `bin/`, accepted-bin, and warm IDB remain disposable caches and never define expected binary identity.

## Callers
- Release rebuild preparation and verification.
- BinSync candidate build and hosted verification.
- Release bundle build, hosted verification, and Pages schema consumers.

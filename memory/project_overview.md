---
title: project_overview
type: note
permalink: cs2-vibesignatures/project-overview
---

# Project Overview

## Overview
CS2_VibeSignatures automates CS2 signature/offset analysis with `bin_artifacts/<GAMEVER>/<module>/*.yaml` as the only Git-tracked per-symbol truth. Snapshots, metadata, gamedata, archives, checksums, and manifests are immutable Release-derived assets.
## Responsibilities
- Download/copy disposable binaries and run deterministic, LLM-assisted, and Agent-assisted analysis.
- Finalize canonical per-symbol bytes and validate the formal producer-group inventory.
- Rebuild affected/downstream closure for source PRs against exact prospective merge trees.
- Run fresh full Release rebuilds, C++ validation, hosted candidate verification, protected BinSync publication, immutable Release publication, and Pages deployment.
## Involved Files & Symbols
- `ida_analyze_bin.py`, `ida_analyze_util.py` - dual-root analysis and central artifact finalization.
- `bin_artifact_contract.py` - tracked inventory, ownership, path, and canonical-byte contract.
- `trusted_pr_context.py`, `trusted_artifact_pr.py` - base-owned context and prospective-tree plan.
- `.github/workflows/source-artifact-required.yml`, `.github/workflows/pr-self-runner.yml` - trusted PR/merge-queue validation.
- `.github/workflows/build-on-self-runner.yml`, `release_bundle.py`, `binsync_candidate.py` - Release candidates.
- `binsync_publish.py`, `release_publish.py`, `pages_release_input.py` - protected publication and Pages input.
## Architecture
```text
source/config/reference + computed bin_artifacts closure
  -> trusted prospective-tree plan
  -> checkout-external affected-group rebuild
  -> exact Git blob comparison
  -> Merge Queue
  -> fresh full Release rebuild + local-only BinSync prepare
  -> hosted verification
  -> protected BinSync and immutable Release publishers
  -> Pages from published Release
```
## Dependencies
- uv, IDA/idalib, ida-pro-mcp, Clang/LLVM, DepotDownloader, GitHub Actions.
- `configs/`, `download.yaml`, `bin_artifacts/`, `gamedata-generators/`, `hl2sdk_cs2`.
- Protected Merge Queue/required-workflow trust root and separate bootstrap/BinSync/Release environments.
## Notes
- `bin/`, accepted-bin, and warm IDB are disposable binary/cache layers and must contain no artifact truth.
- PRs never track `gamesymbols/`, `gamedata/`, or `release-manifests/`.
- New GAMEVER config/download identity and full artifact inventory enter one PR atomically; an artifact-bearing bootstrap head must pass normal exact-byte validation.
- Release never repairs or writes Git source truth and same-version published content is immutable.
## Callers
- Repository workflows, project skills, local analysis commands, Release tooling, and Pages deployment.
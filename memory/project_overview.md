---
title: project_overview
type: note
permalink: cs2-vibesignatures/project-overview
---

# Project Overview

## Overview
CS2_VibeSignatures automates CS2 signature/offset analysis, immutable symbol snapshots, versioned downstream gamedata, C++ ABI validation, and review-gated Release publication.

## Responsibilities
- Download/copy binaries and run deterministic/LLM/skill-assisted analysis.
- Build and validate immutable `gamesymbols/<GAMEVER>.yaml`.
- Generate exact `gamedata/<GAMEVER>/` payloads.
- Validate C++ layouts against the same candidate.
- Promote private bin and publish verified Release assets only after output merge.

## Involved Files & Symbols
- `ida_analyze_bin.py` - analyzer orchestration.
- `gamesymbol_candidate.py` - symbol candidate lifecycle.
- `gamedata_candidate.py`, `gamedata_contract.py`, `update_gamedata.py` - gamedata lifecycle.
- `run_cpp_tests.py` - C++ gate.
- `release_workflow.py`, `release_workflow_lib/` - release transactions.

## Architecture
```text
bin analysis -> immutable symbol candidate -> isolated gamedata candidate
 -> C++ validation -> tracked output PR -> merge-time bin/tag/Release promotion
 -> durable completed-stage cleanup
```

## Dependencies
- uv, IDA/idalib, ida-pro-mcp, Clang/LLVM, DepotDownloader.
- `configs/`, `bin/`, `gamesymbols/`, `gamedata-generators/`, `gamedata/`.

## Notes
- `bin/` is mutable/private state after candidate creation.
- Canonical tracked outputs are `gamesymbols/<GAMEVER>.yaml` and `gamedata/<GAMEVER>/`.
- Historical versions coexist without a global latest-only tree.

## Callers
- Repository workflows, project skills, and local maintenance commands.

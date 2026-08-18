---
title: build-on-self-runner
type: note
permalink: cs2-vibesignatures/build-on-self-runner
---

# Build On Self Runner

## Overview
`.github/workflows/build-on-self-runner.yml` builds one immutable symbol candidate and one isolated versioned gamedata candidate, validates both before review, and stops after creating the generated-output PR. PR merge remains the only promotion gate.

## Responsibilities
- Resolve exact `GAMEVER`, `SOURCE_SHA`, mode, and legacy-bootstrap policy before using the self-hosted runner.
- Restore/invalidate analyzer state, run normal producer scheduling, and build one immutable symbol candidate.
- Generate strict gamedata below `RUNNER_TEMP`, guard it, then run C++ tests against the unchanged symbol candidate.
- Publish only `gamesymbols/<GAMEVER>.yaml` and `gamedata/<GAMEVER>/`.
- Stage private bin plus transaction metadata, write release manifest schema 4, and create an immutable output PR.

## Involved Files & Symbols
- `.github/workflows/build-on-self-runner.yml` - release build and output-PR creation.
- `gamesymbol_candidate.py` - symbol candidate lifecycle.
- `gamedata_candidate.py` - versioned gamedata candidate lifecycle.
- `release_workflow_lib/staging.py` - `stage_build`, `finalize_stage`, `write_pr_index`.
- `release_workflow_lib/manifests.py` - schema and tracked-output verification.

## Architecture
```text
SOURCE_SHA -> analyze bin -> symbol candidate -> isolated gamedata candidate
           -> gamedata + C++ validation -> publish tracked outputs
           -> private bin staging -> generated-output PR
```

## Dependencies
- `configs/<GAMEVER>.yaml`, `gamedata-generators/`, persisted depot/bin, protected Windows runner.
- [[promote-release-after-output-merge]].

## Notes
- Output PR paths are exactly the requested snapshot, `gamedata/<GAMEVER>/**`, and release manifest.
- Historical republish never changes another version directory.
- Private staging contains no gamedata.

## Callers
- `repository_dispatch.types: [build-on-self-runner]`.
- Machine-oriented `workflow_dispatch`.

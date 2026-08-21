---
title: post_change_candidate_lifecycle
type: note
permalink: cs2-vibesignatures/post-change-candidate-lifecycle
---

# Workflow-Owned Post-Change Candidate Lifecycle

## Overview
`/create-pr` classifies staged or committed changes and delivers source changes only. When
`.claude/skills/create-pr/scripts/classify_delivery.py` returns `LIFECYCLE=1`, the PR workflow owns candidate
preparation, gamedata generation, and C++ validation. Local delivery never adds `gamesymbols/<GAMEVER>.yaml` or
`gamedata/<GAMEVER>/`; those tracked outputs advance only at release time.

## Responsibilities
- `/create-pr`: preserve the authorized source change set, run the classifier, commit/push the source branch, and
  truthfully state that lifecycle gates are delegated to CI.
- `.github/workflows/pr-self-runner.yml` full path: normalize immutable PR metadata, restore the warm IDB generation,
  analyze the merge ref, build one symbol candidate and matching gamedata candidate, run C++ validation, and stage
  analyzed YAML for merge promotion.
- `.github/workflows/build-on-self-runner.yml` release pipeline: the sole publisher of validated snapshot and gamedata.
- Stable `pr-validate` terminal job: require the full path to succeed so branch protection keeps one check name.

## Involved Files & Symbols
- `.claude/skills/create-pr/SKILL.md` - source-only PR delivery contract.
- `.claude/skills/create-pr/scripts/classify_delivery.py` - mechanical lifecycle classification.
- `.github/workflows/pr-self-runner.yml` - full validation, staging, and terminal jobs.
- `.github/workflows/build-on-self-runner.yml` - release-time snapshot/gamedata publication.
- `gamesymbol_candidate.py` - immutable snapshot build, guard, and mark commands.
- `gamedata_candidate.py` - isolated gamedata build and guard commands.
- `run_cpp_tests.py` - C++ ABI validation against the exact symbol candidate.

## Architecture
```text
source changes -> create-pr -> classifier -> source commit -> PR head H1
  -> full pr-self-runner on immutable merge ref (H1 + B1)
    -> analysis -> symbol candidate -> gamedata candidate -> C++ gate
    -> stage analyzed YAML
    -> stable pr-validate success
  -> (merge) -> finalize-pr-workspace promotes staged YAML into persisted bin
  -> (release) -> build-on-self-runner publishes snapshot + gamedata
```

## Dependencies
- Same-repository PR head, immutable merge ref, warm IDB cache, self-hosted Windows full-validation runner.
- `contents: read` only on the PR workflow; publication runs in the release pipeline.
- Candidate/session state below runner temp.
- `PERSISTED_WORKSPACE/pr-yaml-staging/<PR>` for merge-time analyzed-YAML promotion.

## Notes
- Snapshot/gamedata publication was removed from the PR workflow (#803); `gamesymbols/<GAMEVER>.yaml` on main now
  advances only at release time.
- `LIFECYCLE=0` remains a plain PR path and never claims candidate/C++ work.
- `pr_published_recheck.py` is orphaned (no caller after #803).

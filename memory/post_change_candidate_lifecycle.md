---
title: post_change_candidate_lifecycle
type: note
permalink: cs2-vibesignatures/post-change-candidate-lifecycle
---

# Workflow-Owned Post-Change Candidate Lifecycle

## Overview
`/create-pr` classifies staged or committed changes and delivers source changes only. When
`.claude/skills/create-pr/scripts/classify_delivery.py` returns `LIFECYCLE=1`, the PR workflow owns candidate
preparation, gamedata generation, C++ validation, publication, and the latest-head required check. Local delivery never
adds `gamesymbols/<GAMEVER>.yaml` or `gamedata/<GAMEVER>/`.

## Responsibilities
- `/create-pr`: preserve the authorized source change set, run the classifier, commit/push the source branch, and
  truthfully state that lifecycle gates are delegated to CI.
- `.github/workflows/pr-self-runner.yml` full path: normalize immutable PR metadata, restore the warm IDB generation,
  analyze the merge ref, build one symbol candidate and matching gamedata candidate, run C++ validation, stage analyzed
  YAML for merge promotion, then publish the validated bytes onto the exact PR head.
- Publisher: restrict changes to `gamesymbols/<GAMEVER>.yaml` and `gamedata/<GAMEVER>/`, create one
  `github-actions[bot]` commit with head/base/digest trailers, recheck the remote head, push without force, and
  explicitly dispatch `published-recheck`.
- Published recheck: on Ubuntu, verify trusted dispatch identity, live same-repository PR state, commit parent/base,
  canonical provenance message, allowed paths, snapshot SHA-256, and gamedata manifest SHA-256.
- Stable `pr-validate` terminal job: require exactly one successful path (`full` or `published-recheck`) so branch
  protection keeps one check name across both phases.

## Involved Files & Symbols
- `.claude/skills/create-pr/SKILL.md` - source-only PR delivery contract.
- `.claude/skills/create-pr/scripts/classify_delivery.py` - mechanical lifecycle classification.
- `.github/workflows/pr-self-runner.yml` - full validation, publication, recheck, and terminal jobs.
- `pr_published_recheck.py` - dispatch/commit/path/digest verification and publication worktree guard.
- `gamesymbol_candidate.py` - immutable snapshot build, guard, mark, and publish commands.
- `gamedata_candidate.py` - isolated gamedata build, guard, and publish commands.
- `run_cpp_tests.py` - C++ ABI validation against the exact symbol candidate.

## Architecture
```text
source changes -> create-pr -> classifier -> source commit -> PR head H1
  -> full pr-self-runner on immutable merge ref (H1 + B1)
    -> analysis -> symbol candidate -> gamedata candidate -> C++ gate
    -> stage analyzed YAML -> checkout H1 -> publish exact outputs
    -> bot commit H2(parent=H1, provenance=B1+digests) -> normal push
    -> explicit workflow_dispatch on H2
      -> trusted lightweight provenance/path/digest recheck
      -> stable pr-validate success on latest head
```

If the base advances between full validation and recheck, provenance remains valid but cannot be reused. Preflight
fetches the current merge ref and routes the dispatch run back through the full path. If the PR head advances, the old
publication is rejected; no force-push is allowed.

## Dependencies
- Same-repository PR head, immutable merge ref, warm IDB cache, self-hosted Windows full-validation runner.
- `GITHUB_TOKEN` with job-scoped `contents: write` and `actions: write` only on the full publisher job.
- Candidate/session state below runner temp so validated bytes survive checkout from merge ref to PR head.
- `PERSISTED_WORKSPACE/pr-yaml-staging/<PR>` for merge-time analyzed-YAML promotion.

## Notes
- A bot push made with `GITHUB_TOKEN` does not create a recursive `pull_request.synchronize` run; explicit dispatch is
  required to attach the stable check to H2.
- Re-running a publisher after H2 already exists verifies and redispatches that exact bot commit instead of creating an
  equivalent H3.
- Snapshot and gamedata publication are paired. A no-op is allowed only after both tracked output trees match the
  validated candidate digests.
- `LIFECYCLE=0` remains a plain PR path and never claims candidate/C++/publication work.

---
title: post_change_candidate_lifecycle
type: note
permalink: cs2-vibesignatures/post-change-candidate-lifecycle
---

# Post-Change Candidate Lifecycle

## Overview
`/create-pr` owns delivery from an already-staged change. It invokes three ordered skills to prepare, validate, and
publish one immutable symbol candidate plus its matching gamedata candidate, then commits the authorized staged
paths and validated current-version outputs, pushes a `dev*` branch, and opens the PR. Candidate validation never
reads directly from `bin` or falls back to a tracked head snapshot.

## Responsibilities
- `/create-pr`: treat the initial staged diff as the authorized change set, orchestrate the three candidate skills,
  stage only formatter refreshes plus current-version publication outputs, commit, push, and create the PR.
- `/prepare-post-change-candidate`: resolve one `GAMEVER`, format tracked files, build and guard isolated symbol and
  gamedata candidates, mark the gamedata step, and return candidate/session paths plus candidate SHA-256.
- `/post-change-validation`: guard the exact symbol candidate, run real C++ tests against its bytes, reject skipped or
  non-runnable validation, and mark `cpp_tests` only after success.
- `/publish-post-change-candidate`: re-guard the same symbol and gamedata sessions, require validated candidate state,
  publish to `gamesymbols/<GAMEVER>.yaml` and `gamedata/<GAMEVER>`, and verify the published snapshot SHA-256.

## Involved Files & Symbols
- `.claude/skills/create-pr/SKILL.md` - staged-change delivery and PR orchestration contract.
- `.claude/skills/prepare-post-change-candidate/SKILL.md` - preparation contract.
- `.claude/skills/post-change-validation/SKILL.md` - C++ validation contract.
- `.claude/skills/publish-post-change-candidate/SKILL.md` - publication contract.
- `gamesymbol_candidate.py` - `build`, `guard`, `mark`, and `publish` commands.
- `gamedata_candidate.py` - `build`, `guard`, and `publish` commands.
- `gamesymbol_snapshot_lib/candidate.py` and `candidate_session.py` - immutable candidate/session state machine.

## Architecture
```text
explicitly staged task changes
  --> create-pr
    --> configs/<GAMEVER>.yaml + bin/<GAMEVER>/
      --> prepare-post-change-candidate
        --> <GAMEVER>.yaml + candidate session
        --> gamedata candidate + gamedata session
      --> post-change-validation
        --> candidate session marked cpp_tests/validated
      --> publish-post-change-candidate
        --> gamesymbols/<GAMEVER>.yaml
        --> gamedata/<GAMEVER>
    --> refresh authorized index --> commit --> push dev* --> PR against main
```

## Dependencies
- Production authoring skills run their domain tests, explicitly stage task files, and delegate delivery to
  `/create-pr`; they do not call the three candidate skills or commit directly.
- Each later skill must receive the exact paths returned by `/prepare-post-change-candidate`.
- Publication requires explicit `/post-change-validation` success for the same game version, candidate, and session.
- `bin/<GAMEVER>/` must already contain all required analyzer outputs; these skills do not run IDA preprocessors.

## Notes
- Preparation may format tracked files but only writes candidate data under a fresh temporary root.
- Validation may advance the untracked candidate session but does not edit tracked files or candidate bytes.
- Publication never rebuilds or reserializes candidate bytes after validation begins.
- Any failed, skipped, or non-runnable gate stops `/create-pr` before commit, push, and PR creation.

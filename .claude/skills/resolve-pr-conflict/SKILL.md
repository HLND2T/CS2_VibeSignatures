---
name: resolve-pr-conflict
description: |
  Resolve an open same-repository GitHub PR conflict in CS2_VibeSignatures by merging the PR base branch into its
  dev branch, resolving config and generated gamesymbol snapshot conflicts, migrating non-latest gamever config
  changes into the latest gamever and reverting stale snapshot, gamedata, and release-manifest changes, running a
  read-only review audit (defined in .claude/skills/resolve-pr-conflict/references/review-pr.md)
  right after conflict resolution to catch design defects early, creating a source-only merge commit, and pushing
  without force so pr-self-runner CI can validate the resulting snapshot/gamedata candidates. Use when a PR is
  CONFLICTING/DIRTY or needs its base
  branch synchronized, especially when configs/GAMEVER.yaml or gamesymbols/GAMEVER.yaml changed. Stop after push and
  check-status reporting; never merge or auto-merge the PR.
disable-model-invocation: true
---

# Resolve PR Conflict

Resolve one PR through a validated, pushed merge commit. Preserve both histories and stop before PR merge.

## Inputs and Scope

- `pr` — PR number or URL. If omitted, resolve the open PR associated with the current branch.
- `gamever` — optional. Otherwise infer exactly one version from the PR/config/snapshot conflict paths.
- `remote` — default `origin`.

Support only a same-repository PR whose head is a non-`main` dev branch writable through `remote`. Stop for a fork PR,
detached head, closed PR, missing remote, or multiple affected game versions. Do not guess a push destination or combine
multiple snapshot publications in one invocation.

## Hard Safety Rules

- Run from the repository root and require a clean tracked worktree and index before starting.
- Never rebase, amend, force-push, reset, discard unrelated changes, delete branches, or commit directly to `main`.
- Merge in exactly this direction: check out the PR head branch, then merge `remote/<base>` into it with `--no-ff`.
- Never hand-edit generated snapshot digest, file count, publish time, or candidate bytes.
- Never use a tracked snapshot as downstream validation input and never publish directly from `bin`.
- Stop on an ambiguous non-generated conflict and ask the user; do not choose a side without semantic evidence.
- Never run candidate preparation, C++ validation, or snapshot/gamedata publication locally. Candidate/C++ validation
  runs in `.github/workflows/pr-self-runner.yml` after push; snapshot/gamedata publication happens only in the release
  pipeline, never on a skill PR's head.
- After push, report PR checks once. Do not invoke `gh pr merge`, enable auto-merge, call a merge API, switch to `main`,
  or clean up branches. PR merge is a separate explicitly authorized task.

## Step 1 — Inspect and Capture the PR

Require successful authentication and capture the immutable starting state:

```bash
git status --short --branch
git remote
gh auth status
gh pr view <PR> --json number,url,state,isDraft,baseRefName,headRefName,headRefOid,headRepositoryOwner,mergeable,mergeStateStatus,statusCheckRollup
git fetch <REMOTE> <BASE_BRANCH> <HEAD_BRANCH> --prune
git rev-parse <REMOTE>/<BASE_BRANCH>
git rev-parse <REMOTE>/<HEAD_BRANCH>
git diff --name-status <REMOTE>/<BASE_BRANCH>...<REMOTE>/<HEAD_BRANCH>
```

Save `PR_URL`, `BASE_BRANCH`, `HEAD_BRANCH`, `PR_HEAD_SHA`, `BASE_HEAD_SHA`, and `ORIGINAL_PR_PATHS`. After fetch, require
the PR API head SHA to equal `<REMOTE>/<HEAD_BRANCH>`. Stop if the PR changed during inspection.

Allow draft PRs, but require `state=OPEN`. If the PR is already mergeable and the user did not explicitly request a
base sync, report that no conflict resolution is needed and stop without mutation.

## Step 2 — Check Out the PR Branch

If no local head branch exists, create it tracking the remote branch. If it exists, require it to be clean and update it
only by fast-forward:

```bash
git switch --track -c <HEAD_BRANCH> <REMOTE>/<HEAD_BRANCH>
# or, for an existing local branch:
git switch <HEAD_BRANCH>
git pull --ff-only <REMOTE> <HEAD_BRANCH>
```

Require `HEAD == PR_HEAD_SHA` before merging.

## Step 3 — Merge the Base and Resolve Conflicts

```bash
git merge --no-ff <REMOTE>/<BASE_BRANCH>
git status --short
git diff --name-only --diff-filter=U
```

An exit code `1` is expected only when Git reports merge conflicts. Any other merge failure is a hard stop.

Resolve each path as follows:

- `configs/<GAMEVER>.yaml`: preserve the semantically required entries from both parents, including skill ordering,
  prerequisites, expected inputs/outputs, symbols, and aliases. Avoid duplicate entries. If `<GAMEVER>` is not the latest
  gamever in `download.yaml`, do not resolve forward — migrate its intent into the latest config and revert the whole
  path to base in Step 4 instead.
- `gamesymbols/<GAMEVER>.yaml`: because the enforced direction is PR head <- base, select the base snapshot:

  ```bash
  git checkout --theirs -- "gamesymbols/<GAMEVER>.yaml"
  git add -- "gamesymbols/<GAMEVER>.yaml"
  ```

  The base snapshot is the final value, not a placeholder. Snapshot/gamedata publication is release-pipeline only
  (in-band skill PRs never advance the tracked snapshot), so `pr-self-runner.yml` validates candidates but does not
  commit or replace this file after push.
- Source, tests, or documentation: read the exact conflicting code and resolve semantically. Stop and ask when intent is
  ambiguous.

Stage resolved conflict paths explicitly. Require no unmerged entries and no conflict markers:

```bash
git diff --name-only --diff-filter=U
git diff --check
git status --short
```

Require exactly one `GAMEVER` when config, analysis output, or gamesymbol paths are involved. Confirm
`configs/$GAMEVER.yaml` exists.

## Step 4 — Migrate Non-Latest Config Changes, Revert Stale Gamever Artifacts

The analysis model is single-versioned: producers, expected inputs, symbol definitions, aliases, and generated outputs
belong only in the latest gamever config. The latest gamever is the last `tag:` entry in `download.yaml` (chronological,
matching `init_gamebin.py`'s `LATEST_GAMEVER = versions[-1]`). A change that edits a non-latest gamever config is
misplaced work, not throwaway work: migrate its intent into the latest gamever config, then discard the old path's
change. Generated artifacts for a non-latest gamever (`gamesymbols`, `gamedata`, `release-manifests`) are never
hand-edited or forward-ported; revert them to base unconditionally.

Determine `LATEST_GAMEVER` once and collect every `<GAMEVER>` in the original PR and merged conflict paths that matches
`configs/<GAMEVER>.yaml`, `gamesymbols/<GAMEVER>.yaml`, `gamedata/<GAMEVER>/`, or `release-manifests/<GAMEVER>.json`:

```bash
LATEST_GAMEVER="$(grep -oE 'tag: *"[0-9]+[ab]*"' download.yaml | tail -1 | grep -oE '[0-9]+[ab]*')"
```

For each `<GAMEVER>` that is **not** the latest, handle its paths as follows:

1. `configs/<GAMEVER>.yaml` — **migrate first, then discard.** Read the exact diff against base
   (`git diff <REMOTE>/<BASE_BRANCH> -- "configs/$GV.yaml"`) and port every semantically meaningful change — skill
   ordering, prerequisites, expected inputs/outputs, symbols, aliases, producer entries — into
   `configs/$LATEST_GAMEVER.yaml`. Merge against what already exists there using the same rules as Step 3 config
   resolution (preserve both parents' intent, avoid duplicates). Then revert the old path to base and stage both the
   migrated latest config and the reverted path:

   ```bash
   git checkout <REMOTE>/<BASE_BRANCH> -- "configs/$GV.yaml"
   git add -- "configs/$GV.yaml" "configs/$LATEST_GAMEVER.yaml"
   ```

   Never drop a non-latest config change without first checking whether its intent belongs in the latest config. If the
   diff is version-specific noise with no latest-gamever equivalent, document why before leaving it unmigrated.

2. `gamesymbols/<GAMEVER>.yaml`, `gamedata/<GAMEVER>/`, `release-manifests/<GAMEVER>.json` — **revert only.** Generated
   artifacts; do not forward-port them.

   ```bash
   git checkout <REMOTE>/<BASE_BRANCH> -- \
     "gamesymbols/$GV.yaml" \
     "gamedata/$GV" \
     "release-manifests/$GV.json"
   git add -- "gamesymbols/$GV.yaml" "gamedata/$GV" "release-manifests/$GV.json"
   ```

Treat every migrated and reverted path exactly like a resolved conflict: require no unmerged entries, no conflict
markers, and a clean diff for that path. A non-latest gamever path left in the merged result — a reverted config whose
intent should have been migrated, or a generated artifact that was not reverted — is a defect. If a legitimately
justified historical backport exists, it must be explicitly documented in the PR before it can be preserved.

If the PR itself is about the latest gamever and introduces no non-latest gamever paths, this step is a no-op.

## Step 5 — Review the Resolved PR

Run the read-only review audit of the resolved PR before creating the merge commit. Catch preprocessor design defects
early rather than after push.

Read `.claude/skills/resolve-pr-conflict/references/review-pr.md` and execute its read-only review steps
(Steps 1-4) against the same `<PR>` now that the merge is resolved and stale-gamever cleanup is staged. The audit checks
the PR's config/script/snapshot changes against the base tree, including the stale-gamever gate for
`configs/<GAMEVER>.yaml`.

Treat the audit's findings as part of this skill's outcome, but do **not** begin repair in this invocation: repair of the
existing PR is a separate explicitly authorized task. If the audit finds actionable defects, report them and stop to ask
the user how to deal with each issue — for example whether to fix the existing PR now or abandon this invocation — and do
not continue to the later steps. If it finds none, state that the resolved PR passed review and continue to Step 6.

The review audit is read-only for this step and never modifies, commits, pushes, or merges. If it reports the PR head has
moved since the captured `PR_HEAD_SHA`, present the updated diff and stop without further mutation.

## Step 6 — Review and Create the Merge Commit

Stage only explicit resolved/authorized source paths. Never use `git add .` or `git add -A`, and do not stage locally
generated snapshot/gamedata outputs.

```bash
git add -- <EXPLICIT_RESOLVED_OR_FORMATTED_PATHS>
git diff --cached --check
git diff --name-only --diff-filter=U
git diff --cached --name-status <REMOTE>/<BASE_BRANCH>
git diff --cached --stat <REMOTE>/<BASE_BRANCH>
git diff --cached <REMOTE>/<BASE_BRANCH> -- "configs/$GAMEVER.yaml" "gamesymbols/$GAMEVER.yaml"
```

Require no unstaged tracked changes. Review the final diff relative to the base: it must contain the original PR intent
and conflict resolutions only. Any selected base snapshot is the final value; pr-self-runner validates candidates but
never commits or publishes snapshot/gamedata back to the PR head.

Create one merge commit without amending existing PR commits:

```bash
git commit \
  -m "chore(merge): sync <BASE_BRANCH> into <TOPIC> branch" \
  -m "Co-Authored-By: Codex <codex@openai.com>"
```

Verify the commit has exactly two parents in this order: `PR_HEAD_SHA BASE_HEAD_SHA`. Require a clean worktree after
commit.

## Step 7 — Push Without Force and Stop Before PR Merge

Immediately before push, confirm the remote PR head is still `PR_HEAD_SHA`. If it changed, stop; never overwrite the
other update.

Push using a normal fast-forward update:

```bash
git push <REMOTE> "HEAD:refs/heads/<HEAD_BRANCH>"
```

If push is rejected, fetch and report the divergence. Never retry with force.

After push, query once and report the new PR state:

```bash
gh pr view <PR> --json url,headRefOid,mergeable,mergeStateStatus,statusCheckRollup
gh pr checks <PR>
```

Pending checks are an acceptable endpoint for this skill. If GitHub becomes unreachable after a successful push,
report the pushed branch and commit plus the last known check state; do not infer success and do not attempt PR merge.

Then **STOP**. Never run any of the following in this skill:

```text
gh pr merge
gh pr merge --auto
GitHub REST/GraphQL merge mutation
git push origin --delete <HEAD_BRANCH>
git switch main
```

## Final Report

Report:

- PR URL, base branch, head branch, original PR SHA, base SHA, and pushed merge-commit SHA;
- resolved conflict paths;
- non-latest gamever config changes migrated into the latest gamever config and their source paths reverted to base in
  Step 4, non-latest snapshot/gamedata/release-manifest paths reverted to base, and the verified latest gamever;
- game version when resolved and a statement that PR CI owns candidate/C++ validation while snapshot/gamedata
  publication happens only in the release pipeline;
- pushed remote branch and latest known PR/check state;
- the review audit result (Step 5, read-only per
  `.claude/skills/resolve-pr-conflict/references/review-pr.md`): findings (or "no actionable findings")
  and the consent question if defects were found;
- explicit statement: `PR was not merged by resolve-pr-conflict`.

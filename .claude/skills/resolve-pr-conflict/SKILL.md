---
name: resolve-pr-conflict
description: |
  Resolve an open same-repository GitHub PR conflict in CS2_VibeSignatures by merging the PR base branch into its
  dev branch, resolving config and generated gamesymbol snapshot conflicts, generating missing current-version
  artifacts with ida_analyze_bin.py, running the immutable candidate validation and publication lifecycle, creating a
  merge commit, and pushing without force. Use when a PR is CONFLICTING/DIRTY or needs its base branch synchronized,
  especially when configs/GAMEVER.yaml or gamesymbols/GAMEVER.yaml changed. Stop after push and check-status
  reporting; never merge or auto-merge the PR.
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
- Stop on the first failed/non-runnable official candidate gate. Do not publish, commit, or push after a gate failure.
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
  prerequisites, expected inputs/outputs, symbols, and aliases. Avoid duplicate entries.
- `gamesymbols/<GAMEVER>.yaml`: because the enforced direction is PR head <- base, select the base snapshot only as a
  temporary valid placeholder:

  ```bash
  git checkout --theirs -- "gamesymbols/<GAMEVER>.yaml"
  git add -- "gamesymbols/<GAMEVER>.yaml"
  ```

  This placeholder must be replaced by `/publish-post-change-candidate` before the merge commit. Never commit it as the
  final resolution.
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

## Step 4 — Preflight Required Analysis Artifacts

Before invoking the official candidate skill, build a disposable symbol-only preflight candidate in a unique temporary
directory. Never use this preflight candidate for validation or publication:

```bash
uv run gamesymbol_candidate.py build \
  -gamever "$GAMEVER" \
  -bindir bin \
  -configyaml "configs/$GAMEVER.yaml" \
  -output "$PREFLIGHT_ROOT/$GAMEVER.yaml" \
  -session "$PREFLIGHT_ROOT/$GAMEVER.session.json"
```

If it succeeds, continue to Step 5 and ignore the disposable candidate.

If it reports `Missing required symbol YAML`, use the exact missing list to locate each producer in the merged config.
For every producer:

1. Identify its module, exact skill name, selected platforms, `expected_input`, `prerequisite`, `optional_output`, and
   `skip_if_exists` chain.
2. Run prerequisite producers before consumers. `ida_analyze_bin.py -skill` does **not** automatically run
   prerequisites.
3. Preserve config order for noinline/inlined or other fallback chains.
4. Run only the required module, platforms, and exact skill against the current version:

   ```bash
   uv run python ida_analyze_bin.py \
     -gamever "$GAMEVER" \
     -oldgamever none \
     -configyaml "configs/$GAMEVER.yaml" \
     -bindir bin \
     -modules <MODULE> \
     -platform <COMMA_SEPARATED_PLATFORMS> \
     -skill <EXACT_SKILL_NAME> \
     -debug
   ```

5. Require `Failed: 0`. A configured fallback skipped because all outputs exist is acceptable.
6. Read every generated YAML and require a non-empty, parseable artifact containing the configured desired fields.

Stop for missing producer definitions, absent expected inputs with no in-scope producer, IDA/MCP infrastructure errors,
unavailable required credentials, or ambiguous producer selection. Do not copy artifacts from the tracked snapshot.

After generating artifacts, create a new disposable preflight root and rerun the preflight once. If required YAML is
still missing, stop and report it; do not loop indefinitely.

## Step 5 — Prepare the Official Immutable Candidate

Always invoke `/prepare-post-change-candidate` with the resolved `GAMEVER`. Do not reuse the disposable preflight
candidate.

Retain the returned candidate path, candidate session path, gamedata session path, and candidate SHA-256. If the skill
fails, stop the entire task.

Formatting may change only paths already participating in the merge or original PR, plus current-version publication
paths. Report and stop on any unrelated tracked change.

## Step 6 — Validate the Exact Candidate

Always invoke `/post-change-validation` with the same `GAMEVER`, candidate, and candidate session returned by Step 5.

Require all of the following evidence:

- process exit code `0`;
- `=== running cpp_tests ===` and `=== done ===`;
- runnable tests greater than zero;
- zero compile failures, invalid test items, and layout/vtable/record differences;
- no non-runnable-test warning.

If validation fails or is non-runnable, stop exactly as that skill requires. Do not repair, retry, publish, commit, or
push within this invocation.

## Step 7 — Publish the Validated Candidate

Always invoke `/publish-post-change-candidate` with the same `GAMEVER`, candidate, candidate session, and gamedata
session. Never rebuild or reserialize after validation begins.

Require the SHA-256 of `gamesymbols/$GAMEVER.yaml` to equal the validated candidate SHA-256 byte-for-byte. Publication
may modify only:

- paths already involved in the original PR/merge and changed by formatting;
- `gamesymbols/$GAMEVER.yaml`;
- files under `gamedata/$GAMEVER/`.

Any other tracked change is a hard stop.

## Step 8 — Review and Create the Merge Commit

Stage only explicit resolved/authorized paths and validated publication outputs. Never use `git add .` or
`git add -A`.

```bash
git add -- <EXPLICIT_RESOLVED_OR_FORMATTED_PATHS>
git add -- "gamesymbols/$GAMEVER.yaml" "gamedata/$GAMEVER"
git diff --cached --check
git diff --name-only --diff-filter=U
git diff --cached --name-status <REMOTE>/<BASE_BRANCH>
git diff --cached --stat <REMOTE>/<BASE_BRANCH>
git diff --cached <REMOTE>/<BASE_BRANCH> -- "configs/$GAMEVER.yaml" "gamesymbols/$GAMEVER.yaml"
```

Require no unstaged tracked changes. Review the final diff relative to the base: it must contain the original PR intent
plus validated current-version publication changes only. In particular, confirm the final snapshot includes both the
base branch artifacts and the PR artifacts with a newly generated digest/count/time.

Create one merge commit without amending existing PR commits:

```bash
git commit \
  -m "chore(merge): sync <BASE_BRANCH> into <TOPIC> branch" \
  -m "Co-Authored-By: Codex <codex@openai.com>"
```

Verify the commit has exactly two parents in this order: `PR_HEAD_SHA BASE_HEAD_SHA`. Require a clean worktree after
commit.

## Step 9 — Push Without Force and Stop Before PR Merge

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
- resolved conflict paths and generated artifact paths;
- game version, official candidate SHA-256, runnable-test count, and zero failure counters;
- published snapshot SHA-256 equality and any versioned gamedata changes;
- pushed remote branch and latest known PR/check state;
- explicit statement: `PR was not merged by resolve-pr-conflict`.

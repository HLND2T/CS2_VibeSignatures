---
name: resolve-pr-conflict
description: |
  Resolve an open same-repository GitHub PR conflict by merging its base into the writable dev head, resolving source
  and config intent semantically, rebuilding conflicted source-owned `bin_artifacts` plus downstream closure, running
  the repository review/format/test gates, creating one merge commit, and pushing without force. Stop after reporting
  PR checks; never merge or auto-merge the PR.
disable-model-invocation: true
---

# Resolve PR Conflict

Resolve one PR through a validated, pushed merge commit. `bin_artifacts/<GAMEVER>/` is the only tracked per-symbol
truth; snapshots, gamedata, metadata, and release manifests are Release-derived and must not appear in the result.

## Inputs and scope

- `pr` — PR number or URL. If omitted, resolve the single open PR associated with the current branch.
- `gamever` — optional expected GAMEVER. Infer only when the changed ownership is unambiguous.
- `remote` — default `origin`.

Support only an open same-repository PR whose non-default head branch is writable through `remote`. Stop for a fork,
detached head, missing remote, moving head, or ambiguous affected GAMEVER/producer ownership.

## Hard safety rules

- Start with a clean tracked worktree and index. Preserve unrelated untracked files.
- Never rebase, amend, reset, force-push, delete branches, commit to the default branch, or use `git add .`/`git add -A`.
- Merge only in this direction: PR head branch <- `remote/<base>` using `--no-ff`.
- Never resolve source-owned artifact bytes by blindly choosing ours/theirs or hand-editing YAML formatting. Base bytes
  may seed an isolated rebuild, but final conflict bytes must come from the merged producer/config contract and central
  finalizer.
- Reject tracked `gamesymbols/**`, `gamedata/**`, `release-manifests/**`, and `bin/**/*.yaml` in the final PR diff.
- Stop on a conflict in trusted planner/policy/required-workflow/publisher code unless the intended trust-root change is
  independently specified and reviewable; do not let the PR choose its own validation boundary.
- Do not run a publisher, create Release outputs, push BinSync, or use publication credentials.
- After push, report checks once and stop. Never merge or enable auto-merge.

## Step 1 — Capture the immutable PR state

```powershell
git status --short --branch
git remote
gh auth status
gh pr view <PR> --json number,url,state,isDraft,baseRefName,baseRefOid,headRefName,headRefOid,headRepository,headRepositoryOwner,mergeable,mergeStateStatus,statusCheckRollup
git fetch <REMOTE> <BASE_BRANCH> <HEAD_BRANCH> --prune
git rev-parse <REMOTE>/<BASE_BRANCH>
git rev-parse <REMOTE>/<HEAD_BRANCH>
git diff --name-status <REMOTE>/<BASE_BRANCH>...<REMOTE>/<HEAD_BRANCH>
```

Save `PR_URL`, `BASE_BRANCH`, `HEAD_BRANCH`, `PR_HEAD_SHA`, `BASE_HEAD_SHA`, and `ORIGINAL_PR_PATHS`. Require the PR API
head SHA to equal `<REMOTE>/<HEAD_BRANCH>` after fetch. If the PR is already mergeable and the user did not request a
base synchronization, report that no resolution is needed and stop.

## Step 2 — Check out the exact PR head

Create a local tracking branch only when absent; otherwise fast-forward the existing clean branch:

```powershell
git switch --track -c <HEAD_BRANCH> <REMOTE>/<HEAD_BRANCH>
# or
git switch <HEAD_BRANCH>
git pull --ff-only <REMOTE> <HEAD_BRANCH>
git rev-parse HEAD
```

Require `HEAD == PR_HEAD_SHA` before merging.

## Step 3 — Merge base and inventory conflicts

```powershell
git merge --no-ff <REMOTE>/<BASE_BRANCH>
git status --short
git diff --name-only --diff-filter=U
```

Exit code 1 is expected only for reported conflicts. Classify every unmerged path:

- `configs/<GAMEVER>.yaml`: merge producer ordering, alternatives, expected/optional inputs/outputs, prerequisites,
  symbols, aliases, cpp tests, and platform gates semantically. Do not duplicate an owner or silently drop either
  parent's intent.
- `ida_preprocessor_scripts/**`, references, Agent skills, source, tests, or docs: read both parents and resolve behavior
  semantically. Stop when intent is ambiguous.
- `bin_artifacts/<GAMEVER>/<module>/*.yaml`: record A/M/D/R paths and base/merge ownership. Do not accept either side as
  final; resolution is deferred to the isolated rebuild in Step 4.
- forbidden legacy/Release-derived namespaces: remove them from the prospective PR result and investigate why they were
  introduced; they are not conflict-resolution inputs.
- trust-root paths named in the safety rules: stop and report the exact conflict for independent handling.

Require one explicit GAMEVER per invocation when artifact/config ownership is involved. A historical GAMEVER change is
allowed only when the PR explicitly intends a backport and carries the matching source-owned artifact closure; never
auto-migrate its intent to latest or silently revert it.

## Step 4 — Rebuild artifact conflicts and downstream closure

From the merged source/config/reference intent, compute affected producer groups using both direct changed paths and
recorded artifact A/M/D/R ownership. Include the complete downstream closure and cross-module paths.

For targeted iteration, use a checkout-external seeded root and omit `-force_all`; `-modules`/`-skill` filters are allowed
only in that non-final iteration. Final validation must use the complete merged config, a different fresh empty root, the
explicit prior GAMEVER (or `none`), and a force-all execution report:

```powershell
uv run ida_analyze_bin.py -gamever <GAMEVER> -configyaml configs/<GAMEVER>.yaml `
  -artifactdir <CHECKOUT_EXTERNAL_EMPTY_ROOT> -oldartifactdir bin_artifacts `
  -oldgamever <PRIOR_GAMEVER-or-none> -execution_report <CHECKOUT_EXTERNAL_EXECUTION_REPORT.json> `
  -force_all -debug
```

Do not combine this final command with `-modules`, `-skill`, or vcall filters. Require:

- every selected producer group actually executed and has one valid winner;
- required/optional/formal inventory, ownership, paths, and canonical bytes pass;
- no extra/stale YAML remains;
- the source checkout's tracked artifact digest did not change during isolated execution.

Copy the validated A/M/D/R closure from the isolated root into tracked `bin_artifacts/<GAMEVER>/`. Remove obsolete paths
only when the merged formal contract proves their deletion/rename, then stage each path explicitly. Run the repository
artifact contract. If IDA/LLM/Agent execution is unavailable, stop without committing: a guessed conflict result is not
deliverable.

## Step 5 — Resolve remaining paths and review

Stage only explicitly resolved source/config/reference/test/artifact paths. Require no unmerged entries or conflict
markers:

```powershell
git diff --name-only --diff-filter=U
git diff --check
git status --short
```

Read `references/review-pr.md` and run its read-only Steps 1–4 against the resolved prospective PR. Its review must treat
`bin_artifacts` as source-owned proof and reject forbidden tracked Release outputs. If actionable findings exist, report
them and stop; repairing findings beyond conflict resolution requires the user's explicit follow-up direction.

## Step 6 — Format and validate

```powershell
uv run python format_repo_files.py
uv run python format_repo_files.py --check
uv run python bin_artifact_contract.py
git diff --check
```

The formatter intentionally skips canonical `bin_artifacts`; never reformat them outside the central finalizer. Run
focused tests for every changed behavior plus the repository-contract suite. Revert formatting-only changes outside the
authorized PR scope before staging. Do not claim CI-only self-hosted or external gates passed locally.

## Step 7 — Create one merge commit

Recheck and explicitly stage the authorized set:

```powershell
git add -- <EXPLICIT_RESOLVED_SOURCE_CONFIG_REFERENCE_TEST_PATHS>
git add -- <EXPLICIT_BIN_ARTIFACT_CLOSURE_PATHS>
git diff --cached --check
git diff --name-only --diff-filter=U
git diff --cached --name-status <REMOTE>/<BASE_BRANCH>
git diff --cached --stat <REMOTE>/<BASE_BRANCH>
```

Require no unstaged tracked changes. Confirm the final diff preserves the PR intent, includes the complete artifact
closure, and contains no forbidden tracked output namespace. Commit without amending:

```powershell
git commit -m "chore(merge): sync <BASE_BRANCH> into <TOPIC> branch" -m "Co-Authored-By: Codex <codex@openai.com>"
```

Verify the merge commit has exactly two parents in order: `PR_HEAD_SHA BASE_HEAD_SHA`.

## Step 8 — Push without force and stop

Immediately before push, query the PR again and require the remote head is still `PR_HEAD_SHA`. Then:

```powershell
git push <REMOTE> "HEAD:refs/heads/<HEAD_BRANCH>"
gh pr view <PR> --json url,headRefOid,mergeable,mergeStateStatus,statusCheckRollup
gh pr checks <PR>
```

If push is rejected, fetch and report divergence; never retry with force. Pending checks are an acceptable endpoint.
Never invoke `gh pr merge`, auto-merge, a merge API, branch deletion, or a switch to the default branch.

## Final report

Report the PR/base/head identities, pushed merge SHA, resolved paths, affected GAMEVER/groups, staged artifact closure,
format/test/contract evidence, review findings, and latest check state. State explicitly:

```text
PR was not merged by resolve-pr-conflict.
```

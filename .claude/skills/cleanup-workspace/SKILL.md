---
name: cleanup-workspace
description: |
  Clean up the local workspace after a dev branch has been merged into main.
  Verifies the current dev branch is fully merged into origin/main, then switches to main,
  pulls the latest, deletes the local dev branch, and deletes the remote dev branch if it still exists.
  STOPS and warns the user if the current branch is not yet merged.
  Triggers: cleanup workspace, cleanup branch, delete merged branch, finish dev branch, post-merge cleanup
---

# Cleanup Workspace

Post-merge housekeeping: verify the active dev branch landed in `main`, then prune it locally and on `origin`.

## When to Use

After a pull request authored on a `dev*` branch has been merged into `main` and the user wants to return the workspace to a clean state on the updated `main` branch.

## Safety Rules

- **NEVER** delete a branch that is not fully merged into `origin/main`. If the merge check fails, STOP immediately and report to the user — do not pass `-D` to force delete.
- **NEVER** run on `main` itself. If the current branch is `main`, abort with a clear message.
- **NEVER** discard uncommitted changes. If the working tree is dirty, abort and ask the user to commit or stash first.
- The remote name is assumed to be `origin`. If `origin` is not present, abort and ask the user which remote to use.

## Method

### Step 1 — Capture state and validate preconditions

Run these checks in parallel:

```bash
git rev-parse --abbrev-ref HEAD          # current branch name
git status --porcelain                   # must be empty (clean working tree)
git remote                               # must contain 'origin'
```

Abort with a clear message if:
- Current branch is `main` (nothing to clean up).
- `git status --porcelain` is non-empty (uncommitted changes).
- `origin` remote does not exist.

Save the current branch name as `DEV_BRANCH` for later steps.

### Step 2 — Fetch latest refs and verify merge status

```bash
git fetch origin --prune
```

Then check whether every commit on `DEV_BRANCH` is reachable from `origin/main`:

```bash
git merge-base --is-ancestor <DEV_BRANCH> origin/main
```

- Exit code `0` → branch is fully merged. Proceed to Step 3.
- Exit code `1` → branch has commits not in `origin/main`. **STOP** and report to the user:
  - Show the unmerged commits: `git log --oneline origin/main..<DEV_BRANCH>`
  - Tell the user the branch is not merged and the skill will not delete it.
  - Do **not** continue to subsequent steps.

### Step 3 — Switch to main and pull

```bash
git checkout main
git pull origin main --ff-only
```

Use `--ff-only` so the pull aborts cleanly if something unexpected happened upstream rather than creating a merge commit silently.

### Step 4 — Delete the local dev branch

```bash
git branch -d <DEV_BRANCH>
```

Use lowercase `-d` (safe delete). It refuses to delete if not merged — which should not happen since Step 2 already verified the merge, but the double-check is intentional. Do **not** fall back to `-D`.

### Step 5 — Delete the remote dev branch if it still exists

First check whether the remote branch is still present (the maintainer may have already deleted it after merging the PR):

```bash
git ls-remote --heads origin <DEV_BRANCH>
```

- Output empty → remote already deleted. Skip the delete and report "remote branch already removed".
- Output non-empty → delete it:

```bash
git push origin --delete <DEV_BRANCH>
```

If the push fails (permission denied, protected branch, etc.), report the error to the user — do not retry with force.

### Step 6 — Report final state

Summarize what changed in a short message:
- Current branch (should be `main`) and its short SHA.
- Whether the local dev branch was deleted.
- Whether the remote dev branch was deleted or was already gone.

## Example Walk-through

User finishes work on `dev-14156` which has been merged into `main` via PR:

```
Step 1: HEAD=dev-14156, working tree clean, origin present.        ✓
Step 2: git fetch origin --prune
        git merge-base --is-ancestor dev-14156 origin/main → 0     ✓ merged
Step 3: git checkout main
        git pull origin main --ff-only                              → main now at <sha>
Step 4: git branch -d dev-14156                                     → deleted
Step 5: git ls-remote --heads origin dev-14156 → non-empty
        git push origin --delete dev-14156                          → deleted
Step 6: Report: on main @ <sha>; local dev-14156 deleted; remote dev-14156 deleted.
```

## Notes

- The skill is a pure git workflow — no IDA Pro MCP or codebase analysis is involved.
- If the user wants to clean up a *different* branch than the one currently checked out, they should switch to it first; this skill only operates on `HEAD`.
- The skill never force-deletes (`-D`) or force-pushes. If a step refuses, that is a signal to stop and surface the situation, not to override.

---
name: create-pr
description: |
  Create a GitHub pull request from either staged task changes or an already-committed current branch. Use when the
  user asks to create or open a PR, including when there are no staged changes but the clean current branch is not
  main and has commits ahead of origin/main. Both modes use the full immutable candidate lifecycle. An
  already-committed branch receives a supplemental publication commit without rewriting its existing commits.
disable-model-invocation: true
---

# Create Pull Request

Create one pull request using exactly one delivery mode:

- `staged-delivery` - deliver the caller's staged changes through candidate preparation, validation, publication,
  commit, push, and PR creation. Treat the index at invocation time as the authorized change set. The only additional
  paths this mode may stage are formatter updates to those same paths and validated
  `gamesymbols/<GAMEVER>.yaml` / `gamedata/<GAMEVER>/` outputs.
- `committed-branch` - when the index is empty, deliver the existing commits on a clean non-`main` current branch
  that is ahead of `origin/main`. Treat the captured `origin/main...HEAD` diff as the authorized source change set.
  Run the same candidate lifecycle, then commit only formatter changes to those captured paths and validated
  `gamesymbols/<GAMEVER>.yaml` / `gamedata/<GAMEVER>/` publication outputs. Never rewrite existing commits.

Never mix the two modes in one invocation.

## Inputs

- `gamever` - required in both modes. Use the caller-provided value; if omitted, read `CS2VIBE_GAMEVER` from `.env`.
- `branch` - optional `dev*` branch name for `staged-delivery`. If omitted while on `main`, derive a concise
  `dev-<topic>` name from the staged change. Ignore this input in `committed-branch`; use the current branch exactly.
- `commit_title` - optional Conventional Commit title for `staged-delivery`. If omitted, derive it from the staged
  diff.
- `pr_title` / `pr_body` - optional PR text. If omitted, derive it from the delivered staged or committed diff and
  actual validation results.
- `issue` - optional GitHub issue number. Add `Closes #<issue>` to the PR body when supplied.

After selecting either mode, resolve exactly one non-empty `GAMEVER`. Set `ANALYSIS_CONFIG="configs/$GAMEVER.yaml"`
and stop if that file does not exist. Never fall back to another game version.

## Safety Rules

- Run from the repository root and require an `origin` remote plus successful `gh auth status`.
- Never commit directly to `main`, force-push, amend an existing commit, or use `git add -A` / `git add .`.
- Preserve unrelated untracked files and never stage them.
- **Never impose a 64-second execution timeout** on candidate preparation, C++ validation, or candidate publication. When a command may outlive the interactive timeout, start it as a background task and poll its log and exit status until it finishes.
- Require zero unstaged tracked changes at invocation. This forbids partially staged paths and prevents the
  formatter from absorbing unrelated work.
- In `staged-delivery`, treat the initial staged path list as immutable authorization. Do not add other source,
  config, reference, test, or documentation paths after the gates run.
- In `committed-branch`, require an empty index, a non-`main` attached branch, at least one commit ahead of
  `origin/main`, and a non-empty `origin/main...HEAD` diff. Preserve the captured `HEAD` as the parent of at most one
  supplemental publication commit; preserve the current branch and captured committed path list until push.
- Stop on the first failed/non-runnable gate. Do not repair or retry inside this skill, and do not commit, push, or
  create a PR after a gate failure.

## Step 1: Select and Guard the Delivery Mode

Record the current branch and complete status, then inspect the index:

```bash
git branch --show-current
git status --short
git diff --cached --quiet
git diff --cached --name-only
git diff --cached --name-status
git diff --cached --stat
git diff --name-only
git ls-files --others --exclude-standard
git remote
gh auth status
git fetch origin main --prune
git rev-parse HEAD
git rev-parse origin/main
git rev-list --count origin/main..HEAD
git diff --name-only origin/main...HEAD
git diff --name-status origin/main...HEAD
git diff --stat origin/main...HEAD
```

### PowerShell Native Command Execution

On Windows PowerShell, use the following wrapper when recording the Step 1 native-command output and exit codes.
Use `CommandArgs` rather than `Args`: PowerShell variable names are case-insensitive, and `$args` is an automatic
variable. Pass the argument array through the named `-CommandArgs` parameter so it cannot be lost or ambiguously
bound. Do not set `$ErrorActionPreference = 'Stop'` around these commands because native tools may write normal
status messages to stderr. Interpret each command using its captured `$LASTEXITCODE` according to this skill.

```powershell
function Run-Native {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Executable,

        [Parameter(Mandatory)]
        [string[]]$CommandArgs
    )

    $output = & $Executable @CommandArgs 2>&1
    $exitCode = $LASTEXITCODE

    Write-Output "<<<$Name exit=$exitCode>>>"
    if ($null -ne $output) {
        $output | ForEach-Object { $_.ToString() }
    }
    Write-Output "<<<END $Name>>>"
}

Run-Native -Name 'branch' -Executable 'git' -CommandArgs @('branch', '--show-current')
Run-Native -Name 'status_short' -Executable 'git' -CommandArgs @('status', '--short')
Run-Native -Name 'cached_quiet' -Executable 'git' -CommandArgs @('diff', '--cached', '--quiet')
```

Use the same explicit form for every remaining command in Step 1, for example:

```powershell
Run-Native -Name 'fetch_main' -Executable 'git' -CommandArgs @('fetch', 'origin', 'main', '--prune')
Run-Native -Name 'gh_auth' -Executable 'gh' -CommandArgs @('auth', 'status')
Run-Native -Name 'committed_names' -Executable 'git' -CommandArgs @(
    'diff', '--name-only', 'origin/main...HEAD'
)
```

`git diff --name-only` must be empty in both modes. If any unstaged tracked change exists, stop before formatting,
candidate creation, push, or PR creation and report the paths. Untracked files may remain, but record them and never
stage them.

Interpret `git diff --cached --quiet` as follows:

### Mode A - `staged-delivery`

Exit `1` proves staged changes exist. Save the exact `git diff --cached --name-only` result as
`INITIAL_STAGED_PATHS`, including staged additions, renames, and deletions. Read `git diff --cached` to understand the
change, detect accidentally staged unrelated files or credentials, and derive the commit/PR summary.

Validate the intended branch before running expensive gates:

- On `main`, choose the caller-provided `branch` or derive a valid, unused `dev-<topic>` name. Validate it with
  `git check-ref-format --branch <dev-branch>` and require that it does not exist locally or on `origin`.
- On an existing `dev*` branch whose `HEAD` still equals `origin/main`, use that branch unless the caller explicitly
  supplied the same name.
- On any other branch, stop and ask the caller to use `main` or a `dev*` branch.

### Mode B - `committed-branch`

Exit `0` means the index is empty. Allow this mode only when all of the following hold after fetching `origin/main`:

- `git branch --show-current` returns a non-empty branch name other than `main`;
- `git check-ref-format --branch <current-branch>` succeeds;
- `git rev-list --count origin/main..HEAD` is greater than zero;
- `git diff --quiet origin/main...HEAD` exits `1`, proving the PR would contain a non-empty committed diff.

Otherwise stop with a specific error. Use these forms for the two common empty-index failures:

```text
<skill_error>create-pr cannot run: no staged changes and the current branch is main or detached.</skill_error>
<skill_error>create-pr cannot run: no staged changes and the current branch has no committed changes ahead of origin/main.</skill_error>
```

Capture `INITIAL_BRANCH`, `INITIAL_HEAD`, `AHEAD_COUNT`, and the exact `git diff --name-only origin/main...HEAD` result
as `INITIAL_COMMITTED_PATHS`. Read `git diff origin/main...HEAD` and `git log --format=fuller origin/main..HEAD` to
understand the complete PR change, detect unrelated files or credentials, and derive the PR title/body. Ignore the
optional `branch` input and use `INITIAL_BRANCH` as the PR head.

Any exit code from `git diff --cached --quiet` other than `0` or `1` is a hard stop.

For either mode, set `PR_BRANCH` to the intended dev branch or captured current branch. Check
`gh pr list --state open --head <PR_BRANCH> --json url`. Stop if an open PR already exists for it. Never create a
duplicate PR.

## Step 2: Prepare the Immutable Candidate

In both modes, **ALWAYS** Use SKILL `/prepare-post-change-candidate` with the resolved `gamever`.

Retain the returned candidate path, candidate session path, gamedata session path, and candidate SHA-256. If the
skill fails, stop the entire task.

After preparation, inspect `git diff --name-only`. Formatting may have changed a path only when it belongs to
`INITIAL_STAGED_PATHS` in `staged-delivery`, or to `INITIAL_COMMITTED_PATHS` in `committed-branch`. If any other
tracked path changed, stop and report it; do not stage it or continue.

## Step 3: Validate the Exact Candidate

In both modes, **ALWAYS** Use SKILL `/post-change-validation` with the same `gamever`, candidate path, and candidate
session path returned by `/prepare-post-change-candidate`.

Require explicit success, runnable C++ tests, and zero failure counters. If validation fails or is non-runnable,
stop exactly as that skill requires. Do not publish, commit, push, or create a PR.

## Step 4: Publish the Validated Candidate

Only after validation succeeds in either mode, **ALWAYS** Use SKILL `/publish-post-change-candidate` with the same
`gamever`, candidate path, candidate session path, and gamedata session path.

Require the published snapshot SHA-256 to equal the validated candidate SHA-256. Publication may modify only:

- existing paths in `INITIAL_STAGED_PATHS` or `INITIAL_COMMITTED_PATHS` that were reformatted;
- `gamesymbols/$GAMEVER.yaml`;
- files under `gamedata/$GAMEVER/`.

Compare `git status --short` with the status recorded in Step 1. Any new or modified path outside that allowlist is
a hard stop. Preserve pre-existing unrelated untracked files and leave them untracked.

## Step 5: Refresh the Authorized Index

Refresh formatter changes only for existing files in the active mode's initial authorized path list, passing every
path explicitly:

```bash
git add -- <explicit-existing-initial-authorized-paths>
git add -- "gamesymbols/$GAMEVER.yaml" "gamedata/$GAMEVER"
```

Already-staged deletions need no refresh. In `committed-branch`, the initially captured paths are already committed, so
stage only those existing paths that the formatter changed. Never use a repository-wide add command.

Then verify:

```bash
git diff --name-only
git diff --cached --quiet
git diff --cached --name-only
git diff --cached --stat
```

Require zero unstaged tracked changes. Every final staged path must be either an active mode initial authorized path or
an allowed current-version publication path. Review the final cached diff before committing. In `staged-delivery`,
require a non-empty staged diff. In `committed-branch`, an empty staged diff is permitted only when formatter and
publication are both no-ops; record it and create no empty supplemental commit.

## Step 6: Create the Required Commit

If currently on `main`, create the validated branch now:

```bash
git switch -c <dev-branch>
```

If already on the intended branch, remain there. In `staged-delivery`, derive or validate `commit_title` using the
repository format `<type>(scope): <summary>`: start with a verb, keep it at most 100 characters, and omit the final
period. In `committed-branch`, use `chore(gamesymbols): publish <GAMEVER> snapshot` for the non-empty supplemental
publication commit.

In `staged-delivery`, commit exactly the staged index. In `committed-branch`, commit exactly the non-empty staged
publication index; when it is empty, skip this command and retain `INITIAL_HEAD`:

```bash
git commit -m "<commit_title>" -m "Co-Authored-By: Codex"
```

Verify any new commit's changed paths match the final staged path list and that no unstaged tracked changes remain.
In `committed-branch`, require the supplemental commit's parent to equal `INITIAL_HEAD`, proving no existing commit
was rewritten. Do not amend if verification fails; stop and report the mismatch.

## Step 7: Push and Create the Pull Request

In `committed-branch`, re-run the following immediately before push:

```bash
git branch --show-current
git merge-base --is-ancestor <INITIAL_HEAD> HEAD
git diff --cached --quiet
git diff --quiet
git rev-list --count origin/main..HEAD
git diff --name-only origin/main...HEAD
```

Require the branch to equal `INITIAL_BRANCH`, `INITIAL_HEAD` to remain an ancestor of `HEAD`, and both index and
tracked worktree to be clean. Require the ahead count to remain greater than zero and the final committed path list to
equal the union of `INITIAL_COMMITTED_PATHS` and the authorized formatter/publication paths. If a supplemental commit
was made, require it to be the direct child of `INITIAL_HEAD`; otherwise require `HEAD` to equal `INITIAL_HEAD`.
Stop if any condition fails.

Push without force:

```bash
git push -u origin <PR_BRANCH>
```

Build the PR title from `pr_title` when supplied. Otherwise, use the new commit title in `staged-delivery`; in
`committed-branch`, derive a concise title from the captured initial committed diff and its pre-publication log so the
supplemental publication commit does not become the PR title.

Build the body from the delivered committed diff and actual results. Never claim a validation that this invocation
did not run. Use this concise shape in both modes:

```markdown
## Summary
- <behavioral change>
- <supporting change>

## Validation
- implementation-specific tests: <commands/results supplied by the caller>
- candidate preparation: passed for `<GAMEVER>`
- C++ post-change validation: passed with runnable tests and zero failures
- candidate publication: passed; published SHA-256 matches the validated candidate

Closes #<issue>
```

For `committed-branch`, retain the candidate lifecycle lines and add this truthful delivery evidence:

```markdown
- existing committed branch: `<AHEAD_COUNT>` initial commit(s) ahead of `origin/main`; supplemental publication commit:
  <created or not needed because publication was a no-op>
```

Omit the issue line when no issue was supplied. Create the PR explicitly against `main`:

```bash
gh pr create --base main --head <PR_BRANCH> --title "<pr_title>" --body "<pr_body>"
```

Report the branch, commit SHA, pushed remote, PR URL, game version, candidate SHA-256, and final committed path list
for both modes. In `committed-branch`, also report `INITIAL_HEAD`, the initial ahead count, and whether a supplemental
publication commit was created. If push succeeds but PR creation fails, report the remote branch and exact failure;
do not delete the branch, force-push, or create another commit.

## Checklist

- [ ] Exactly one mode was selected: non-empty initial index, or clean non-`main` branch ahead of `origin/main`.
- [ ] No unstaged tracked changes existed at invocation.
- [ ] `staged-delivery`: initial cached diff is task-related; all candidate gates passed; final staged paths are
      authorized; commit is on a `dev*` branch and follows repository format.
- [ ] `committed-branch`: the full candidate lifecycle passed; formatter changes stay within captured committed paths;
      publication outputs are staged and committed when non-empty; the original HEAD is preserved as the supplemental
      commit parent; branch and worktree are clean before push.
- [ ] No duplicate open PR existed; branch was pushed without force; exactly one PR was created against `main`.

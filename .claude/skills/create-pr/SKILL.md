---
name: create-pr
description: |
  Create a GitHub pull request from either staged task changes or an already-committed current branch. Use when the
  user asks to create or open a PR, including when there are no staged changes but the clean current branch is not
  main and has commits ahead of origin/main. Delivered changes that touch the CS2 symbols pipeline run the full
  immutable candidate lifecycle (prepare, validate, publish, refresh). Changes that touch no CS2 Symbols-related path
  skip the lifecycle and open the PR directly. Classification uses
  `.claude/skills/create-pr/scripts/classify_delivery.py`; do not guess. An already-committed branch receives a
  supplemental publication commit only when the lifecycle runs.
disable-model-invocation: true
---

# Create Pull Request

Create one pull request using exactly one delivery mode:

- `staged-delivery` - deliver the caller's staged changes through candidate preparation, validation, publication,
  commit, push, and PR creation — or directly as a plain PR when the staged change touches no CS2 Symbols-related
  path. Treat the index at invocation time as the authorized change set. The only additional paths this mode may
  stage are formatter updates to those same paths and validated
  `gamesymbols/<GAMEVER>.yaml` / `gamedata/<GAMEVER>/` outputs.
- `committed-branch` - when the index is empty, deliver the existing commits on a clean non-`main` current branch
  that is ahead of `origin/main`. Treat the captured `origin/main...HEAD` diff as the authorized source change set.
  Run the same candidate lifecycle — or deliver the branch directly as a plain PR when no changed path is CS2
  Symbols-related. Never rewrite existing commits.

Both modes share one classification gate (Step 2, the bundled classifier). Never mix the two modes in one invocation.

## Inputs

- `gamever` - required only when the delivered change is CS2 Symbols-related (see Step 2). Use the caller-provided
  value; if omitted, read `CS2VIBE_GAMEVER` from `.env`. The plain-PR path never resolves or requires `gamever`.
- `branch` - optional `dev*` branch name for `staged-delivery`. If omitted while on `main`, derive a concise
  `dev-<topic>` name from the staged change. Ignore this input in `committed-branch`; use the current branch exactly.
- `commit_title` - optional Conventional Commit title for `staged-delivery`. If omitted, derive it from the staged
  diff.
- `pr_title` / `pr_body` - optional PR text. If omitted, derive it from the delivered staged or committed diff and
  actual validation results.
- `issue` - optional GitHub issue number. Add `Closes #<issue>` to the PR body when supplied.

## Safety Rules

- Run from the repository root and require an `origin` remote plus successful `gh auth status`.
- Never commit directly to `main`, force-push, amend an existing commit, or use `git add -A` / `git add .`.
- Preserve unrelated untracked files and never stage them.
- **Never impose a 64-second execution timeout** on candidate preparation, C++ validation, or candidate publication.
  When a command may outlive the interactive timeout, start it as a background task and poll its log and exit status
  until it finishes.
- Require zero unstaged tracked changes at invocation. This forbids partially staged paths and prevents the
  formatter from absorbing unrelated work.
- In `staged-delivery`, treat the initial staged path list as immutable authorization. Do not add other source,
  config, reference, test, or documentation paths after the gates run.
- In `committed-branch`, require an empty index, a non-`main` attached branch, at least one commit ahead of
  `origin/main`, and a non-empty `origin/main...HEAD` diff. Preserve the captured `HEAD` as the parent of at most one
  supplemental publication commit; preserve the current branch and captured committed path list until push.
- After capturing the change set, run the bundled classifier and obey `LIFECYCLE=`. When it prints `LIFECYCLE=0`,
  skip the entire candidate lifecycle: do not resolve `gamever`, do not invoke `/prepare-post-change-candidate`,
  `/post-change-validation`, or `/publish-post-change-candidate`, and do not run the formatter. Deliver the captured
  staged or committed change exactly as-is. Never claim candidate preparation, C++ validation, or candidate
  publication in the PR body when the lifecycle was skipped. You may override only from `0` to `1` when a captured
  path clearly feeds the symbols pipeline and the classifier missed it. Never override `1` to `0`.
- Stop on the first failed/non-runnable gate. Do not repair or retry inside this skill, and do not commit, push, or
  create a PR after a gate failure. The sole exception is Step 3a: when `/prepare-post-change-candidate` fails only
  because `bin/$GAMEVER/` is missing analysis artifacts that the config's `modules` contract already declares (the
  `Missing required symbol YAML:` marker), this skill may run the module analyzer once to fill those artifacts and
  retry preparation exactly once. Any other failure — or a second failure after that fill — still hard-stops with no
  commit, push, or PR.

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

## Step 2: Classify the Change and Choose the Delivery Path

Do not classify by inspection. After Step 1, run the bundled classifier from the repository root against the selected
mode's change set:

```powershell
# staged-delivery
uv run python .claude/skills/create-pr/scripts/classify_delivery.py --cached

# committed-branch
uv run python .claude/skills/create-pr/scripts/classify_delivery.py --committed
```

The script reads `git diff --name-status` itself (including both sides of a rename). If it exits non-zero, stop. Read
`LIFECYCLE=` from the first output line. The `matched=` line is a count; the following lines are the matching paths.

Decide:

- **Lifecycle mode** (`LIFECYCLE=1`): at least one captured path feeds symbol analysis, the canonical snapshot,
  versioned gamedata, or C++ validation. Run Steps 3 through 6, then Step 7 and Step 8.
- **Plain-PR mode** (`LIFECYCLE=0`): no captured path is CS2 Symbols-related (for example only `.claude/skills/`,
  `docs/`, `memory/`, `pages/`, `.github/`, `tests/`, `README*`, `download.yaml`, `config.toml`, `.mcp.json`,
  `release_workflow.py`, `release_workflow_lib/`, or process-monitoring modules). Skip Steps 3 through 6 entirely,
  proceed directly to Step 7 and Step 8, and deliver the captured change exactly as-is.

Override only `0` → `1` when a captured path clearly feeds the symbols pipeline and is missing from the matched list.
Never override `1` → `0`.

## Step 3: Prepare the Immutable Candidate

In lifecycle mode only, resolve exactly one non-empty `GAMEVER`. Set `ANALYSIS_CONFIG="configs/$GAMEVER.yaml"`
and stop if that file does not exist. Never fall back to another game version. Then **ALWAYS** Use SKILL
`/prepare-post-change-candidate` with the resolved `gamever`.

Retain the returned candidate path, candidate session path, gamedata session path, and candidate SHA-256. If the
skill fails, stop the entire task.

After preparation, inspect `git diff --name-only`. Formatting may have changed a path only when it belongs to
`INITIAL_STAGED_PATHS` in `staged-delivery`, or to `INITIAL_COMMITTED_PATHS` in `committed-branch`. If any other
tracked path changed, stop and report it; do not stage it or continue.

## Step 3a: Recover Missing Analysis Artifacts (Prepare Failure Only)

Use this step only when `/prepare-post-change-candidate` fails **exclusively** at `gamesymbol_candidate.py build` with
the `Missing required symbol YAML:` marker — i.e. the config's `modules` contract declares analysis artifacts that are
absent from `bin/$GAMEVER/`. This is a `bin`/config drift, not a change to the delivered source. Any other prepare
failure (formatter, guard, gamedata build, malformed YAML, undeclared YAML, etc.) is a hard stop; do not invoke this
step for it.

The declared analyzer is already idempotent and skip-if-exists, so the fill runs only skills whose outputs are
missing. It may only ever add untracked `bin/$GAMEVER/` files (never tracked or staged paths), and it runs the full
module dependency graph — safer than a per-skill fill, since prerequisites are honored.

Procedure:

1. Parse the missing artifact lines from the failure output. Each line is `<module>/<Symbol>.<platform>.yaml`. Collect
   the **module** names only — the part before the first `/` — deduplicated and in order. Stop if any line does not
   match `<module>/<symbol>.{windows,linux}.yaml` or any module contains `/` or `\`.

2. For every such module, run the analyzer from the repository root. The config already declares every missing
   artifact, so no `-skill` filter is needed; run the whole module and let `skip-if-exists` limit the work:

   ```bash
   uv run ida_analyze_bin.py -gamever "$GAMEVER" -modules "$MODULES" 
   ```

   where `$MODULES` is the comma-joined, deduplicated module list from step 1. Any nonzero exit stops this step and
   the whole task. Start it as a background task and poll until it finishes — never impose a 64-second timeout on IDA
   analysis.

3. Re-verify on disk that every parsed missing artifact now exists, then re-run `/prepare-post-change-candidate` with
   the same `gamever` exactly once. Use the new candidate/session paths it returns for Steps 4 and 5; do not reuse the
   failed attempt's paths. If preparation fails again, stop the whole task; there is no second recovery attempt.

4. Re-inspect `git status --short`. The recovery must leave the working tree and index exactly as Step 1 recorded them:
   no tracked file may become modified or staged, and no path outside `bin/$GAMEVER/` may appear as untracked. Any
   tracked change not already present in the initial authorized path list is a hard stop; `bin/` files remain untracked
   and are never committed.

## Step 4: Validate the Exact Candidate

In lifecycle mode only, **ALWAYS** Use SKILL `/post-change-validation` with the same `gamever`, candidate path, and
candidate session path returned by `/prepare-post-change-candidate`.

Require explicit success, runnable C++ tests, and zero failure counters. If validation fails or is non-runnable,
stop exactly as that skill requires. Do not publish, commit, push, or create a PR.

## Step 5: Publish the Validated Candidate

Only after validation succeeds in lifecycle mode, **ALWAYS** Use SKILL `/publish-post-change-candidate` with the same
`gamever`, candidate path, candidate session path, and gamedata session path.

Require the published snapshot SHA-256 to equal the validated candidate SHA-256. Publication may modify only:

- existing paths in `INITIAL_STAGED_PATHS` or `INITIAL_COMMITTED_PATHS` that were reformatted;
- `gamesymbols/$GAMEVER.yaml`;
- files under `gamedata/$GAMEVER/`.

Compare `git status --short` with the status recorded in Step 1. Any new or modified path outside that allowlist is
a hard stop. Preserve pre-existing unrelated untracked files and leave them untracked.

## Step 6: Refresh the Authorized Index

In lifecycle mode, refresh formatter changes only for existing files in the active mode's initial authorized path
list, passing every path explicitly:

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

## Step 7: Create the Required Commit

If currently on `main`, create the validated branch now:

```bash
git switch -c <dev-branch>
```

If already on the intended branch, remain there. In `staged-delivery`, derive or validate `commit_title` using the
repository format `<type>(scope): <summary>`: start with a verb, keep it at most 100 characters, and omit the final
period. In `committed-branch` lifecycle mode, use `chore(gamesymbols): publish <GAMEVER> snapshot` for the non-empty
supplemental publication commit. In `committed-branch` plain-PR mode, there is no supplemental commit.

Commit exactly the staged index in `staged-delivery` (both lifecycle and plain-PR). In `committed-branch` lifecycle
mode, commit exactly the non-empty staged publication index; when it is empty, skip this command and retain
`INITIAL_HEAD`. In `committed-branch` plain-PR mode, the captured commits are already the complete change and the
index is empty, so skip this command and retain `INITIAL_HEAD`:

```bash
git commit -m "<commit_title>" -m "Co-Authored-By: Codex"
```

Verify any new commit's changed paths match the final staged path list and that no unstaged tracked changes remain.
In `committed-branch`, require the supplemental commit's parent to equal `INITIAL_HEAD`, proving no existing commit
was rewritten. Do not amend if verification fails; stop and report the mismatch.

## Step 8: Push and Create the Pull Request

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
tracked worktree to be clean. Require the ahead count to remain greater than zero. Require the final committed path
list to equal the union of `INITIAL_COMMITTED_PATHS` and the authorized formatter/publication paths in lifecycle
mode, or to equal `INITIAL_COMMITTED_PATHS` exactly in plain-PR mode. If a supplemental commit was made, require it to
be the direct child of `INITIAL_HEAD`; otherwise require `HEAD` to equal `INITIAL_HEAD`. Stop if any condition fails.

Push without force:

```bash
git push -u origin <PR_BRANCH>
```

Build the PR title from `pr_title` when supplied. Otherwise, use the new commit title in `staged-delivery`; in
`committed-branch`, derive a concise title from the captured initial committed diff and its pre-publication log so the
supplemental publication commit does not become the PR title.

Build the body from the delivered committed diff and actual results. Never claim a validation that this invocation
did not run. In lifecycle mode, use this concise shape in both modes:

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

In plain-PR mode, omit the three candidate lifecycle lines entirely; the lifecycle was not run and must not be
claimed. Use this shape:

```markdown
## Summary
- <behavioral change>

## Validation
- implementation-specific tests: <commands/results supplied by the caller>

Closes #<issue>
```

For `committed-branch`, add the truthful delivery evidence in both modes:

```markdown
- existing committed branch: `<AHEAD_COUNT>` initial commit(s) ahead of `origin/main`; supplemental publication commit:
  <created, not needed because publication was a no-op, or not created because the lifecycle was skipped>
```

Omit the issue line when no issue was supplied. Create the PR explicitly against `main`:

```bash
gh pr create --base main --head <PR_BRANCH> --title "<pr_title>" --body "<pr_body>"
```

Report the branch, commit SHA, pushed remote, PR URL, and final committed path list for both modes; report the game
version and candidate SHA-256 only in lifecycle mode. In `committed-branch`, also report `INITIAL_HEAD`, the initial
ahead count, and whether a supplemental publication commit was created. If push succeeds but PR creation fails, report
the remote branch and exact failure; do not delete the branch, force-push, or create another commit.

## Checklist

- [ ] Exactly one mode was selected: non-empty initial index, or clean non-`main` branch ahead of `origin/main`.
- [ ] No unstaged tracked changes existed at invocation.
- [ ] Step 2 ran `classify_delivery.py` for the selected mode. `LIFECYCLE=1` ran Steps 3-6; `LIFECYCLE=0` skipped
      them and created the PR directly from the captured change, without lifecycle claims in the body.
- [ ] Step 3a ran only when prepare failed with the `Missing required symbol YAML:` marker; it derived modules from
      those paths, ran the module analyzer once (background, no 64s timeout), verified the artifacts, retried prepare
      once, and left the tracked tree/index untouched (only untracked `bin/` files added).
- [ ] `staged-delivery`: initial cached diff is task-related; all candidate gates passed (lifecycle mode); final staged
      paths are authorized; commit is on a `dev*` branch and follows repository format.
- [ ] `committed-branch`: the full candidate lifecycle passed (lifecycle mode); formatter changes stay within captured
      committed paths; publication outputs are staged and committed when non-empty; the original HEAD is preserved as
      the supplemental commit parent; branch and worktree are clean before push.
- [ ] No duplicate open PR existed; branch was pushed without force; exactly one PR was created against `main`.

---
name: create-pr
description: |
  Create a GitHub pull request from staged task changes or an already-committed current branch. Classify the delivered
  paths with `.claude/skills/create-pr/scripts/classify_delivery.py`; symbol-pipeline changes are committed as source
  changes only, while candidate preparation and C++ validation are owned by
  `.github/workflows/pr-self-runner.yml`; snapshot/gamedata publication is release-pipeline only.
disable-model-invocation: true
---

# Create Pull Request

Create one pull request using exactly one delivery mode:

- `staged-delivery` — commit the caller's explicitly staged source changes, push a `dev*` branch, and create the PR.
- `committed-branch` — push an existing clean non-`main` branch that is ahead of `origin/main`, without rewriting or
  supplementing its commits.

Both modes run the classifier before delivery. `LIFECYCLE=1` means the PR requires the workflow-owned symbols
lifecycle; it does not authorize local generation or publication. `LIFECYCLE=0` means a plain PR.

## Inputs

- `gamever` — optional descriptive value for the PR body. Never resolve or require it for local delivery.
- `branch` — optional `dev*` branch name for `staged-delivery`. If omitted on `main`, derive `dev-<topic>` from the
  staged change. Ignore it in `committed-branch`.
- `commit_title` — optional Conventional Commit title for `staged-delivery`.
- `pr_title` / `pr_body` — optional PR text. Otherwise derive truthful text from the delivered diff and caller-supplied
  test results.
- `issue` — optional issue number. Add `Closes #<issue>` to the PR body.

## Safety Rules

- Run from the repository root and require an `origin` remote plus successful `gh auth status`.
- Never commit directly to `main`, force-push, amend existing commits, or use `git add -A` / `git add .`.
- Preserve unrelated untracked files and never stage them.
- Require zero unstaged tracked changes at invocation. This forbids partially staged paths and unrelated work.
- In `staged-delivery`, the initial staged path list is the immutable authorized change set. Do not add generated
  `gamesymbols/<GAMEVER>.yaml` or `gamedata/<GAMEVER>/` outputs locally.
- In `committed-branch`, require an empty index, a non-`main` attached branch, at least one commit ahead of
  `origin/main`, and a non-empty `origin/main...HEAD` diff. Never create a supplemental publication commit.
- Run the bundled classifier and obey `LIFECYCLE=`. You may override only `0` → `1` when a captured path clearly feeds
  the symbols pipeline and the classifier missed it. Never override `1` → `0`.
- Candidate preparation and C++ validation run only in `.github/workflows/pr-self-runner.yml` after the PR exists;
  snapshot/gamedata publication runs only in the release pipeline. Never claim those CI gates passed locally.
- Commit and push commands may take longer than an interactive timeout. Wait for their real exit status; do not infer
  success from elapsed time.

## Step 1: Select and Guard the Delivery Mode

Record the current state and fetch the target branch:

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

On Windows PowerShell, use explicit argument arrays and capture `$LASTEXITCODE` for native commands. Do not use the
automatic `$args` variable as a named parameter:

```powershell
function Run-Native {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string[]]$CommandArgs
    )
    $output = & $Executable @CommandArgs 2>&1
    $exitCode = $LASTEXITCODE
    Write-Output "<<<$Name exit=$exitCode>>>"
    if ($null -ne $output) { $output | ForEach-Object { $_.ToString() } }
    Write-Output "<<<END $Name>>>"
}
```

`git diff --name-only` must be empty in both modes. Untracked files may remain, but record and preserve them.

### Mode A — `staged-delivery`

Exit `1` from `git diff --cached --quiet` proves staged changes exist. Save the exact cached path list as
`INITIAL_STAGED_PATHS`, review the cached diff for unrelated files or credentials, and derive the summary.

- On `main`, validate the supplied/derived branch with `git check-ref-format --branch <dev-branch>` and require it not
  to exist locally or on `origin`.
- On an existing `dev*` branch whose `HEAD` equals `origin/main`, use that branch.
- On any other branch, stop and ask the caller to use `main` or a suitable `dev*` branch.

### Mode B — `committed-branch`

Exit `0` means the index is empty. Require an attached branch other than `main`, a valid branch name, an ahead count
greater than zero, a non-empty `origin/main...HEAD` diff, and a clean tracked worktree. Capture `INITIAL_BRANCH`,
`INITIAL_HEAD`, `AHEAD_COUNT`, and `INITIAL_COMMITTED_PATHS`. Read the full diff and log; never rewrite those commits.

For either mode, set `PR_BRANCH`, then reject duplicate open PRs:

```bash
gh pr list --state open --head <PR_BRANCH> --json url
```

## Step 2: Classify the Delivered Change

Run the classifier against the selected mode; do not classify by inspection:

```powershell
# staged-delivery
uv run python .claude/skills/create-pr/scripts/classify_delivery.py --cached

# committed-branch
uv run python .claude/skills/create-pr/scripts/classify_delivery.py --committed
```

If it exits non-zero, stop. Read `LIFECYCLE=` from the first line and retain the matched paths as delivery evidence.

- `LIFECYCLE=1` — submit only the captured source change. State that `pr-self-runner.yml` will prepare the candidate
  and run C++ validation after the PR is opened; snapshot/gamedata publication happens only at release time.
- `LIFECYCLE=0` — submit the captured change as a plain PR without lifecycle claims.

Never override `1` → `0`.

## Step 3: Revalidate the Authorized Index

Do not run formatters or generators in this skill. In `staged-delivery`, verify that the cached path list still equals
`INITIAL_STAGED_PATHS` and that no unstaged tracked path exists:

```bash
git diff --name-only
git diff --cached --quiet
git diff --cached --name-only
git diff --cached --stat
git diff --cached --check
```

Require a non-empty staged diff, review it again, and stage nothing else. In `committed-branch`, require both index and
tracked worktree to remain clean and `HEAD == INITIAL_HEAD`.

## Step 4: Create the Source Commit

In `staged-delivery`, create the validated branch when currently on `main`:

```bash
git switch -c <dev-branch>
```

Derive or validate `<type>(scope): <summary>`: begin with a verb, keep it at most 100 characters, and omit the final
period. Commit exactly the existing staged index:

```bash
git commit -m "<commit_title>" -m "Co-Authored-By: Codex <codex@openai.com>"
```

Verify the commit changed exactly `INITIAL_STAGED_PATHS` and the tracked worktree/index are clean. In
`committed-branch`, create no commit and require `HEAD == INITIAL_HEAD`.

## Step 5: Push and Create the Pull Request

Immediately before push, require the intended branch, clean index/worktree, a positive ahead count, and a final
`origin/main...HEAD` path list equal to the captured source paths. In `committed-branch`, also require
`HEAD == INITIAL_HEAD`.

Push without force:

```bash
git push -u origin <PR_BRANCH>
```

Build a truthful body. For `LIFECYCLE=1`, use this shape and do not claim the CI gates have already passed:

```markdown
## Summary
- <behavioral change>
- <supporting change>

## Validation
- implementation-specific tests: <commands/results supplied by the caller>
- candidate preparation and C++ validation: delegated to `pr-self-runner.yml` CI; snapshot/gamedata publication is
  release-pipeline only

Closes #<issue>
```

For `LIFECYCLE=0`, omit the CI lifecycle line. If `gamever` was supplied, it may be included as descriptive context,
not as evidence of local validation. Omit the issue line when absent.

Create exactly one PR against `main`:

```bash
gh pr create --base main --head <PR_BRANCH> --title "<pr_title>" --body "<pr_body>"
```

Report the branch, commit SHA, pushed remote, PR URL, classifier result, and final committed paths. For
`committed-branch`, report `INITIAL_HEAD` and the initial ahead count. If push succeeds but PR creation fails, report the
remote branch and exact failure; do not delete the branch or create another commit.

## Checklist

- [ ] Exactly one delivery mode was selected and no unstaged tracked changes existed.
- [ ] `.claude/skills/create-pr/scripts/classify_delivery.py` ran with `--cached` or `--committed`.
- [ ] The local commit contains source changes only; generated snapshot/gamedata outputs were not added.
- [ ] `LIFECYCLE=1` delegates candidate/C++ validation to `pr-self-runner.yml`; `LIFECYCLE=0` makes no lifecycle claim.
- [ ] No duplicate PR existed; the branch was pushed without force; exactly one PR was opened against `main`.

[Back to README](../../README.md) | [中文](../zh-CN/conributing-via-pr.md) | [Creating skills](creating-skills.md)

# Contributing symbol-analysis skills via a pull request

After creating and verifying a symbol-analysis skill, use `SKILL: create-pr` (invoked as `/create-pr`) to share it with the project. The skill classifies the staged change first. CS2 Symbols-related paths go through candidate preparation, validation, and publication before commit, push, and PR creation. Changes that touch no symbols-related path open a PR directly.

## Invoke the skill

Ask the agent to run the skill, for example:

```text
Use SKILL: create-pr to share the staged symbol-analysis skill.
gamever: 14156
branch: dev-find-example
commit_title: feat(skills): add find-example symbol-analysis skill
```

`branch`, `commit_title`, PR title/body, and an issue number are optional. 

If omitted, `create-pr` derives suitable values from the staged diff.

It creates the PR from a `dev*` branch against `main`; it never commits directly to `main`.

## What `create-pr` does

The workflow classifies the delivered change with
`.claude/skills/create-pr/scripts/classify_delivery.py`. If any staged path feeds the CS2 symbols pipeline (for
example `configs/`, `ida_preprocessor_scripts/`, `cpp_tests/`, `hl2sdk_cs2/`, `gamesymbols/`, `gamedata/`, or the
root analysis/snapshot/C++ modules), it runs these gates in order:

1. Captures and checks the exact staged paths.
2. Runs `/prepare-post-change-candidate` for the selected game version.
3. Runs `/post-change-validation` against that immutable candidate.
4. Runs `/publish-post-change-candidate` only after validation succeeds.
5. Stages only authorized formatter changes and current-version generated outputs.
6. Commits with the repository's Conventional Commit format and `Co-Authored-By: Codex`.
7. Pushes the `dev*` branch and opens one PR against `main`.

If no staged path is CS2 Symbols-related (for example the change is only a documentation, workflow, skill, or
process-monitoring update), `create-pr` skips steps 2 through 5 entirely, does not resolve a `gamever`, and opens the
PR directly from the captured change. The PR body never claims candidate preparation, C++ validation, or publication
in that case.

The skill stops before commit or PR creation when there are no staged changes, unstaged tracked changes, missing authentication, a failed or non-runnable gate, or an unexpected path change. Do not bypass a failed gate or manually publish the candidate.

## After the skill finishes

Record the reported branch, commit SHA, PR URL, and final committed path list. For a symbols-related delivery, also record the game version and candidate SHA-256, and review the PR to confirm that it contains the intended skill and supporting files plus only the generated outputs for the selected game version.

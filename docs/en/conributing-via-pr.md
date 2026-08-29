[Back to README](../../README.md) | [中文](../zh-CN/conributing-via-pr.md) | [Creating skills](creating-skills.md)

# Contributing symbol-analysis skills via a pull request

After creating and locally testing a symbol-analysis skill, use `SKILL: create-pr` (invoked as `/create-pr`) to share it
with the project. The skill commits only the staged source change. `pr-self-runner.yml` independently selects the PR's
validation path from its changed paths; snapshot/gamedata publication is release-pipeline only.

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

The skill delivers the captured source change without trying to predict or influence the workflow's validation route:

1. Captures and checks the exact staged paths.
2. Commits only those source paths with the repository's Conventional Commit format and `Co-Authored-By: Codex`.
3. Pushes the `dev*` branch and opens one PR against `main`.
4. `pr-self-runner.yml` classifies the changed paths with `pr_validation_mode.py` and its trusted
   `pr_validation_mode.yaml`, then runs the selected light or full validation path.
5. On the full path, CI checks out an immutable merge ref, analyzes binaries, builds one snapshot candidate and matching
   gamedata candidate, and runs C++ validation against those exact bytes.
6. `gamesymbols/<GAMEVER>.yaml` and `gamedata/<GAMEVER>/` advance only at release time; the PR workflow never publishes
   them back to the PR head.

The skill stops before commit or PR creation when there are no staged changes, unstaged tracked changes, missing
authentication, or an unexpected path change. Do not add generated snapshot/gamedata outputs locally; CI owns them.

## After the skill finishes

Record the reported branch, source commit SHA, PR URL, and final committed path list. Wait for the stable `pr-validate`
check on the latest PR head. Snapshot/gamedata outputs are published later by the release pipeline, not by this PR.

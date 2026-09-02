[Back to README](../../README.md) | [中文](../zh-CN/conributing-via-pr.md) | [Creating skills](creating-skills.md)

# Contributing symbol-analysis skills via a pull request

After creating and locally testing a symbol-analysis skill, rebuild its affected producer groups and complete downstream closure in `bin_artifacts/`. Stage the source/config/reference change and the resulting canonical per-symbol artifacts together, then use `SKILL: create-pr` (invoked as `/create-pr`) to share them with the project.

Do not stage Release-derived `gamesymbols/`, `gamedata/`, metadata, archives, checksums, or `release-manifests/`. The binary/IDA workspace under `bin/` is also not source truth.

## Invoke the skill

Ask the agent to run the skill, for example:

```text
Use SKILL: create-pr to share the staged symbol-analysis change and artifact closure.
gamever: 14156
branch: dev-find-example
commit_title: feat(skills): add find-example symbol-analysis skill
```

`branch`, `commit_title`, PR title/body, and an issue number are optional. If omitted, `create-pr` derives suitable values from the staged diff. It creates the PR from a `dev*` branch against `main`; it never commits directly to `main`.

## What must be staged

The staged set is one atomic source-owned change:

1. The producer, config, reference, or source files that changed.
2. Every affected artifact A/M/D/R under `bin_artifacts/<GAMEVER>/`.
3. Every artifact in the computed downstream closure, including cross-module outputs.
4. Any directly related tests or durable documentation.

Use the local planner and repository artifact contract to compute and verify the closure. Do not trust a hand-written affected list: CI recomputes ownership and invalidation from the default-branch planner.

## What `create-pr` does

1. Captures and checks the exact staged path set, including the `bin_artifacts` closure.
2. Rejects tracked `gamesymbols/`, `gamedata/`, `release-manifests/`, and `bin/**/*.yaml`.
3. Commits only the captured paths using the repository Conventional Commit format and `Co-Authored-By: Codex`.
4. Pushes the `dev*` branch and opens one PR against `main`.
5. Waits for the stable `source-artifact-required` and `pr-validate` checks on the latest head.

Full validation binds the exact prospective merge tree, rebuilds affected producer groups into a checkout-external root, and compares the complete actual inventory with Git blobs byte-for-byte. Merge Queue repeats that proof for the final queued tree.

For a new GAMEVER, the initial PR may enter `bootstrap_required`. The protected bootstrap publisher may append only a fast-forward artifact commit to the matching `bump-download/<GAMEVER>` branch. That artifact-bearing head must then pass normal exact-byte validation; the bootstrap run cannot satisfy the required check by itself.

## After the skill finishes

Record the branch, source commit SHA, PR URL, final committed paths, and verification results. Snapshot, metadata, gamedata, archives, manifests, BinSync changes, and Pages inputs are reconstructed later by the immutable Release pipeline; they are never published back to the source PR.

---
name: review-pr
description: Review an open or local CS2_VibeSignatures pull request for correctness, with special scrutiny of IDA preprocessor design, duplicated LLM_DECOMPILE work, interface-versus-concrete virtual-function ownership, INHERIT_VFUNCS chains, requested YAML fields, config dependencies, generated snapshots, and regression coverage. Use when the user asks to review, inspect, audit, or fix a PR. Report evidence-backed findings first and never modify, commit, push, comment on, close, or merge the PR until the user explicitly approves the proposed fixes; after approval, fix the existing PR branch directly without creating or merging another PR.
disable-model-invocation: true
---

# Review Pull Request

Review one PR against its base branch. Treat review and repair as separate phases.

## Safety Boundary

- Keep the initial phase read-only. Fetching refs and running non-mutating diagnostics are allowed.
- Do not edit files, post review comments, commit, push, close, merge, or create another PR during review.
- If no actionable finding exists, report that result and the remaining validation limits.
- If any actionable finding exists, stop after presenting the findings and a concrete repair plan. Ask the user for explicit approval to fix the existing PR.
- Accept approval only from a later user message that clearly authorizes the proposed repair. The original request to review or use this skill is not repair approval.
- After approval, check out the PR's existing head branch, make only the approved fixes, run the repository-required validation, commit, and push to that same branch without force. Never merge the PR.
- Stop before repair when the PR comes from a fork or the head branch cannot be pushed safely; report the limitation.

## Step 1: Establish the Review Target

Resolve the PR number or URL from the user. If omitted, infer it only when the current branch maps to exactly one open PR.

Verify GitHub authentication and inspect the PR without changing it:

```powershell
gh auth status
gh pr view <PR> --json number,url,title,body,state,isDraft,baseRefName,baseRefOid,headRefName,headRefOid,headRepository,headRepositoryOwner,author,mergeable,mergeStateStatus,commits,files,statusCheckRollup
git status --short --branch
git fetch origin <base-branch> <head-branch> --prune
```

Record immutable `BASE_OID` and `HEAD_OID`. Review exactly `BASE_OID...HEAD_OID`; do not review an ambiguous moving branch range. Preserve any pre-existing worktree changes and never switch branches during the read-only phase.

## Step 2: Build the Evidence Set

Inspect at least:

```powershell
git diff --stat <BASE_OID>...<HEAD_OID>
git diff --name-status <BASE_OID>...<HEAD_OID>
git diff --find-renames <BASE_OID>...<HEAD_OID>
git log --format=fuller <BASE_OID>..<HEAD_OID>
gh pr checks <PR>
```

Read every changed source/config/test file relevant to behavior. Treat generated `gamesymbols/` and `gamedata/` diffs as outputs to cross-check, not as proof that the analysis model is correct.

For changes under `ida_preprocessor_scripts/` or `configs/`, also search the base tree and history for:

- all scripts consuming the same `reference_yaml_paths` predecessor;
- all existing producers of each expected output symbol;
- adjacent interface and concrete-class vtable patterns;
- recent fixes or refactors for the same predecessor, vtable family, or analysis primitive;
- config ordering, `expected_input`, `expected_output`, symbol category, aliases, and cross-module paths.

Use `git show <BASE_OID>:<path>` or a temporary worktree for base-tree content. Do not judge only the PR head: the central question is whether the PR missed or duplicated an existing mechanism.

## Step 3: Apply Repository-Specific Review Gates

Read [preprocessor-review-patterns.md](references/preprocessor-review-patterns.md) whenever the PR changes preprocessor scripts, analysis configs, reference YAML, or generated symbol snapshots. Apply every applicable gate, not only the two examples.

Additionally check general correctness:

- behavior matches the PR title/body and all requested symbols are actually produced;
- dependency paths and module ownership are correct on Windows and Linux;
- failure handling does not silently skip required targets;
- requested YAML fields are necessary and generatable for the target;
- deterministic logic is preferred over an added LLM call when repository primitives already express the relationship;
- tests cover new reusable behavior or high-risk branches;
- generated snapshots correspond to config/script changes and do not conceal stale or hand-edited output.

Run focused read-only tests or linters when practical. Do not run publication workflows or commands that rewrite tracked files during review.

## Step 4: Report Findings

Order findings by severity. For each actionable finding include:

1. severity (`P0` to `P3`) and concise title;
2. exact PR file and line;
3. observed behavior and why it is wrong;
4. base-tree or historical evidence, including symbol/script/commit names;
5. concrete repair shape and affected files;
6. validation needed after repair.

Avoid speculative findings. Distinguish confirmed defects from questions and validation gaps.

When findings exist, end the review with a single explicit consent question such as:

```text
我发现以上问题。是否允许我直接在该 PR 的现有 head branch 上按上述方案修复、验证、提交并 push？我不会合并 PR。
```

Do not begin repair in the same turn, even if the user originally asked to “review and fix.” Wait for the follow-up approval because the findings determine the repair scope.

## Step 5: Repair Only After Approval

Re-read the live PR metadata and require its head SHA still equals `HEAD_OID`. If it changed, inspect the new diff and present an updated review before editing.

Require:

- the PR is open and from the same repository;
- the working tree can be preserved safely;
- the existing head branch is available and pushable;
- no unrelated local changes would be overwritten or included.

Check out the existing PR head branch without creating a replacement PR. Implement only approved findings. For preprocessor changes, keep config producers/consumers, scripts, tests, reference YAML, and desired output fields coherent.

Run focused tests first. When analysis outputs, configs, generators, or C++ tests change, follow the exact immutable lifecycle:

1. use `/prepare-post-change-candidate` for the affected game version;
2. use `/post-change-validation` on that exact candidate;
3. use `/publish-post-change-candidate` only after validation succeeds.

Stop on any failed, skipped, or non-runnable gate. Commit using the repository Conventional Commit format plus `Co-Authored-By: Codex <codex@openai.com>`, then push normally to the same head branch. Never force-push, merge, enable auto-merge, close the PR, or create a second PR.

Report the repaired findings, commands and results, commit SHA, pushed branch, and PR URL.

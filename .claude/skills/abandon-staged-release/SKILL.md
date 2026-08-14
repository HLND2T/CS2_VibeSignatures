---
name: abandon-staged-release
description: Safely discover the unique trusted merged generated-output PR and dispatch the protected recovery workflow for one explicitly identified unpromoted staged release. Use only when the user explicitly asks to abandon or clean a GAMEVER/BUILD_ID, or supplies a trusted GitHub Actions run/job URL for the staged build or a run uniquely blocked by it, after promotion failed before promote-bin.
disable-model-invocation: true
---

# Abandon Staged Release

Use the bundled script as the only remote-operation entry point. Do not run `cleanup-unmerged`, delete `READY`,
remove staging paths manually, accept a user-supplied SHA/path, resume promotion, or trigger a replacement build.

## Procedure

1. Require an explicit `GAMEVER/BUILD_ID` or trusted GitHub Actions run/job URL, exact confirmation, and one-line
   reason. A run URL may identify the staged build itself or a failed release build whose logs uniquely report that
   staged build as its READY blocker.
2. Run from any directory with the build identity:

   ```powershell
   uv run python .claude/skills/abandon-staged-release/scripts/abandon_staged_release.py `
     <GAMEVER>/<BUILD_ID> `
     --confirm "ABANDON <GAMEVER>/<BUILD_ID>" `
     --reason "<WHY_PROMOTION_IS_BEING_ABANDONED>"
   ```

   Or use a run/job URL as independent target evidence:

   ```powershell
   uv run python .claude/skills/abandon-staged-release/scripts/abandon_staged_release.py `
     <GITHUB_ACTIONS_RUN_OR_JOB_URL> `
     --confirm "ABANDON <GAMEVER>/<BUILD_ID>" `
     --reason "<WHY_PROMOTION_IS_BEING_ABANDONED>"
   ```

3. The script automatically discovers the exact output branch and requires exactly one trusted merged Bot PR from
   the same repository into `main`; it derives the PR number and head SHA rather than accepting either from the user.
   Discovery accepts the canonical `gamesymbols/build/<GAMEVER>/<BUILD_ID>` branch and, only for historical recovery,
   the exact legacy `gamesymbols/<GAMEVER>/build-<BUILD_ID>` branch. All other trust and identity checks remain required.
4. Report the target evidence, discovered PR URL, game version/build ID/head SHA, reason, and Actions run URL.
5. If the script or workflow refuses the operation, surface the exact safety reason and stop. Never bypass repository,
   PR author/repository/base/branch, confirmation, active-run, promotion-marker, recovery-path, or index/manifest checks.

The workflow only removes the matching staged directory and PR index. It refuses any state containing
`PROMOTION_STARTED`, `PROMOTED.json`, `PROMOTION_COMPLETE`, or matching accepted-bin incoming/backup paths. It never
modifies accepted `bin/<GAMEVER>` and never automatically reruns a release build.

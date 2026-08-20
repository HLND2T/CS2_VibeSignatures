---
title: pr-self-runner
type: note
permalink: cs2-vibesignatures/pr-self-runner
---

# pr-self-runner

## Overview
`.github/workflows/pr-self-runner.yml` 是同仓库 PR 的确定性验证流水线。非 bump PR 先解析实际 validation GAMEVER，并强依赖 [[warmup_idb]] 发布 immutable cache generation；验证 job 只从该 generation 恢复 binary/`.i64`（不再从 accepted persisted bin 拷贝二进制），再以 `-require_warm_idb` 严格分析。accepted persisted bin 只提供 YAML 等基线状态，不再提供 IDB cache。
## Responsibilities
- 监听 PR 打开、更新、ready 与关闭事件，拒绝 fork，并跳过 generated-output PR。
- `pr-preflight` 从 PR merge ref 与 base snapshot 历史解析实际 validation GAMEVER、base snapshot metadata 和 immutable merge/base SHA。
- 非 bump PR 通过 `pr-warmup-idb` 强依赖 reusable warm-cache producer；producer 失败会阻止 validation。
- 只从 producer 返回的 explicit generation 恢复 configured binaries 与 `.i64`，不依赖 accepted persisted bin；尚未 promotion 的新版本允许没有 accepted bin。
- restore 前在 repo root→目标路径上执行 reparse-component 校验，拒绝 junction/symlink 注入；并校验 cache key、inventory 与 consumer IDA kernel version。
- 使用 `ida_analyze_bin.py -require_warm_idb`，禁止缺失或无效 IDB 回退 inline auto-analysis。
- 构建、比较并验证实际 candidate；成功后只 stage/promote analyzed YAML，不回传 `.i64`。
## Involved Files & Symbols
- `.github/workflows/pr-self-runner.yml` - jobs `pr-preflight`, `pr-warmup-idb`, `pr-validate`, `finalize-pr-workspace`.
- `.github/workflows/warmup-idb.yml` - required reusable producer.
- `pr_validation_version.py` - 在 job DAG 建立前解析 validation GAMEVER。
- `idb_cache.py` - explicit generation restore 与 inventory/cache-key 校验。
- `ida_analyze_bin.py` - `-require_warm_idb` strict consumer mode.
- `gamesymbol_snapshot.py`, `gamesymbol_pr_validation.py`, `gamesymbol_candidate.py` - baseline/candidate lifecycle.
- `tests/test_pr_self_runner_workflow.py` - DAG、cache restore、strict analysis 与 YAML-only promotion contract。
## Architecture
1. `pr-preflight` 检出 PR merge ref，识别 bump PR；普通 PR 使用 base snapshot 历史解析 validation GAMEVER，并输出 merge SHA。
2. `pr-warmup-idb` 以 reusable workflow 形式生产或复用 immutable warm-cache generation；同一 PR 的 validation 必须等待其成功。
3. `pr-validate` 检出 preflight 固定的 merge SHA，并断言 checkout HEAD 精确一致；base snapshot path/commit 也直接消费 preflight 的 Python selector 输出，不再重复实现选择算法。
4. consumer 验证本机 IDA kernel version 后，`idb_cache.py restore` 从 explicit generation 恢复 configured binaries 与 `.i64`；restore 前对 repo root→目标路径执行 reparse-component 校验，缺失、篡改或 identity 不匹配立即失败。无单独的 accepted-bin copy 步骤。
6. baseline restore/invalidate、tests、strict IDA analysis、candidate compare、gamedata/C++ validation 按原确定性顺序执行。
7. 成功 run 只 stage analyzed YAML；PR merged 时 finalize 只 promote YAML 回 accepted bin。
## Dependencies
- GitHub PR merge ref、base SHA、protected `win64` environment 与 self-hosted Windows runner。
- [[warmup_idb]]、`PERSISTED_WORKSPACE/idb-cache/<GAMEVER>`；`PERSISTED_WORKSPACE/bin/<GAMEVER>` 仅作为 merge 后 YAML 提升目标。
- `CS2VIBE_AGENT`/LLM secrets、submodules、base/head configs 与 snapshots。
- `PERSISTED_WORKSPACE/pr-yaml-staging/<PR>` 用于 YAML-only merge promotion。
## Notes
- PR 在 generated-output PR 合并前即可消费 warm cache，因为 cache publication 与 release promotion 已解耦。PR 自己也可以在 cache miss 时通过 reusable producer 创建 generation。
- 旧设计有单独的 `prepare-bin` 步骤，从 accepted `PERSISTED_WORKSPACE/bin/<GAMEVER>` 按 `.stignore` robocopy 二进制；该步骤已删除，二进制与 `.i64` 一律由 cache generation restore 提供。即使 accepted bin 中存在 release promotion 带回的 `.i64`，PR 也不会消费它。
- cache generation 是 immutable；PR 使用 `needs.pr-warmup-idb.outputs.generation/cache_key`，不跟随随后变化的 READY pointer。
- PR title/head ref/login 通过 job environment 传给 PowerShell，不直接插值进脚本源码。
- warmup/cache restore/strict identity 任一失败都会阻止 analysis；不存在 inline auto-analysis fallback。
- accepted bin 不再被 PR job 拷贝；configured binaries 与 IDB 完全由 warm-cache generation restore 提供，因此 accepted bin 是否存在都不影响验证，只要 cache generation 完整。accepted YAML baseline 的恢复仍由 Git snapshot 规则决定。
- bump-download PR 保持 lightweight validation，不调用 warmup；generated-output PR 仍被显式排除。
- PR 成功后仍只 stage/promote `*.yaml`，不回传或发布 analysis 期间变化的 `.i64`。
- concurrency group 仍按 PR number 取消同一 PR 的过期 run；warm-cache producer 另按 GAMEVER 串行化。
## Callers
- GitHub pull request actions：`opened`、`synchronize`、`reopened`、`ready_for_review`、`closed`。

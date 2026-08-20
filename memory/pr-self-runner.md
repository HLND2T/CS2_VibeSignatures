---
title: pr-self-runner
type: note
permalink: cs2-vibesignatures/pr-self-runner
---

# pr-self-runner

## Overview
`.github/workflows/pr-self-runner.yml` 是同仓库 PR 的确定性验证流水线。非 bump PR 先解析实际 validation GAMEVER，并强依赖 [[warmup_idb]] 发布 immutable cache generation；验证 job 只从该 generation 恢复 binary/`.i64`，再以 `-require_warm_idb` 严格分析。accepted persisted bin 只提供 YAML 等基线状态，不再提供 IDB cache。
## Responsibilities
- 监听 PR 打开、更新、ready 与关闭事件，拒绝 fork，并跳过 generated-output PR。
- `pr-preflight` 从 PR merge ref 与 base snapshot 历史解析实际 validation GAMEVER 和 immutable merge SHA。
- 非 bump PR 通过 `pr-warmup-idb` 强依赖 reusable warm-cache producer；producer 失败会阻止 validation。
- accepted `PERSISTED_WORKSPACE/bin/<GAMEVER>` 存在时按 `.stignore` 复制非 IDB 基线；尚未 promotion 的新版本允许没有 accepted bin。
- 只从 producer 返回的 explicit generation 恢复 configured binaries 与 `.i64`，并校验 cache key/inventory。
- 使用 `ida_analyze_bin.py -require_warm_idb`，禁止缺失或无效 IDB 回退 inline auto-analysis。
- 构建、比较并验证实际 candidate；成功后只 stage/promote analyzed YAML，不回传 `.i64`。
## Involved Files & Symbols
- `.github/workflows/pr-self-runner.yml` - jobs `pr-preflight`, `pr-warmup-idb`, `pr-validate`, `finalize-pr-workspace`.
- `.github/workflows/warmup-idb.yml` - required reusable producer.
- `pr_validation_version.py` - 在 job DAG 建立前解析 validation GAMEVER。
- `idb_cache.py` - explicit generation restore 与 inventory/cache-key 校验。
- `ida_analyze_bin.py` - `-require_warm_idb` strict consumer mode.
- `gamesymbol_snapshot.py`, `gamesymbol_pr_validation.py`, `gamesymbol_candidate.py` - baseline/candidate lifecycle.
- `PERSISTED_WORKSPACE/bin/.stignore` - accepted baseline copy exclusions，包含 IDA database side files。
- `tests/test_pr_self_runner_workflow.py` - DAG、cache restore、strict analysis 与 YAML-only promotion contract。
## Architecture
1. `pr-preflight` 检出 PR merge ref，识别 bump PR；普通 PR 使用 base snapshot 历史解析 validation GAMEVER，并输出 merge SHA。
2. `pr-warmup-idb` 以 reusable workflow 形式生产或复用 immutable warm-cache generation；同一 PR 的 validation 必须等待其成功。
3. `pr-validate` 再次检出相同 merge ref，并断言本地解析的 GAMEVER 与 preflight 一致，防止 warmup/analysis drift。
4. accepted persisted bin 若存在，只按 `.stignore` 复制 YAML/sidecar 等非 IDB 基线；不存在时由 cache generation 提供 binaries。
5. `idb_cache.py restore` 从 explicit generation 恢复 configured binaries 与 `.i64`；缺失、篡改或 identity 不匹配立即失败。
6. baseline restore/invalidate、tests、strict IDA analysis、candidate compare、gamedata/C++ validation 按原确定性顺序执行。
7. 成功 run 只 stage analyzed YAML；PR merged 时 finalize 只 promote YAML 回 accepted bin。
## Dependencies
- GitHub PR merge ref、base SHA、protected `win64` environment 与 self-hosted Windows runner。
- [[warmup_idb]]、`PERSISTED_WORKSPACE/idb-cache/<GAMEVER>`、accepted `PERSISTED_WORKSPACE/bin/<GAMEVER>` 可选基线。
- `CS2VIBE_AGENT`/LLM secrets、submodules、base/head configs 与 snapshots。
- `PERSISTED_WORKSPACE/pr-yaml-staging/<PR>` 用于 YAML-only merge promotion。
## Notes
- PR 在 generated-output PR 合并前即可消费 warm cache，因为 cache publication 与 release promotion 已解耦。PR 自己也可以在 cache miss 时通过 reusable producer 创建 generation。
- 旧设计从 accepted `PERSISTED_WORKSPACE/bin/<GAMEVER>` 单独 robocopy `*.i64`；该路径已经删除。即使 accepted bin 中存在 release promotion 带回的 `.i64`，PR 也不会消费它。
- cache generation 是 immutable；PR 使用 `needs.pr-warmup-idb.outputs.generation/cache_key`，不跟随随后变化的 READY pointer。
- warmup/cache restore/strict identity 任一失败都会阻止 analysis；不存在 inline auto-analysis fallback。
- accepted bin 不存在不再直接失败，只要 warm-cache generation 完整即可提供 configured binaries 与 IDB。accepted YAML baseline 的恢复仍由 Git snapshot 规则决定。
- bump-download PR 保持 lightweight validation，不调用 warmup；generated-output PR 仍被显式排除。
- PR 成功后仍只 stage/promote `*.yaml`，不回传或发布 analysis 期间变化的 `.i64`。
- concurrency group 仍按 PR number 取消同一 PR 的过期 run；warm-cache producer 另按 GAMEVER 串行化。
## Callers
- GitHub pull request actions：`opened`、`synchronize`、`reopened`、`ready_for_review`、`closed`。
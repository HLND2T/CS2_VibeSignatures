---
title: Bootstrap gate red is expected until the new head revalidates
type: lesson
permalink: cs2-vibesignatures/lessons/bootstrap-gate-red-is-expected-until-the-new-head-revalidates
tags:
- cs2vibesignatures
- ci
- pr-validation
- bootstrap
- bin-artifacts
---

# 新 GAMEVER bootstrap 造成的 source-artifact-required 红叉属预期，不是回归

## 触发信号

- 新 GAMEVER 的 bump PR（`bump-download/<tag>` 分支）上，某次 run 的 `source-artifact-required` 红 ✗，
  日志尾为 `##[error]Process completed with exit code 1`，其 env 显示 `VALIDATION_MODE: bootstrap_required`。
- 同一 run 的 gate 日志出现：
  `Bootstrap artifacts were published to a new PR head; this obsolete head must not pass. Waiting for pull_request.synchronize revalidation.`
- 同一 run 内 `bootstrap-new-gamever / build-bootstrap-candidate`、`publish-new-gamever-artifacts` 均为 success，
  而 `test-prospective-tree`、`validate-full`、`pr-validate` 为 skipped。

## 根因 / 约束

- 终止 gate 对 `bootstrap_required` 模式的**两个分支都 `exit 1`**（`.github/workflows/source-artifact-required.yml:282-289`）：
  产物发布成功时，被验证过的 head 已被产物提交取代，旧 head 不允许通过，必须由 `pull_request.synchronize` 在新 head 上重新验证。
- 所以该红叉是流水线自证"旧 head 已作废"的信号，不是代码/配置回归。
- 与之矛盾的是：**只有当 `BOOTSTRAP_RESULT == failure` 时才是真问题**（build 或 publish 真的挂了）。

## 正确判读（按顺序看三个事实）

1. gate env 里的 `BOOTSTRAP_RESULT`（= `needs.bootstrap-new-gamever.result`）是 `success` 还是 `failure`。
   后者才是真失败，前者是预期失败。
2. 预期失败时，核对**产物提交确实落地**：分支/PR head 被 `source-artifact-automation` 推进，
   提交信息含 `feat(artifacts): bootstrap <GAMEVER>` 与 `Workflow-Run: .../runs/<本失败 run id>`
   （即失败的这个 run 正是产物的产出者）。
3. 新 head 上的后续 run 是否全绿（`source-artifact-required: success`，`validate-full (<GAMEVER>)` 走 bootstrap-reuse/validate）。

取值命令（避免只看 run 结论）：

```bash
gh run view <run_id> --json jobs --jq '.jobs[] | "\(.name)\t\(.conclusion)"'
# gate env 在 "Require exact prospective-tree artifact binding" 步骤的 env 块里
gh run view <run_id> --log --job <gate_job_id> | grep -E 'BOOTSTRAP_RESULT|VALIDATION_MODE'
```

## 实证（PR #1109 / GAMEVER 14189, 2026-10-06）

- run 37413023334、37426773667：**真失败**，`BOOTSTRAP_RESULT=failure`，根因是 finder SKILL 缺失 ——
  `Error: Skill file not found: .claude\skills\find-CNetChan_ProcessMessages\SKILL.md`
  （后续一次是 `find-CNetworkMessages_UnserializeMessageInternal`），preprocess 锚点失效回退 AGENT SKILL 也失败，
  最终表现为 `Force-all execution contract failed: fresh artifact repository contract failed: missing required artifacts`。
- run 37436941610：bootstrap 的 build + publish 均 success，产物提交 `6d9c6d17e`
  （`Source-Head-SHA: 15cf47f5`、`Workflow-Run: .../runs/37436941610`）落到分支 → gate 按设计失败。
- run 37455208644（head `6d9c6d17e`）：全绿，含 `validate-full (14189) / bootstrap-reuse` + `validate`。
- 同一 PR 连续多次红色完全正常（每次 bump/产物提交都触发一轮），不要按"连续失败"去报警。

## 不要做的事

- 不要把这类红叉当回归去改 workflow / planner，也不要重跑那个失败 run —— 旧 head 永远不通，
  只有新 head 上 `pull_request.synchronize` 触发的 run 才有判读意义。
- 不要把 `BOOTSTRAP_RESULT=success` 的预期失败当成"bootstrap 没生效"。

## 适用范围

仅限新 GAMEVER 的 bootstrap 路径（`download.yaml` 新增 tag + 同提交新增 `configs/<tag>.yaml`，
`binary_locks/<tag>.json` 为 added）。`light` / `full` 模式失败、以及 non-maintained 版本编辑被 planner 拒绝的判读不适用。
相关：[[source-artifact-required]]（gate 设计意图与 bootstrap 复用机制）、[[post_change_candidate_lifecycle]]、[[pr-self-runner]]。

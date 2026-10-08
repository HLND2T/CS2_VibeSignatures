---
title: Manifest contract changes must stay backward compatible for published Releases
type: lesson
permalink: cs2-vibesignatures/lessons/manifest-contract-changes-must-stay-backward-compatible-for-published-releases
tags:
- release-manifest
- pages
- deploy-pages
- backward-compatibility
- regression-prevention
---

# Manifest 契约变更必须对已发布 Release 向后兼容

## 触发信号

- `Deploy Pages` 在 `Hydrate verified published Release inputs` 步骤整体失败，报错
  `Tracked source-owned releases must not claim BinSync or warm IDB identity`，而**触发该次部署的那次发布自身 manifest 完全合规**。
- 校验规则新增后，先在 CI 中失败的是**历史上早已发布**的产物（本次为 `14180` / `14181` / `14182`），不是本次新发布的那个。
- 症状表现为“站点整体停更”：hydration fail-closed，build job 中止，后续 gamesymbols/gamedata 均不产出。

## 根因 / 约束

- `pages_release_input.py` 的 hydration 会**枚举全部已发布 Release** 逐个校验 manifest，因此任何一个历史 Release 不合规都会让整个部署失败；且 Pages 由每次 Release 发布触发，故障会连带传染到后续每一个新版本。
- 已发布的 Release 产物不能就地修改（修改等于重写 provenance 字节，含 `SHA256SUMS-<tag>.txt`、release notes、release-set digest），所以“事后修数据”不是可行出路。
- 顶层 manifest 字段集是**严格相等**校验（`set(manifest) != required`），任何新增顶层字段会让全部历史 manifest 直接失败；判别位/新增键必须放进非严格校验的子结构（本次为 `full_rebuild`）。
- 判别位必须由 manifest 自身携带：hydration 与 `init_gamebin` 路径**没有** source checkout，无法做 `producer_contract` 这类需要源码比对的判别。
- 新增键必须在 producer 计算 `verification_sha256` **之前**写入，才能被既有摘要覆盖（binding 文档的摘要公式在 producer 与 verifier 两处各有一份）。
- 同类事故已有两次：`bc6e095ca` 提升 `BUNDLE_SCHEMA_VERSION` 后 `pages_release_input.py` 以 `return None` **静默剔除** schema-v1 历史 Release（见 issue 958 的 lesson）；`9169638f4` 新增双向绑定规则后**追溯**判定历史 tracked Release 违规，Pages 自该提交起停更，直到下一个触发才暴露。

## 正确做法

- 给规则加一个**可验证的判别位**（本仓库为 `full_rebuild.binding_rule_version`，常量 `release_artifact_rebuild.BINDING_RULE_VERSION`），只对声明了当前版本的 manifest 强制；未声明该版本的历史 manifest **仅豁免这一条规则**，其余全部校验（字段集、摘要、身份、资产白名单）照旧生效。不要放松校验器整体，也不要静默跳过整个 Release。
- 判别位放在非严格字段集的子结构内，并在 producer 两条路径（tracked / rebuild）都于摘要计算前写入，使新老文档都能经既有 loader 往返。
- 消费方把观测到的规则版本记入 receipt（`RELEASE_INPUT_SCHEMA_VERSION` 随之提升），并对低于强制版本的 Release 打印提示，使“按放宽规则接受”可审计 —— 不要静默选取。
- 新增任何校验规则前，先**枚举线上已发布集合**评估追溯影响，再决定是否需要判别位。
- 需要“用新代码重部署旧 Release 数据”时，用 `workflow_dispatch` 的 `deployment_sha`（必须是 main 祖先）选择部署代码，`source_sha` 保持原 Release 来源用于验证；不要修改旧 Release、移动 tag 或重跑旧 Release 期待新代码。

## 验证方式

- 对**真实**已发布 manifest 逐个跑校验器，而不仅测触发本次故障的那一个；期望“历史按放宽规则通过 + 新发布按规则强制”两者同时成立。
- 端到端跑一次真实 hydration（真实 token、真实 Release），确认退出码 0 且 receipt 记录每个 Release 的规则版本。
- 合成 fixture 必须新增一个 **pre-rule 变体**（无判别位 + 违反新规则的数据）作为回归测试，并保留“带判别位时仍必须被拒绝”的对侧断言，避免把规则整体关掉。
- 跑 `repository-contract`、`release-integration`、`unit` 套件与 `format_repo_files.py --check`。

## 适用范围

- 任何对**已发布、不可变产物**新增或收紧校验的改动（Release manifest、Pages 数据源、归档清单）。
- 任何“消费方枚举全量集合 + fail-closed”的管线：单点历史不合规会放大为整体停摆，需按“逐条判别 + 留痕”而非“整体否决或静默丢弃”处理。

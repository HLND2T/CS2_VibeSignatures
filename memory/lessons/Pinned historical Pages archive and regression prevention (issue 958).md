---
title: Pinned historical Pages archive and regression prevention (issue 958)
type: lesson
permalink: cs2-vibesignatures/lessons/pinned-historical-pages-archive-and-regression-prevention-issue-958
tags:
- pages
- legacy-archive
- deploy-pages
- regression-prevention
- issue-958
---


# 固定历史 Pages 归档与防回归（issue 958）

## 触发信号

- 线上 `gamesymbols/index.json` 只剩最近版本，历史版本消失，旧内容寻址 URL（如 `14178b.3b967f18c5ebd488afb824915cc903d6d36c67c0145e485db3c1ec027a8e8ff1.json`）返回 404。
- 有一次“切换数据来源”的改动：Pages 构建从“合并 `pages-snapshots` 分支”改为“只读新格式 Release manifest”，但迁移遗漏了历史数据来源。
- 需要在不依赖旧 Release API/附件可用性的前提下恢复历史 gamesymbols 与历史 gamedata。

## 根因 / 约束

- 单一数据来源切换会静默丢掉旧来源覆盖的数据集；构建成功不代表数据齐全，索引缺版本不会让构建失败。
- 历史数据只能一次性离线导入；正常部署不得再下载历史 assets、解压历史 7z 或写归档分支。
- Git 归档字节必须跨平台稳定：Windows 检出会把 LF 改写成 CRLF，导致哈希与清单不一致，且同提交的 `checkout --force` 会因 stat 缓存不重写文件。
- 部署用浅检出（`fetch-depth: 1`），没有完整历史，因此不能做祖先校验，只能校验 checkout 目标 SHA 与实际逐文件 inventory。
- 手动触发部署时，部署代码取自 Release 的 `source_sha`；重跑旧 Release 只会运行旧代码，不会加载新脚本。

## 正确做法

- 把历史 gamesymbols 与历史 gamedata 一次性固化到 `pages-snapshots` 的一个新提交，并在主分支用受版本控制清单 `pages/legacy-inputs.json` 固定 `archiveCommit` + 完整 inventory + 每版 `selected` + `excluded[]` + `importProvenance`；原 asset 映射与排除原因另存 `pages/legacy-gamedata-sources.json`。
- 部署两个接入点：build job 在 Release hydration 成功后、Vite build 前补历史 gamedata；archive job 在写最终 verification manifest 前合并历史 gamesymbols。两者只读消费同一固定提交，任一历史输入缺失或损坏即中止 upload/deploy。
- 归档分支根 `.gitattributes` 标注 `gamesymbols/**` 与 `gamedata/**` 为 `text eol=lf`；核验用 git blob SHA-1（`blob <len>\0<data>`），而非工作树字节。
- 数据归属有分歧时不静默选取：记录选择依据与双方哈希（`importProvenance.gamedataSource.differences`），人工审定后再固定。
- 需要“用新代码重部署旧 Release 数据”时，用 `workflow_dispatch` 的 `deployment_sha`（必须是 `main` 祖先）选择部署代码，`source_sha` 保持原 Release 来源用于验证；不要修改旧 Release、移动 tag 或重跑旧 Release 期待新代码。
- 归档提交必须远端可达后才能启用引用它的清单/workflow；发布只用 fast-forward，绝不重写已发布归档历史。

## 验证方式

- 双运行时清单校验：Python 用 `object_pairs_hook` 拒绝重复键，Node 用“重编码为 canonical JSON 后与原文逐字节相等”；两者对同一组 fixture 语义一致。**不要**用正则/splice 构造重复键样例（canonical 会排序 key，容易构造出一个恰好合法的清单）。
- 合并后逐项断言结果目录包含清单内全部历史文件的 path/size/sha256；不要依赖 CDN 校验兜底——旧文件若未复制，最终 manifest 也可能不含它。
- 幂等：重复执行补数据与合并，最终资产字节一致；已存在整版本记 `skipped_existing`，不比较不覆盖。
- 端到端：真实 Release hydration → 补历史 gamedata → build → 合并历史 gamesymbols → `verify:gamesymbols` / `verify:gamedata` → 上线后核对两个索引、已知旧 URL 与最终 CDN 字节校验。
- 上线后确认版本集合等于“本次有效新 Release 集合 ∪ 对应固定历史集合”，总数为动态值，不写死具体版本或总数。

## 适用范围

- Pages 静态数据（gamesymbols/gamedata）的历史恢复与固定归档维护。
- 任何“切换数据来源后必须保底旧集合”的迁移；固定清单 + fail-closed 校验 + 只读消费的防回归思路可复用到其他清单驱动的部署。

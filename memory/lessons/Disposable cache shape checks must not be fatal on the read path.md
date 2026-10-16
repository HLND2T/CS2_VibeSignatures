---
title: Disposable cache shape checks must not be fatal on the read path
type: lesson
permalink: cs2-vibesignatures/lessons/disposable-cache-shape-checks-must-not-be-fatal-on-the-read-path
tags:
- accepted-bin
- ci-cd
- cache
- fail-closed
- regression-prevention
---

# 可丢弃缓存的"形状"校验不能在读路径致命

## 触发信号

- `validate-full (<GAMEVER>) / warmup-idb / warmup` 在 `Prepare persisted depot link and restore accepted bin` 步骤失败，报
  `Error: binary cache allowlist mismatch: missing=['schemasystem/libschemasystem.so', 'schemasystem/schemasystem.dll', 'tier0/libtier0.so', 'tier0/tier0.dll']; unexpected=[]`。
- 同一 run 的 `source-artifact-required` 报 `##[error]Process completed with exit code 1`，其 env 显示 `FULL_RESULT: failure`；那只是下游连带失败，真正要看的 job 是 warmup。
- 触发条件固定为：**config 新增（或删除）模块之后，持久化 accepted-bin 缓存仍是旧的文件集合**。缓存内容本身没有损坏。

## 根因 / 约束

- `restore_accepted_bin` 有三个失败分支，其中"缓存缺失"与"内容锁不匹配"都在 `--required` 未传时按 cache miss 软返回，
  只有 `validate_binary_cache_tree` 的 allowlist 分支**无条件抛异常**（`release_workflow_lib/restore_accepted_bin.py`）。
- warmup 调用 restore 时并不传 `--required`，且对非零退出直接 `throw`；而唯一能修复缓存的 `accepted_bin.py sync` 位于同一 job 的**末尾**。
  于是硬失败必然发生在修复之前 —— 死锁，只能人工删除 `PERSISTED_WORKSPACE/bin/<GAMEVER>` 才能恢复。
- 设计本身并不自洽：`sync_accepted_bin` 对**同一种** allowlist mismatch 是显式容忍的（捕获后继续走 swap 重建）。
  同一个不变量，写侧认为"可自愈"，读侧认为"致命"。
- 该 allowlist 相对 `binary_locks/<GAMEVER>.json` 的唯一独有贡献只有"拒绝多余文件/多余目录"：锁在加载时已强制
  `binaries` 的 (module, platform) 集合等于 `config.binary_targets`，且 `verify_binary_root` 会逐个哈希比对。
  而在 restore 读路径上，"多余文件"本来就是惰性的 —— restore 只拷 `allowed_paths` 里的文件，缓存里的 extras 永远不会进入工作区。

## 正确做法

- 读路径（消费者 restore）遇到任何"缓存形状与当前 config 声明不一致"都按 **cache miss** 处理：返回 `reason=cache-invalid`（附 `detail`），
  仅在 `--required` 时才抛。`--required` 的语义是"缓存缺失即不可继续"，不是"缓存必须恰好等于当前 config"。
- 严格形状校验留在**写路径**（`sync_accepted_bin` 的 source 校验）与**目标树校验**上；内容身份继续由 `binary_locks/<GAMEVER>.json` 强制。
- 判断"要不要 fail closed"时先问：**这个失败之后还有没有自动恢复路径**。如果没有，而对象又是可丢弃/可重建的缓存，那就是死锁而不是防护。
- 同类先例：`.trusted-tools` 的 bridge restore（`source_artifact_accepted_bin.py`）从一开始就只做 `verify_binary_root`，不做 allowlist 形状校验，因此从未出现这个死锁。

## 验证方式

- `tests/test_sync_accepted_bin.py::test_restore_treats_a_cache_predating_a_new_module_as_a_soft_miss`：config 增模块 → restore 软 miss 且不拷贝任何文件 → depot 重新供给后 `sync` 修复缓存，修复后的缓存重新满足严格 allowlist。
- 同文件 `test_restore_treats_unexpected_cache_entries_as_a_soft_miss`：多余文件/空目录同样软 miss，但 `--required` 时仍硬失败。
- `uv run python tests/run_test_suite.py unit -b` 与 `repository-contract -b` 全绿。

## 适用范围

- 任何"可丢弃 + 可重建"的持久化缓存的读侧校验：accepted-bin、warm IDB cache，以及未来同类自托管 runner 持久化状态。
- 不适用于发布门禁：Release 发布路径上的 fail-closed 校验必须保持硬失败（那里没有自动恢复路径，也确实不该有）。

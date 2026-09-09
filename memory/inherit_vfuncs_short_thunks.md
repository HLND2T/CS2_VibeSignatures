---
title: inherit_vfuncs_short_thunks
type: note
permalink: cs2-vibesignatures/inherit-vfuncs-short-thunks
---

# inherit_vfuncs_short_thunks

## 触发信号
- inherited vfunc 的 artifact 出现「唯一匹配但落错 slot」：issue #953 中 `CEngineServiceMgr_GetEngineWindow` 被解析到 slot 20，而基类声明的是 slot 18。
- 该虚函数在目标二进制里是跳板 / 访问器（Windows MSVC 下常见 5–14 字节）。

## 根因 / 约束
- fast path（`preprocess_func_sig_via_mcp`）复用旧 `func_sig` 时只要求 `find_bytes` 唯一，不校验语义身份。
- 短 thunk 的指令字节跨版本几乎不变，但 RIP-relative disp32 指向的目标会随代码移动，于是「唯一匹配」可能落到同一 vtable 的兄弟函数。
- 短函数生成的 sig 区分度极低，例如 `8B 81 28 02 00 ?? C3`（`mov eax,[rcx+0x228]; ret`）是类无关模式。

## 正确做法
- 函数体 ≤4 条指令的 inherited vfunc：`INHERIT_VFUNCS` 第 4 位 `generate_func_sig=False`，同时从 `GENERATE_YAML_DESIRED_FIELDS` 去掉 `"func_sig"`。
- 这是仓库既有约定：全部 60 个 `gen=False` 条目都不含 `func_sig` 字段（只置 False 而不删字段，会让旧 sig 被 carry-forward 保留下来）。
- 工具侧兜底（#953）：fast path 命中后校验 resolved `vfunc_index` 是否等于继承的 `vfunc_index`，不等则丢弃并退回 index-based（`_read_inherited_vfunc_index`）。
- Windows 与 Linux 函数体长度可能不同（MSVC vs Itanium ABI），而 flag 跨平台共享；判定口径按维护者：以 Windows 反汇编 ≤4 条为准。
- 已知例外：`CGameEventManager_FireEventClientSide`（Windows 165 条 / Linux 3 条）与 `CEngineClient_ExecuteClientCmd`（Windows 9 条 / Linux 4 条）只在 Linux 侧是跳板，未按此规则处理。

## 验证方式
- 重跑对应 skill（先删 artifact 再跑，否则会 "all outputs exist" 跳过）：日志出现 `Preprocess: generated <name>.yaml`。
- 期望 diff：artifact 只少一行 `func_sig`，`func_va`/`func_rva`/`func_size`/`vtable_name`/`vfunc_offset`/`vfunc_index` 不变。
- `uv run python tests/run_test_suite.py unit`；`uv run python run_cpp_tests.py -snapshot <candidate> -gamever <ver>`。

## 适用范围
- 仅限 `INHERIT_VFUNCS` 的 inherited vfunc（`preprocess_common_skill` → `preprocess_index_based_vfunc_via_mcp` 路径）。
- 有真实函数体的（≥6 条指令）仍保留 `func_sig`。
- 14180 审计结果：141 个 INHERIT_VFUNCS 条目（138 个在 14180 有调度），`generate_func_sig=True` 的 81 个中 Windows 函数体 ≤4 条的共 9 个，已全部改为 False。

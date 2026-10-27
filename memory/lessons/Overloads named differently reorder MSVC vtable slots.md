---
title: Overloads named differently reorder MSVC vtable slots
type: lesson
permalink: cs2-vibesignatures/lessons/overloads-named-differently-reorder-msvc-vtable-slots
tags:
- cs2vibesignatures
- cpp-tests
- vtable
- abi
- msvc
- itanium
- s2sdk
- overload
---

# 同名重载决定 MSVC 槽位顺序：拆开命名会让整个尾段错位

## 触发信号

- cpp_tests 报 `Reference index N from engine/<Class>_<Func>.yaml expects '<Name>', but compiler reports 'unk001'`，
  且差异只出现在一处，前后槽位名字全部对得上。
- 或者反过来：把 `unk001` 这类占位名改成真实语义名之后，本该出现的差异消失了，但**槽位总数与具名槽位仍全绿**。
- 典型场景：SDK 里同一类有两个语义相关的虚函数，其中一个还是占位名，另一个已经有 reference artifact。

## 根因 / 约束

MSVC 会按**声明名**对虚函数分组排序，而 Itanium（GCC/Clang）按**声明顺序**排列。因此两个函数
**同名（重载）**还是**异名**，会得到不同的槽位布局：

`CServerSideClientBase` 实测（MSVC，dump 含 RTTI 槽）：

| SDK 声明 | dump 49/50/51 | 解析后（去 RTTI） |
|---|---|---|
| `unk001(CUtlVector&)` / `SendInitialSpawnGroups` / `SendServerInfo(Build...)` | 49 unk001(collector) 50 SendInitialSpawnGroups 51 SendServerInfo(Build) | 48 unk001 / 49 Group / 50 SendServerInfo |
| **两个都叫 `SendServerInfo`** | 49 SendServerInfo(Build...) 50 SendServerInfo(collector) 51 SendInitialSpawnGroups | **48 SendServerInfo(Build)** / 49 SendServerInfo(collector) / 50 Group |

引擎的 reference artifact 把 `CServerSideClientBase_SendServerInfo` 定在 **index 48**
（Windows `0x1800c7030` / Linux `0x5497d0`，函数体内序列化 `SV_SendServerinfo->msg` 与
`BuildServerInfoMessageAsync_t` 消息链）。只有两个重载**同名**时，编译器才会把这个
「发 server info」的重载排到 48；只改其中一个名字，它会被推到 50，48 让位给 collector。

所以：SDK 里那对虚函数共享名字不是命名偷懒，而是**ABI 的一部分**。

### 二次陷阱：同名会让名称校验失去分辨力

`cpp_tests_util` 的比对只看 `vfunc_index -> member_name`。两个重载同名后，index 48 无论指向
哪个重载都会「名字相同」，比对必然通过。**绿色结果不再证明槽位语义正确**，必须回到 dump 或反编译
确认 index 48 落到的是期望的那个重载。

## 正确做法

1. 改占位名之前，先 dump 一次当前布局，记录目标 index 上是哪个重载：
   ```bash
   clang++ --target=x86_64-pc-windows-msvc -std=c++20 -c cpp_tests/<test>.cpp -o /tmp/x.o \
     -Icpp_tests/stubs -Is2sdk/game/shared -Is2sdk/public -Is2sdk/public/tier0 \
     -Is2sdk/public/tier1 -Is2sdk/public/mathlib -Is2sdk/common \
     -DCOMPILER_MSVC=1 -DCOMPILER_MSVC64=1 -fms-extensions -fms-compatibility \
     -Xclang -fdump-vtable-layouts | grep -E "^\s+(4[5-9]|5[0-2]) \|"
   ```
   注意 dump 索引含 RTTI 槽，解析后要 **-1**。
2. 若两个函数在引擎里相邻且语义成对，优先**共享同一个名字**（同时改两个），而不是只改占位名。
3. 若确实要异名，必须同时核对目标 index 与 `SendInitialSpawnGroups` 等邻近槽位是否整体平移。
4. 名字确定后用 `OUTPUT_NAME_MAP` 更正 artifact 的 `func_name`（保留 artifact 路径身份），
   见 [[docs/cpp-abi-reference-validation]] 的 14192 corrections。

## 验证方法

- Windows + Linux 双平台跑 `run_cpp_tests.py --platform <p>`，全量 0 differences **只是必要条件**。
- 对同名重载这一类，额外用第 1 步的 grep 确认 dump 中目标 index 落在期望重载上，
  并记录到 PR 描述里作为证据。
- Linux 侧可用 WSL；给 uv 单独指定 `UV_PROJECT_ENVIRONMENT`，否则它会覆盖 Windows 的 `.venv`。

## 适用范围

- 任何 SDK 头文件里存在重载虚函数、且其中一个仍为 `unkNNN` 占位名的类。
- 主要影响 MSVC 目标（`x86_64-pc-windows-msvc`）；Itanium 目标按声明顺序排，通常不受同名影响，
  但**两侧仍需各自验证**。
- 同样适用于 `CServerSideClientBase` 之外的类：只要 reference artifact 按 index 记录 vfunc，
  槽位顺序就是契约。

## See also

- [[cpp_tests_util]] — 比对只校验 reference 声明的 index 与名字。
- docs/cpp-abi-reference-validation.md 的「14192 corrections」一节。

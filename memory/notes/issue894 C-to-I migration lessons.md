---
title: issue894 C-to-I migration lessons
type: note
permalink: cs2-vibesignatures/notes/issue894-c-to-i-migration-lessons
tags:
- issue894
- pattern-f
- llm-decompile
- inetworksystem
---

# issue894 C-to-I 迁移经验

## 触发信号
- 需要把 Pattern B/C 的具体类 vfunc finder 迁移为 接口层(Pattern C slim) + 具体类层(Pattern F) 双层结构
- 在 engine2.dll 中寻找 INetworkSystem 接口调用证据

## 关键事实（14178b Windows）
- g_pNetworkSystem (engine2.dll win) = `0x180688d00`；第二接口副本 = `0x180612C98`（registry 写入，sub_180205940 引用 "NetworkSystemVersion001"）
- Linux engine2 只有具名 `g_pNetworkSystem`（接口指针表 0xc74200 区），加载模式为 `lea rax,[g]; mov rdi,[rax]; mov rax,[rdi]; call [rax+disp]` 两步解引用；尾调用是 `mov rax,[rax+disp]; jmp rax`（无法生成唯一 vfunc_sig）
- Windows 的 `mov rcx, cs:g` 单步模式扫描要匹配 o_phrase（无位移基址 `[rcx]` 是 type 3 不是 o_displ 4）
- engine2.dll 里 12 个 INetworkSystem 方法中：10 个有真接口调用；RemoveNetChannelByAddress 和 CloseAllSockets 无任何模块的接口调用证据（CloseAllSockets 仅被 CNetworkSystem::Shutdown this 直调；InitGameServer 里 0x1800f8313 的 0xC0 调用接收者是 g_pNetworkServerService——寄存器链假阳性陷阱）

## 正确做法
- 双平台前驱不要求同名同函数：接口 finder 可按 platform 分支 LLM_DECOMPILE spec；或接口层 platform: windows + 具体类拆 -linux 后缀保留原 Pattern B（仓库已有 -linux/-windows 拆分先例）
- LLM reference 无目标虚调用标注时 LLM 会猜错槽位（RemoveNetChannel 猜成 0xB0/21，实际 0xB8/23）——每个接口前驱 reference 必须双字段标注目标 vcall
- Pattern F 输出的 vtable_name 是纯类名（CNetworkSystem），旧 Pattern B 写 CNetworkSystem_vtable——迁移后产物该字段变化是预期差异
- generate_reference_yaml 每次调用自启停 IDA；手动 idalib-mcp 会话会锁住 bin/**.i64（.id0 锁文件），跑 ida_analyze_bin 前必须先杀实例并删 .id0

## 验证方式
- 对照旧 artifact 的 func_va/vfunc_index 全量 MATCH（Pattern F 与原独立定位一致性）
- 平台限定的 skill 在另一平台显示 "Skipping skill ... platform 'x' != 'y'"

## 适用范围
CS2_VibeSignatures 的 finder 迁移、接口槽位证据调查


## 教训：Pattern F fallback 无校验复用旧 func_sig（issue #937，修复 7bcc84b7）

### 触发信号
- selected rebuild / validate-full 报某个产物 drift，且 actual 内容 = prior gamever 同名产物的逐字节拷贝（含过期 func_sig），但磁盘各层（.so、binary lock、IDB payload、workspace .i64）校验全部干净。

### 根因 / 约束
- `preprocess_common_skill` 的 inherit_vfuncs 流程：fast path `preprocess_func_sig_via_mcp` 用 `_find_unique_match`（find_bytes limit=2, n==1）严格校验旧 func_sig，失败后 fallback `preprocess_index_based_vfunc_via_mcp` 会在 step 6 **无校验地**把同一份旧 func_sig 拷回输出——被 fast path 拒绝的签名被"复活"。
- 修复语义（7bcc84b7 起）：fallback 在 `generate_func_sig=True` 时总是走 `preprocess_gen_func_sig_via_mcp` 从当前 IDB 生成；`generate_func_sig=False` 的调用方保持旧签名 carry-forward。**跨版本复用只允许发生在经过唯一性校验的 fast path。**

### 正确做法
- 任何"复用旧 artifact 字段"的代码路径都必须先在当前 IDB 上验证（唯一匹配 + 匹配地址一致），否则重新生成；不允许 fallback 悄悄 resurrect 上游已拒绝的数据。
- 复现 PR CI 的 selected rebuild 失败时，必须用 **PR 分支树**（skill 脚本 + configs + bin_artifacts 三者都要是 PR 形态）+ `-oldartifactdir bin_artifacts` 跑。此前所有本地复现失败的原因：working tree 停在 main 基分支，skill 脚本还是旧 LLM_DECOMPILE 形态（无 inherit_vfuncs），buggy fallback 根本没被执行。

### 验证方式
- 单技能 A/B：pre-fix 输出 sha256 == runner drift 产物（d7c9a47d...），post-fix == Git blob（73a49914...）即闭环。
- 回归测试在 `tests/test_ida_analyze_util.py`（TestPreprocessIndexBasedVfuncViaMcp，3 个新用例）。

### 适用范围
- 所有 inherit_vfuncs / 跨版本 func_sig 复用逻辑；将来给 fallback 增加任何 old-yaml 字段复用时同样适用。


## 教训续：修复暴露 Git 潜伏 stale 签名 + 本地全量复刻方法（issue #937 后续，692a4d61）

### 触发信号
- 修复 fallback 后 validate-full 仍 drift，但 drift 文件换了，且 diff 只有 func_sig 一行、全是 RIP disp32/rel32 差异，func_va/size/vtable 元数据不变。

### 根因
- 老的 buggy fallback 曾把过期签名写进 Git 产物（bootstrap 时期），Git 与 buggy 重建自洽所以历史上 verify 全绿；修复后重建生成真实签名 → 暴露 Git 中的潜伏 stale 副本。判定方法：`Git(14178b) func_sig == 14178 旧产物 func_sig` 即 stale-copy 来源。这类签名在真实二进制里 relocate 不到任何东西，必须按固定管线输出更新 Git。

### 本地全量复刻 runner selected execution 的方法
- 从 planner artifact（trusted-source-artifact-plan.json）的 `game_versions[gamever]` 提取 execute_nodes/groups/inherit_paths，构造 manifest：`schema_version=1`、`execution_strategy=base-inherited-selected-v1`、`config_sha256=_sha256_file(config)`（**带 `sha256:` 前缀**）、`manifest_sha256=_selected_manifest_digest(unsigned)`；plan 的 `merge_config_sha256` 是规范化哈希，不能直接用。
- 单次大跑（2265 节点）在本地会因 MCP 连接 churn 耗尽临时端口（WinError 10048，默认范围 49152-65535 仅 16k）级联失败。对策：**分模块+平台批处理**——非 selected 模式，artifact root 用 Git 全量预填充的累积目录，每批只删该 (module, platform) 的闭包输出，skip 逻辑只重建缺失件；批间 sleep 让 TIME_WAIT 恢复；批按 manifest stage_index 排序保证下游先用重建产物。
- TaskStop 杀掉的运行会留 idalib_server 孤儿进程与 `.id0` IDB 锁：先 `Get-CimInstance ... idalib_server` 杀进程，再删残留 `.id0`，否则下一批报 "IDB lock file detected"。
- agent-fallback 类 optional skill（如 IsMapValid）本地无 agent 不产出，属预期缺失；runner 上由 agent 产出且已验证。

### 验证方式
- 已知 drift 文件本地重建 sha == runner actual（如 05f3dd4f）即证明复刻保真；全闭包 3560 输出与 Git 比对应为 identical + 少量单行 func_sig 差异 + 3 个 agent optional 缺失。

### 适用范围
- 任何需要本地预演 CI validate-full / selected rebuild 的场景；跨版本签名复用相关的 Git 产物审计。
# CS2_VibeSignatures:full validation 耗时过长问题交接文档

- 日期:2026-09-06
- 仓库:`HLND2T/CS2_VibeSignatures`(本地 `D:\CS2_VibeSignatures`,本讨论时分支 `dev-CGameResourceService_AllocGameResourceManifest`,HEAD `d2cb49c5`)
- 当前状态（2026-09-07）：selected 能力与跳过缺陷修复已实施；Phase-D 通过原运行和单节点跨运行续验完成，独立策略更新启用 selected。下文第 1–17 节保留历史分析与迁移过程，最新证据见第 18 节。

---

## 1. 问题陈述

PR / Merge Queue 的 full validation 中,`pr-self-runner.yml` 的步骤
**"Execute every producer group from an empty artifact root"** 耗时 ~2 小时,严重拖慢所有 full 模式 PR 与 merge queue 复验。

实测数据(GitHub Actions job step 元数据):

| Run | 事件 | 该步骤耗时 | 备注 |
|---|---|---|---|
| 33973053680(2026-09-05,成功) | merge_group | **15:05:57 → 17:04:19 ≈ 1h58m** | 占整个 validate job(2h07m)的 93% |
| 34006334075(PR #900,进行中) | pull_request_target | >1h(观察时仍在跑) | 日志已过期,仅 step 元数据可取 |

放大因素:
- merge queue 会对**同一棵树再跑一遍**(pr-validate merge_group 复验);
- `validate-full` 矩阵 `max-parallel: 1`;
- 每个 full PR 实际占用约 **4 小时串行自托管 runner 时间**。

## 2. 背景:this step 在做什么(不要轻易推翻的设计前提)

信任模型(已与维护者确认接受,优化**不应**破坏):

- PR 里 staged 的 `bin_artifacts/**` 是作者交付物;CI 的职责是从**空根**重新推导**全部**产物,与 merge 树的**完整** inventory 逐字节比较(`trusted_artifact_pr.py` 的 `validate_isolated_rebuild`,约 :1076-1099:set 相等 + size/sha 逐文件 + expected blob 物料化复验)。
- 强制空根:`ida_analyze_bin.py:4654` `validate_force_all_artifact_root`(必须为空、checkout 外、不穿 reparse point);`-force_all` 禁用"输出已存在即跳过"(:3478)。
- planner 的细粒度失效选择(`gamesymbol_snapshot_lib/pr_validation.py:294` `build_invalidation_plan`)只作为**验证期望**(执行覆盖、winner alternatives、输出哈希,`trusted_artifact_pr.py:1015-1043`),**不缩小执行范围**。
- 为什么不从 main 的可信 `bin_artifacts` 起跑(增量种子):会产生"作者工具链与 CI 同源漏判 → 静默通过"的相关性盲区;空根全量重放使"main 上每个字节当前可再现"成为每次运行自证的不变量。
- `main` 的 artifacts 已被用于**加速而非证据**:`-oldartifactdir bin_artifacts` 仅做 signature reuse;`-require_warm_idb` + 不可变 warm IDB 缓存掉 IDA 自动分析(恢复仅 ~50s)。
- 合并后另有 `build-on-self-runner.yml` **独立全量重建** + Release 前 fresh rebuild——这是重要的兜底,方案二/三的安全性依赖它。

## 3. 根因(代码定位)

规模与执行模型:

- `ida_preprocessor_scripts/find-*.py` 共 **1134** 个;`configs/14178b.yaml` 13 modules / **1174 skills**;windows+linux 双平台 ≈ **2348 次技能执行**;26 个 module×platform 的 IDA/MCP 会话。
- 执行驱动 `_execute_analysis`(`ida_analyze_bin.py:5070`)是**纯串行双重循环**:`for module in modules: for platform in args.platforms: _process_platform(...)`。每个 job 内技能也串行(同一 MCP 会话,断线恢复,:3742-3765)。
- 平均每技能 ~3s(含摊销的会话加载)→ 2348 × 3s ≈ 2h。
- **关键发现**:`_build_execution_plan`(`ida_analyze_bin.py:2570-2620`)已经构建了 stage/job/依赖边(stages、jobs、nodes、edges、跨 stage artifact 边),但执行器完全没用它——依赖图建了没用上。

## 4. 已讨论的方案(按推荐顺序)

### 方案一:stage 内并行执行(推荐先做;零信任模型变化)
- 把 `_execute_analysis` 改为依赖感知调度:同 stage 的 module-platform job 并行(受 `-max_parallel` 与 runner 内存约束),stage 间保持串行(跨 stage artifact 依赖边已存在),job 内技能仍串行(alternatives 竞争语义不变,见 :4008-4015 "modified output already produced by an earlier alternative" 判失败逻辑)。
- 预期:4-8 个并行 IDA 实例 → 2h → **~20-35min**(下界受最大单 job 制约,engine 模块可能是长尾)。
- 风险:自托管 runner 内存(N × IDB 大小);force-all 报告确定性(记录按 key 索引、报告构建时排序,需验证无顺序依赖)。
- 最简子集:先并行同 module 的 windows/linux → 立刻 2×。
- 实施建议:先补调度正确性测试(stage 依赖不被违反)再改实现。

### 方案二:内容寻址 producer 缓存(结构性修复)
- 每组缓存键 = binary lock sha + warm IDB generation + module/skill 配置片段哈希 + 预处理脚本 + reference 输入 + 共享运行时哈希 + 输入产物哈希;值 = 规范输出字节 + 执行证据记录。
- 命中→物料化字节 + 回放证据;未命中→推导。**完整 inventory 逐字节比较保持不变**;merge queue 对同一棵树复验变全命中(分钟级)。
- 信任代价:键完备性成为新信任面。兜底:(a) 共享运行时变更已被 plan 强制全量失效→强制 miss;(b) 合并后 `build-on-self-runner` 全量重建 + Release fresh rebuild 最迟在发布前抓住漂移。
- 效果:PR #900 这类"新增符号"PR 从 2h → **分钟级**;全量成本转移给本来就存在的合并后重建。
- 工作量:大(缓存存储、执行证据 schema 增加 cache-hit 类型、`trusted_artifact_pr.py` 验证端接受搬运证据、`validate_isolated_rebuild` 的 "selected producer group was not executed" 检查需为缓存命中定义合法路径)。

### 方案三:PR 时只跑 plan 选中组,其余从 base Git blob 物料化(方案二的无缓存简化版)
- 最便宜,但重新引入第 2 节所述相关性盲区,漂移要等合并后重建才暴露。仅在一、二都不可行时考虑。

### 顺手项
- workflow 里 `ida_analyze_bin.py ... -debug` 可去掉(2348 次技能的日志开销),预计小头。

## 5. 相关近期变更(避免接手模型困惑)

- 本分支已有提交 `445e7312`:"ci(source-artifact): derive full-mode matrix from trusted plan affected versions"——full 矩阵已从硬编码 `["14178b"]` 改为 plan 派生(planner 侧 `maintained_versions` 单例保证 full 模式恒等于最新 GAMEVER,`trusted_artifact_pr.py:549`)。与本性能问题正交。

## 6. 关键文件/符号索引

| 位置 | 内容 |
|---|---|
| `.github/workflows/pr-self-runner.yml:157-165` | "Execute every producer group" 步骤与命令行(`-force_all -require_warm_idb -debug`) |
| `ida_analyze_bin.py:5070` `_execute_analysis` | 串行执行驱动(改造目标) |
| `ida_analyze_bin.py:2570-2620` `_build_execution_plan` | 已有 stage/job/edges 依赖图 |
| `ida_analyze_bin.py:4654` `validate_force_all_artifact_root` | 空根强制 |
| `ida_analyze_bin.py:4719` `build_force_all_execution_report` | 执行证据报告 |
| `trusted_artifact_pr.py:892` `prepare_isolated_rebuild` | staging 准备与 gamever 绑定 |
| `trusted_artifact_pr.py:~1050-1105` | force-all 报告校验 + `validate_isolated_rebuild` 完整比较 |
| `gamesymbol_snapshot_lib/pr_validation.py:294` | 细粒度失效计划(验证期望来源) |
| `.github/workflows/source-artifact-required.yml` | 门禁 workflow(bind-source-artifact-plan 路由) |

## 7. 待决问题

1. 方案一先行是否可接受?自托管 runner 的核数/内存上限是多少(决定并行度上界)?
2. engine 模块单 job 耗时占比(并行后的长尾)——需要一次分模块耗时统计(本地跑一次或给执行报告加 per-job 统计)。
3. 方案二的缓存键粒度:config 是单文件,per-group 键需要"逻辑配置片段"(即失效计划的映射),是否复用 `build_invalidation_plan` 的内部结构?
4. 是否接受方案二的"PR 时盲点由合并后全量重建兜底"这一策略放宽?

---

## 8. 已确认决策与迁移范围

- 日期：2026-09-06。状态：设计，代码/schema/workflow 尚未实施。
- 用户接受最简方案三：信任绑定的 base Git tree，不等待其全量验证，允许连续继承尚未发现的问题。
- 以下设计替代第 2 节中“PR 每次空根执行全部 producer”的前提，发布前全量要求不变。
- 不实现 producer 缓存、并行调度、自动修改 artifacts，不改变维护 GAMEVER 范围或减少下游验证。

正式保证：PR 强制重建可信计划的执行闭包，其余合法产物仅从准确 base Git blobs 继承；组合后的完整 inventory 必须与 prospective merge tree 完全一致。PR 不再证明所有继承产物当前可重新生成。

executed 是本次执行证据；inherited 只是来源及未改写证明，不得冒充 executed/cache-hit。planner 漏判源码影响且作者保留旧输出时，错误可能进入 main 并连续继承。完整字节比较不能补偿此盲区。不要求 base attestation，不因 base 未审计而等待或自动全量。

## 9. 契约与计划

保留 `mode=full` 的自托管路由含义，新增独立 execution_strategy，拟议为 base-inherited-selected-v1 / fresh-full-v1。未知策略/schema 或缺少身份字段必须失败，不能静默采用增量。

plan 绑定 base SHA/tree、head SHA（适用时）、merge SHA/tree、GAMEVER、策略、配置、binary lock、执行和继承清单摘要。warm IDB generation 在运行时解析后绑定 preparation/execution，并验证 binary/runtime 匹配。摘要不是签名，可信来源仍依赖 base-owned bridge 和现有计划重算边界。

每个版本的计划保留 base_artifacts/merge_artifacts，并明确划分：

1. execute_groups：完整执行组。
2. execute_nodes：稳定 ID 的 alternatives/prerequisites 与顺序。
3. inherit_paths：base 现存输出及 blob SHA、size、SHA-256。
4. inherited_absent_groups：base/merge 均合法缺席的未执行 optional 输出。
5. removed_paths：base 存在但 merge 契约已移除的输出。
6. selection_reasons：失效、闭包扩展、全量回退原因。

可信工具推导，verifier 检查精确覆盖、互斥和完整性。继承必须满足：属于 merge 契约；不属于实际执行节点可能写的输出；base 是合法普通 blob；base/merge 的 blob、size、hash 相同；producer 及已声明依赖未失效；没有全量条件。

- 字节不同却未选 owner：计划失败，不能从 merge 补 actual。
- 新 required 输出必须执行；新 GAMEVER 全量且保持 bootstrap 规则。
- optional 存在/缺席变化必须执行对应组。
- 已删除契约输出不运行旧 producer、不物料化旧 blob，最终验证缺席。
- 未知依赖可保守 full；非法路径/产物/身份漂移必须失败。

## 10. 闭包与执行语义

先审查 build_invalidation_plan 与 _selected_groups，不能假定现有 affected_producer_groups 已是完整执行范围。

正确性闭包迭代到固定点：失效节点扩展整个 group；执行节点写多个输出时扩展全部对应组；新增输出传播下游；新增节点再次扩展 group/多输出。任何实际执行节点可写的输出都不能继承。

依赖区分：纯 artifact-byte 上游未失效时可继承；session prerequisite 依赖同一 IDA 会话的初始化/命名等副作用，必须实际执行；不明依赖保守扩大乃至 full。prerequisite 若写正式输出，将其移出继承集合并重算下游；无输出 prerequisite 也要执行证据。

保留 stage、module/platform 会话边界和 alternatives 顺序/winner 规则。加载完整配置，以稳定 ID 选择任务，避免裁剪配置造成编号或 fingerprint 变化。

保留共享 analyzer/serializer、binary/download identity、新 GAMEVER、output contract version 全量失效。审查环境/依赖变更覆盖，不能精确映射时保守 full。不改变 fork、可信根、维护范围、bootstrap、未知路径的 fail-closed 行为。

## 11. 隔离物料化与执行器

保留 `-force_all` 原义：checkout 外空根、全部 producer、full 报告。新增独立 selected 模式和 seeded-root validator，不能放宽 validate_force_all_artifact_root。

Preparation 顺序：

1. 验证可信 plan 和准确 Git 身份，创建唯一全新 checkout 外 staging。
2. expected-root 从 merge blobs 物料化，仅用于比较；actual-root 从空目录开始。
3. actual 仅按 inherit_paths 白名单从准确 base blobs 原样写入，不重新序列化，写入前后核验 blob/size/hash。
4. 确认执行输出、removed_paths 和合法继承缺席路径均不存在。
5. 记录初始 inventory、继承清单、策略、plan 及运行身份。

不要复制整个 base 再删除，不从工作树、accepted-bin、持久化 workspace 或 expected-root 补实际输出。保留路径规范化、祖先/子路径 reparse point、越界、证据路径和 checkout 未改写检查，安全要求不得弱于 full。

selected 强制执行计划节点，不因输入/输出存在或历史状态跳过。只为有任务的 module/platform 启动 IDA。保留 alternatives 的真实尝试、winner 和禁止后续 alternative 改写已获胜输出的规则。

允许读继承输入，只允许写授权输出。利用 attempted/produced 记录或适当写入检测发现未授权写入，并校验继承项前后状态；hash 前后相等不能单独证明从未写入，不得宣称它提供完整写隔离。继承项改写/删除、继承缺席被创建、额外文件均失败。

`-oldartifactdir` 如保留，仅保持现有 signature reuse，不增加复制旧输出兜底。失败/中断不得生成 valid=true；重试使用新 staging，不复用残留输出。

## 12. Schema、证据与可信验证

当前定位时 plan schema=3、preparation schema=2、force-all execution schema=2；实施时重新确认。升级 plan/preparation，selected 使用独立报告类型或显式 schema；旧 full 语义保持用于 release，不能原地重解释。

- executed：group/fingerprint/alternatives、真实 attempted 节点、winner、输出 hash 或合法缺席，以及 prerequisite 结果。
- inherited：可信 preparation/verifier 从 base 独立推导 base SHA/tree、path/blob/size/hash、物料化前后状态和 optional 缺席，不能仅信执行器声明。

最终验证：

1. schema、策略、摘要、plan/preparation/report/tree/binary/warm generation 绑定正确。
2. 精确执行集合与节点证据正确，拒绝缺组、重复、未授权额外组和错误 attempt/winner。
3. 继承资格、base 字节身份、缺席状态和 removed_paths 均正确。
4. 使用完整 merge 契约构建 actual inventory，保持完整路径集合相等、逐文件 size/SHA-256 比较。
5. 保留 expected Git blob 物料化复核、execution inventory 对照、checkout 未改写检查。
6. 结果明确策略、执行/继承/删除数量和证据摘要；每个合法输出状态恰好得到一种解释。

snapshot/gamedata candidate 与 C++ ABI 验证继续消费完整 actual-root，不只验证选中符号。full/release verifier 必须拒绝 selected 证明。

## 13. 工作流与发布兜底

PR 改为 trusted prepare → base 白名单物料化 → selected execute → 完整 verify → 原 downstream gates → 上传证据。保持无发布权限及可信路由，step/日志不再宣称 every producer / empty-root full rebuild。

无执行节点但仍需下游验证时不启动 IDA；无需分析的变更保持现有路由。merge queue 重新绑定自己的 base/merge tree，不复用 PR 计划，也不等待 base 审计。

发布目标准确 source SHA 必须通过 fresh-full 和不可变 Git truth 比较，不能用 selected 报告、其他 SHA 或旧 inventory 替代。失败时禁止 BinSync/Release 发布并告警，保留诊断，不自动修改 Git artifacts 掩盖漂移。

最简策略下，审计失败不追溯改变已结束的 PR 检查，也不自动要求后续 PR 等待；全局可再现性不再是 PR 保证。

必须核实 post-merge 触发链：build-on-self-runner.yml 自身入口为 workflow_call/workflow_dispatch/repository_dispatch，不是直接 on:push。追踪真实调用方、过滤条件、告警和准确 source SHA 绑定，不能仅凭该文件断言每次 main 合并都有审计。覆盖缺口应补齐调度或明确记录真实范围；发布前 fresh-full 是不可放宽的硬门禁。

## 14. 文件落点与分阶段迁移

以下为本次定位，实施时按符号重新定位，不依赖旧行号：

- gamesymbol_snapshot_lib/pr_validation.py:294：失效与闭包；config.py/model.py：检查 group、多输出及 prerequisite 表达，仅必要时调整。
- trusted_artifact_pr.py:550：可信根门禁；:721：版本计划；:892：准备/继承；:972：报告策略；:1044：完整组合验证。
- ida_analyze_bin.py:4654：保留 full root validator；:4719：保留 full 报告；_build_execution_plan/_execute_analysis/skill 路径新增 selected 调度与证据。
- .github/workflows/pr-self-runner.yml:136：prepare/execute/verify/上传。
- .github/workflows/source-artifact-required.yml、trusted_pr_context.py：可信计划传递、策略和迁移桥。
- .github/workflows/build-on-self-runner.yml:300、:331、:514：fresh rebuild、Git truth 比较和发布依赖。

### 阶段 A：基线与契约

读取当前项目规则、相关 memory、可信调用链和待改代码；记录相关测试基线及真实审计覆盖；确认 prerequisite/多输出语义；先补行为测试，落地 plan/verifier 能力，默认仍 fresh-full。

### 阶段 B：执行器与组合证明

实现固定点闭包、继承资格、白名单物料化、selected 执行和独立报告。验证 full/release 无回归，release 拒绝 selected 报告。实现期间保持应用层参数与可信验证策略显式分离。

### 阶段 C：可信桥迁移

现有 planner 拒绝普通 PR 修改 trusted roots，要求 independently merged bridge update。不能假定同一个业务 PR 能修改 planner/workflow 并用自己的新规则验证自身。

先沿现有受信维护流程独立合入 bridge/schema 支持，保持 full 默认；analyzer/verifier 均就绪后再启用 selected 路由。核对旧 base 的可信工具、复用 workflow 和新 schema 兼容性，保证每次合入都可运行。未知 schema 明确失败。若没有可用维护流程，向维护者确认，不删除 trusted-root 门禁绕过。

### 阶段 D：真实验证与启用

选新增符号、finder 修改、跨 stage 依赖、artifact-only、共享运行时变更样本；在相同 tree/binary lock/warm generation 下运行 selected 与 fresh-full，对比完整 inventory、执行证据和时延。此为迁移验证，不要求后续每个 PR 永久双跑，也不能证明 planner 永远完备。

确认发布 gate 与告警后切换。记录执行组数、IDA 会话数、producer/恢复/下游/总耗时。不预先承诺分钟级，固定成本和闭包范围会限制收益。

### 回滚

通过可信路由切回 fresh-full，使用新空 staging 和原 full verifier。不要把 seeded root 交给 force-all，不改作者 artifacts，不删除历史证据，不接受旧 schema 绕过失败。

## 15. 测试与完成门禁

本次涉及共享正确性边界和显式行为变更，采用 Level 2 TDD，加代码审查与 completion verification。测试运行行为，不对 workflow、配置、文档或 memory 文本做字符串约束。

### 行为测试矩阵

- 计划：未变更继承；artifact-only 选 owner；finder/reference/config 变化和删除/重命名传播；alternatives/多输出新增下游达到固定点。
- 依赖：字节上游可继承，会话 prerequisite 实际执行；有输出 prerequisite 重新分类传播；未知依赖保守 full。
- 回退：shared runtime、binary lock、output contract version、新 GAMEVER 全量；bootstrap、维护范围和 fork 规则保留。
- 分区：不同字节未选 owner、未知 owner、集合重叠/遗漏拒绝；optional 存在/缺席变化及契约删除正确。
- 物料化：仅绑定 base 来源；执行输出起始缺席；残留 staging、错误 blob/size/hash、reparse point、越界、checkout 内输出和非法类型拒绝。
- 执行：已有输入不跳过节点；attempt/winner 正确；继承项改写/删除、继承缺席被创建、额外输出与未授权写入拒绝。
- 证据：缺组/重复/额外组、伪造 executed、未知策略/schema、plan/tree/binary/warm generation 漂移拒绝。
- 最终：完整 inventory 缺失/多余/字节不符、expected-root 改写拒绝；中断重试不误用旧报告；下游消费完整组合根；release 不接受 selected。

### 完成判据

1. 关键行为测试及 full/release 回归通过，报告实际命令和结果。
2. 真实 selected/full 对比及性能测量完成；环境无法执行则明确未验证，不宣称完整交付。
3. PR/merge queue 身份绑定、发布 hard gate、告警得到验证；真实审计覆盖缺口显式记录。
4. 文档和相关 Basic Memory 更新为新保证，纠正“PR 每次证明全局可再现”的旧表述，保留连续继承风险。
5. 所有关键未验证项和剩余风险显式交付。

## 16. 后续执行边界

- 用户已确认最简 base 信任，不再询问是否等待 base 全量验证。
- 本次仅整理文档；实际 schema/shared types/CI/配置与可信 bridge 改动按后续用户授权和仓库门禁推进。
- 不顺带实现方案一/二，不削弱发布 fresh-full。
- 核心审查点：组/多输出固定点、session prerequisites、独立继承资格检查、selected 证据不能冒充 full。

---

## 17. 实施状态（2026-09-06，分支 dev-base-inherited-selected）

状态：**阶段 A/B/C 代码与测试已实施；阶段 D 真实 runner 对比未执行；selected 路由未启用（policy 默认仍 fresh-full-v1）**。

### 已实施

- 策略契约：`source_artifact_policy.yaml` 新增可选键 `execution_strategy`（缺省 `fresh-full-v1`，合法值 `fresh-full-v1` / `base-inherited-selected-v1`）；`trusted_pr_context.py` 解析并写入 context；planner 从 base-owned policy 决定 plan 顶层 `execution_strategy`。
- plan schema 3 → 4：每 maintained GAMEVER 版本新增分区 `execute_groups` / `execute_nodes` / `inherit_paths` / `inherited_absent_groups` / `removed_paths` 与 `maintained` 标志；旧字段 `affected_producer_groups` / `selected_alternative_nodes` 移除（消费方同步：verifier、bootstrap 验证器、测试）。
- 执行闭包固定点（`_execution_closure`）：失效节点扩展其全部输出组、组扩展全部 alternatives 与下游组、执行节点反向扩展同会话 session prerequisites；分区函数对新输出、字节变化未选 owner、optional 存在性变化 fail-closed，并校验 execute ∪ inherit ∪ absent == merge 契约 formal_paths。
- preparation schema 2 → 3：selected 策略下按白名单从 base Git blobs 物料化继承文件到 actual root（写前 base blob 校验 + 与 merge 期望 blob 对照 + 写后复核），确认执行输出 / removed / 合法缺席路径不存在，记录初始 inventory digest，签发 `selected-execution-<gamever>.json` manifest（绑定 plan / config / 初始 inventory）；fresh-full 策略行为与旧版一致（actual root 为空）。
- executor（`ida_analyze_bin.py`）新增 `-selected_execution`：manifest fail-closed 加载（digest 域 `source-artifact-selected-execution-manifest:v1`）、seeded-root 校验（白名单精确、checkout 外、无 reparse）、按稳定 node_id 过滤技能、prerequisite 缺失 / 未知节点拒绝、与 `-force_all` / `-skill` / `-vcall_finder` / `-rename` / `-skip_error` 互斥；selected 模式下计划节点不因输出 / skip_if_exists 存在而跳过；执行后产出独立报告类型 `source2-selected-execution:v1`（schema 1，绑定 plan / manifest / 路径 / 初始 inventory，组级 attempted 前缀与 winner 证据）。
- 组合验证（`validate_isolated_rebuild`）：按策略分支加载报告；selected 要求报告组 / 节点集合与计划**精确相等**、每组与 merge 期望字节一致、报告回显 preparation 初始 inventory；额外从 base SHA 独立重推导继承 blob 并与最终 actual 字节比较，校验 removed / 合法缺席路径不被创建；最终仍做完整 merge 契约 inventory 精确集合 + 逐文件 size/SHA-256 + expected Git blob 物料化复核 + checkout 未改写检查。结果新增 `execution_strategy` 与 executed/inherited/removed 计数。
- workflow `pr-self-runner.yml`：prepare 输出 `strategy` / `selected-manifest`，execute 步骤按策略路由（selected：`-selected_execution ... -require_warm_idb`；full：原 `-force_all`）；step 名不再宣称 every producer / empty-root；去掉 `-debug`。
- release 侧不放宽：`release_artifact_rebuild.py` 维持 force-all v2 报告要求，selected 证据在 digest 域即被拒绝（已补测试）。

### 测试

全部通过：unit 1184/1184、repository-contract 71/71、release-integration 15/15；redis-integration 本地无 Redis 跳过（CI 会跑）。覆盖：未变更继承 / artifact-only 选 owner / prerequisite 反向闭包 / 共享运行时与二进制身份全量回退（继承为空）/ 契约移除输出 / 白名单物料化精确性 / selected verify 往返 / 继承字节漂移 / 漏执行组 / 报告组集合漂移 / 报告篡改 digest / full 策略空根 / staging 复用拒绝 / policy 策略解析与缺省 / manifest 篡改与结构拒绝 / root 白名单精确 / config 漂移拒绝 / 技能过滤 / 报告 winner 证据 / CLI 互斥 / release 拒绝 selected 证据。

### 启用步骤（阶段 C 剩余 + 阶段 D，未执行）

1. 本 bridge 合入 main 后，维护者通过受信流程把 `source_artifact_policy.yaml` 的 `execution_strategy` 设为 `base-inherited-selected-v1`（仅需 policy 单文件 bridge）。
2. 启用前完成阶段 D：在相同 tree/binary lock/warm generation 下对典型 PR（新增符号、finder 修改、跨 stage 依赖、artifact-only）双跑 selected 与 fresh-full，对比完整 inventory、执行证据与时延。
3. 回滚：policy 改回 `fresh-full-v1` 即回到全量路由（新空 staging、原 full verifier）。

### 真实审计覆盖核实（第 13 节要求）

`build-on-self-runner.yml` 入口为 `workflow_call` / `workflow_dispatch` / `repository_dispatch`，唯一仓库内调用方为 `tag-bump-after-merge.yml`，其仅在 `bump-download/*` 分支的 PR 合并（closed+merged）时触发 release 全量重建（publication_mode=publish）。**普通 main 合并不触发 fresh-full 审计**；全局可再现性兜底为：发布前 fresh-full（`release_artifact_rebuild`，硬门禁，不变）+ bump 合并审计 + 手动/事件触发。启用 selected 后，planner 漏判造成的漂移最迟在下一个 bump 合并审计或发布前 fresh-full 暴露；两次 bump 之间的普通合并仅有连续继承风险（用户已接受，第 8 节）。

### 未验证项（明确交付）

- 阶段 D 真实 selected/full 对比与性能测量未执行（需要自托管 Windows runner、IDA、warm IDB 与真实 14178b 二进制；本地环境不可用）。不宣称分钟级收益。
- merge queue 对 selected 策略的真实运行未演练（逻辑上 merge_group 重新绑定 base/merge tree，复用同一 planner/verifier 路径）。
- 本 bridge PR 自身因修改 trusted roots 会被现有 base planner 拒绝（`independently merged bridge update`），需维护者按受信流程合并——这是预期行为，未绕过。

### 评审修复（2026-09-06，PR #924 review 反馈）

1. Verifier 不再信任报告自报 `valid=true`：独立核验节点记录无重复、attempted 节点具有终态（succeeded/failed）、组 attempt 恰为基于 winner 的有序前缀、winner 必须成功产出该输出、节点 attempt/production 声明与组证据交叉一致、produced ⊆ attempted。
2. 超授权写入记录双层拒绝：executor 报告对 attempted/produced 超出节点授权输出的路径记 issue（valid=false）；verifier 独立以计划节点 outputs 校验报告记录——即使继承文件被原样重写且最终字节相同，凡记录了写入即拒绝（§11 的未改写要求；最终字节相等仍不宣称完整写隔离）。
3. 纯删除计划可执行：空 `execute_nodes`（契约删除 + 其余继承）为合法 manifest；executor 允许空模块集合继续组合验证（不启动 IDA），verifier/prepare 原本已支持零执行组。`-modules` 与 `-selected_execution` 显式互斥。
4. 无输出 session prerequisite 的独立执行证据:不属于任何 producer group 的计划节点(纯会话副作用前置)必须 `attempted=true` 且 **成功**(succeeded)——执行失败不能证明依赖者所需的会话副作用已建立,不沿用 alternatives 允许失败尝试的规则;组级校验不覆盖它们,缺失该检查时报告标 aborted/failed 仍可通过。
5. 合法 optional 缺席的 skip 被接受:executor 对"计划内 optional 生产者实际运行但未产出"记录 `status=skipped` 且 reason 为 `optional_output_absent` / `preprocess_absent`(报告本身 valid=true)。verifier 仅在该 skip reason 合法、节点零产出、且其 attempted 的每条输出路径**要么确实缺席于 merge tree,要么是它位于组内 winner 之前的合法回退让渡**(后一个 alternative 成功产出同一路径)时接受;其它 skip reason(existing_outputs、skip_if_exists、platform_mismatch 等)、已物化输出上的 skipped、以及 winner 之后的缺席声明一律拒绝。

## 18. Phase-D 临时维护入口（2026-09-06）

用户已授权新增独立手动 workflow，完成 Phase-D 后独立启用 selected 策略、rebase PR #926；临时入口在 #926 合并后清理。

- `.github/workflows/phase-d-validation.yml` 仅允许从 main 手动运行，绑定调用时的 main、准确 PR head 和双亲匹配的 prospective merge SHA；只接收同仓库的开放 PR。
- GitHub 可保留 PR 原来的 base/merge 快照，即使 main 已前进。维护工具固定为 dispatch 的 main SHA，样本固定为 PR 报告的 base/head/merge；另核验样本 base 是维护 main 的祖先，不要求两者相等，也不提前改写业务分支。
- `phase_d_validation.py` 使用生产 planner/prepare/executor/verifier，不改变生产策略解析或 required-check 路由。实验计划仅切换 strategy 并重新计算 digest，原计划与实验计划分别留档，报告明确标为迁移实验而非 PR attestation。
- PR #926 覆盖新增符号与 finder 修改；artifact-only、跨 stage、共享运行时样本通过隔离 Git index 构造临时 base/merge commits，不改工作树或分支。所有样本的 merge tree 完全相同。
- 每次分析前恢复同一个不可变 warm generation 并核验 source binary lock。三个小闭包 selected 样本、一次 fresh-full 基线及共享运行时全量 selected 样本分别执行生产完整字节 verifier、snapshot/gamedata 和 C++ gates。相同 tree/binary/generation 允许所有 selected 样本与同一次 fresh-full 基线作完整 inventory 比较。
- 真实分析显式设置 `CS2VIBE_STRING_MIN_LENGTH=4`（用户期望，避免 minlen=5 丢失短字符串锚点），并写入实验报告；不修改本机 `.env`。现有 unit suite 中两项测试依赖该变量未启用，基线测试以进程内空值隔离该本机覆盖，不能把这解释为分析应使用 5。
- 保存原计划、实验计划、preparation、warm restore、执行证据、完整验证、命令日志与各阶段耗时；失败也上传诊断，`comparison.json.valid` 仅在全部比较完成后为 true。此处尚不声明真实 runner 已验证。
- 发布流程仍由 empty-root `-force_all -rename`、`release_artifact_rebuild.py verify` 与 hosted verification 保护；publish jobs 依赖这些成功结果。当前工作流无独立外部告警发送步骤，失败通过 Actions job/check 呈现；个人通知订阅未核验。
- **清理门槛：PR #926 已合并。**届时删除临时 workflow、`phase_d_validation.py`、`tests/test_phase_d_validation.py`，移除 `tests/run_test_suite.py` 中对应归属；保留本交接文档、运行链接和汇总证据。不得在 #926 合并前清理入口。

### 启用前运行记录

- 临时维护入口通过 PR #928（`26ea0b2f`）合入；身份绑定修正通过 PR #929（`99bca9a3`）合入。
- 首次 run `34031579577` 在身份预检失败，未执行分析；GitHub 仍报告 #926 原 base/merge，修正为维护工具与样本身份分别绑定。
- 正式实验：[run 34031704261](https://github.com/HLND2T/CS2_VibeSignatures/actions/runs/34031704261)，绑定 #926 head `df457afa71313cd45d27ccaa9d1bd8f5187f0d61`、base `db8e615b01cd0e600b7288de96f4e6e359157774`、merge `b46ae7aae6e388ce3854ec02a82bbf4e57932e33`。已结束：前三个 selected 样本及 fresh-full 成功，共享运行时 selected 样本在最终证据检查失败。
- 本地真实树规划预演通过：PR 样本 6 组 / 6 节点 / 3520 继承；artifact-only 3 / 3 / 3523；跨 stage 14 / 10 / 3512；共享运行时 3529 / 2235 / 0。跨 stage 源为 `find-CLoopModeFactory_CLoopModeGame_Shutdown-decompiles.py`。
- 临时脚本固定执行五轮：三个小闭包 selected、一个 fresh-full、一个共享运行时全量 selected。**其中两轮为全量，按历史单轮约两小时估算，整个迁移实验为数小时规模。**每轮后的 downstream 检查也被重复执行；当前入口把全部轮次放在一个 Actions step，未结束时 REST 日志不可读，进度可见性有限。
- 本地回归：unit 1192、repository-contract 83、release-integration 15 通过；unit 以进程内空值隔离本机字符串最小长度覆盖，真实分析保持用户要求的 4。actionlint、仓库格式检查及新增行为测试通过。

### 单节点续验（2026-09-07）

- 失败根因：`process_binary` 在 IDA 会话中的第二次 `skip_if_exists` 检查遗漏 `not force_all` 条件，导致 selected 模式已经授权的 `7:241:server:linux:find-CFlashbangProjectile_Spawn_NetworkStateChangedNotify` 未执行。报告为 2195 succeeded、40 skipped，其中仅该节点为 `skip_if_exists`；完整文件比较也仅缺少对应 Linux YAML。
- 原 fresh-full 报告为 valid=true、2196 succeeded，且没有 `skip_if_exists` 节点。三个小闭包的 3526 个文件与 full 基线完全相同。PR 样本 producer 109.578 秒、总计 466.687 秒；full producer 7204.719 秒、总计 7604.359 秒（总计均包含 prepare/restore/verify/downstream，不包含前面的统一规划）。
- 修复严格限于第二次 skip 检查补 `and not force_all`；普通增量跳过、已有输出的 alternatives winner 行为保持原语义。回归覆盖标记在会话前存在及会话中生成的两种情况。
- 用户要求跳过已成功的 2195 条 skill；临时 `phase_d_resume.py` 仅用于该固定 run 和准确 source SHA。它重新核验已上传的四个成功报告、旧失败报告的摘要/绑定、保留节点的证据及除缺失文件之外的完整字节；只允许准确的一行 executor 修复。恢复同一 warm generation，从准确 source Git blobs 继承其它输出，仅运行没有 prerequisite、额外输出或下游的这一个节点。
- 续验使用 records-only 验证入口核对跨 run 的组/节点覆盖，原失败报告和原 comparison.json 均不修改，也不生成冒充原单次 run 的成功报告。新报告标为 `phase-d-cross-run-continuation-not-pr-attestation`，记录原报告、补跑报告、executor 修复摘要与完整 inventory 比较；它是一次性迁移续验证据，不引入生产 PR/release 的通用 resume 契约。
- 全量下游证据仅在源码/config 和补齐后的完整 inventory 与已验证 full 基线完全一致后复用。#926 合并后的临时入口清理范围同时包含 `phase_d_resume.py`；永久保留执行器修复及其回归测试。

### 续验结果与策略启用

- 修复通过 PR #931 合入（`2ddc73a5`）。[续验 run 34067782997](https://github.com/HLND2T/CS2_VibeSignatures/actions/runs/34067782997) 成功；`continuation.json` 为 `valid=true`，明确标记 `phase-d-cross-run-continuation-not-pr-attestation`。
- 保留 2195 个成功节点，只重跑 `7:241:server:linux:find-CFlashbangProjectile_Spawn_NetworkStateChangedNotify`；producer 耗时 **53.203 秒**。补跑报告 `valid=true`、issues 为空；联合记录覆盖全部 3529 组。
- 补齐后的 3526 个文件与原 fresh-full 基线逐字节相同，并再次在本地下载结果进行完整 inventory 比较。比较摘要：`sha256:6f5c2fddb7bd8883b52a4de815bc5932ba468065baebf77df4056f32604c630c`。
- 原失败报告摘要：`sha256:a59af7ef608aa1fda02ea8bf352f17a6826aac4c577df25b1211663418fc31f6`；补跑报告摘要：`sha256:efdaf5cc6cae4888ef2c70483ccaea696f355069d86a0fde4c750f480de762eb`。原报告不改写。
- 保持 IDA 9.3、warm generation `19101f3cc9642dc952428d880331ce0f4cf92f8873a3f4479998b8c0ed54cac2-33321771474-1`、binary lock `sha256:f731bb7d9648092272eb749fbd8c1892bf8e7b94b3221a92633c0a7297836e89` 和字符串最小长度 4。
- 独立策略更新将 `source_artifact_policy.yaml` 设为 `base-inherited-selected-v1`，并在正式 `pr-self-runner.yml` 显式设置 `CS2VIBE_STRING_MIN_LENGTH=4`，使 PR 分析条件与已验证条件一致。release fresh-full 及发布前精确字节门禁不变；回滚只需将 policy 恢复为 `fresh-full-v1`。
- 限制：共享运行时样本使用保留旧成功证据 + 准确一行 executor 修复下的单节点续验，不宣称修复后又执行过一次完整 fresh-full。补跑输出、声明依赖及未触发该分支的旧成功记录分别验证；这不是生产通用断点续跑契约。merge queue 的 selected 真机复验仍由 #926 后续队列运行验证。
- #926 于 2026-09-07 01:41:12 UTC 合并（`e80b418a4689abdf3de1b569217ffb9511a8053c`），满足临时入口清理门槛。后续清理补丁删除 `phase-d-validation.yml`、`phase_d_validation.py`、`phase_d_resume.py`、临时 helper 测试及 suite 注册；保留永久执行器修复、回归测试、selected 策略和上述证据。第 18 节的临时入口说明作为历史记录保留。

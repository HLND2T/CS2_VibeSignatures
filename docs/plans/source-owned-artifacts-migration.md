# Source-owned per-symbol artifacts 迁移计划

状态：实施中（仓库内步骤 1–17 已完成；外部 cutover 与发布验收未完成）

日期：2026-09-01

实施记录（2026-09-02）：

- 仓库内实施顺序 1–17 已在 `dev-source-owned-artifacts` 上按步骤提交；步骤 20 的文档、Skill、Memory、
  独立审查 finding 与 completion verification 正在收口。
- 步骤 18 的 drain/freeze、先合并 PR A trust bridge、启用外部 required workflow/ruleset、再基于
  default-branch-owned planner 验证 PR B 尚未执行。当前 `origin/main` 不具备该 trust bridge，不能用本分支
  自带 workflow 代替。
- 步骤 19 的 new-GAMEVER bootstrap drill、non-publishing Release dry run、sandbox BinSync/Release publish、
  Pages CDN byte verification、accepted-bin cleanup receipt 与两次真实 fresh full rebuild 尚无外部验收证据。
- 两个历史 `gamesymbols/build/14174/*` 远端分支仅完成识别，未获删除授权，保持不变。
- 因此本文仍是进行中的迁移记录；在步骤 18–20 的全部门禁与真实外部验收完成前，不得声明迁移完成或可合并。

优先级：P1

评估基线：`main@6c28ad813a197d93df138edcb9824e6d27f2118c`

参考实现：`GoldSrc_VibeSignatures` PR #61 → #60 → #62 合并后的契约语义；不直接
cherry-pick GoldSrc 实现。

## 1. 决策摘要

本迁移把 `bin_artifacts/<gamever>/<module>/<artifact>.yaml` 确立为 per-symbol
分析结果的唯一 Git source truth。

迁移后：

1. source PR 提交自身影响范围及 downstream closure 内的 per-symbol artifacts；
2. PR 不提交 `gamesymbols/<gamever>.yaml`、metadata、gamedata 或 release manifest；
3. trusted PR validation 在隔离目录重跑受影响 producer groups，并对完整 artifact tree
   做 inventory 与 Git blob exact-byte comparison；
4. 新 GAMEVER 必须在版本 PR 中先完成 full bootstrap，再由独立 hosted publisher 使用专用 PAT 将
   artifact commit fast-forward push 到同一 `bump-download/<GAMEVER>` 分支，随后进入普通
   exact-byte validation；main 不允许出现已配置但没有 source-owned artifacts 的版本；
5. Merge Queue 或严格 up-to-date branch protection 保证每个最终合并组合都重新验证；
6. Release build 对目标 GAMEVER 在 fresh artifact root 中完整执行
   `ida_analyze_bin.py -force_all -rename`，要求重建结果与 Git truth 逐字节一致；
7. Release build 同时生成本地 BinSync changes，但不得在验证完成前推送；
8. hosted verifier 复验 release bundle 与内部 BinSync publication candidate；
9. 受保护的 `publish-binsync` job 使用仅限 BinSync repositories 的凭证幂等推送；
10. `publish-new-gamever-artifacts` 是唯一允许写 source branch 的自动化特例；受保护的
    `publish-release` 是唯一允许创建或修改 tag、Release 和 Release assets 的 job；
11. `gamesymbols`、metadata、gamedata、archives、checksums 和 release manifest 全部成为
    Release 派生产物，不再作为 Git versioned outputs。

## 2. 背景与动机

### 2.1 多 PR 协作冲突

当前 canonical analysis lockfile 是单个 `gamesymbols/<gamever>.yaml`。如果两个并行 PR 分别
修改无关 symbol，却都提交完整 snapshot，它们会争用同一个大文件：

```text
PR A -> gamesymbols/<gamever>.yaml  # Artifact A
PR B -> gamesymbols/<gamever>.yaml  # Artifact B
```

后合并的 PR 需要解决与业务变化无关的文本冲突，还可能覆盖先合并 PR 已验证的结果。

source-owned per-symbol truth 将 merge 粒度缩小到真实语义单元：

```text
PR A -> bin_artifacts/<gamever>/<module>/ArtifactA.<platform>.yaml
PR B -> bin_artifacts/<gamever>/<module>/ArtifactB.<platform>.yaml
```

不同 artifacts 可以正常合并；只有修改同一路径时才产生应当解决的真实语义冲突。

### 2.2 PR 验证与 Release 重跑职责不同

PR validation 证明某个 prospective merge tree 中受影响 artifacts 与其 producers 一致；Release
full rebuild 则证明多个已合并 PR 的最终 source SHA 在指定 runtime 下仍可完整重现 Git truth，并为
IDB/BinSync 应用 rename/comment side effects。

因此 Release 保留完整分析不是重新定义 truth，而是最终组合复验与 BinSync publication 的生产阶段。
Release 重跑产生不同 bytes 时必须失败并回到 source PR 修复，禁止在 Release workflow 中覆盖 Git truth。

### 2.3 当前数据基线

2026-09-01 的只读审计结果：

- configured gamevers：16；
- configured `bin/<gamever>` 中现有 YAML：52,544 个，约 15.38 MiB；
- formal contract paths：51,361；
- tracked canonical snapshots 可解包 artifacts：51,299；
- private `bin` 相对 formal contract：50 个 required 缺失、1,295 个 extra/stale；
- per-version multi-owner paths 合计：590，最大 owner 数为 2；
- 整个本地 `bin`（含未配置历史版本和 backup 目录）共有 104,043 个 YAML，不属于迁移范围；
- 当前 Git tracked outputs：`gamesymbols` 32 个、`gamedata` 260 个、
  `release-manifests` 15 个；
- 当前无 open generated-output PR；仍有两个待审计 remote branches：
  `gamesymbols/build/14174/30871463145-1` 和
  `gamesymbols/build/14174/31775391898-1`。

当前 private `bin` 已与 formal contract 漂移，不能作为一次性迁移 truth。bootstrap 必须从通过当前
snapshot contract 的 tracked `gamesymbols/<gamever>.yaml` 解包语义 payload，再由新的中央 serializer
生成 canonical per-symbol bytes。

## 3. 目标

1. 让 per-symbol artifacts 成为 source-owned、可合并、可审查的 Git truth。
2. 让 source/config/artifact PR 对 exact prospective merge tree 执行可信增量重建。
3. 让 artifact-only PR 正确触发 owner producer group 与 downstream closure。
4. 让 Release full rebuild 在 fresh root 中逐字节重现 source truth。
5. 保留 Release `-rename` 和 BinSync publication，同时隔离其凭证与远端副作用。
6. 让 snapshot、metadata、gamedata、C++ validation、Pages input、archives 和 manifest 从同一份
   validated artifact tree 派生。
7. 删除 generated-output PR、独立 output promotion 和 tracked release output 状态机。
8. 保持 warm IDB 与 accepted-bin 为可删除、可重建的性能/二进制层，而非分析 truth。
9. 让 tag、Release assets、BinSync refs 和 manifest 都绑定产生它们的 immutable source SHA。
10. 在不信任 PR 自带 planner、self-hosted publisher token 或 Actions Artifact 长期留存的前提下
    完成 build、verify、BinSync publish 和 Release publish。
11. 让新 GAMEVER 在进入 main 前先完成 source-owned artifact bootstrap，禁止 Release workflow
    成为首次创建或回写 Git truth 的路径。

## 4. 非目标

- 不把 game binaries 提交到主仓库。
- 不把 `bin` 改成 submodule；CS2 的 binary identity 使用 formal binary inventory、Depot/download
  identity 和 per-file hashes。
- 不把 `bin_artifacts` 纳入 warm IDB cache identity；warm IDB 仍是中性性能层。
- 不改变 `ida_preprocessor_scripts/references/` 的人工语义所有权。
- 不在本次重命名所有 finder/preprocessor 的 `new_binary_dir` 参数；保持 ABI，内部传入
  artifact module dir。
- 不把 Actions Artifact 当作长期 truth 或失败恢复的唯一存储。
- 不允许 Release workflow 自动修复、提交或 push 与 Git truth 不一致的 artifacts。
- 不允许 Release build 为 main 中缺少 artifacts 的新 GAMEVER 临时生成 truth 后继续发布。
- 不允许执行 PR producer、IDA、LLM 或 Agent payload 的 self-hosted job 持有 artifact publication PAT。
- 不允许同版本 Release 内容覆盖；内容变化必须发布新版本。
- 不通过测试锁定 workflow YAML、skill 文本、文档、前端或其他易变文本内容。

## 5. 术语与目录契约

统一使用以下语义：

```text
binary_root              = bin
binary_game_root         = bin/<gamever>
binary_module_dir        = bin/<gamever>/<module>

artifact_root            = bin_artifacts
artifact_game_root       = bin_artifacts/<gamever>
artifact_module_dir      = bin_artifacts/<gamever>/<module>

expected_artifact_root   = Git blobs materialized from prospective merge/source SHA
actual_artifact_root     = isolated fresh rebuild output
old_artifact_root        = Git-owned prior-gamever artifacts used for signature reuse
```

所有 binary/hash/loader/IDA database 操作只接受 binary roots。所有 per-symbol YAML 的读、写、
skip、dependency lookup、inventory、canonicalization、restore 和 comparison 只接受 artifact roots。

`gamesymbols/<gamever>.yaml` 不再是 root 或 baseline；它是从 validated artifact tree 构建的
Release candidate document。

## 6. 目标信任模型

| 层级 | 内容 | 是否 truth | 生命周期 |
|---|---|---:|---|
| Git source truth | configs、producers、`bin_artifacts`、reference YAML、SDK gitlink | 是 | 随 source commit |
| PR expected tree | prospective merge Git blobs | 只读 expected | 单次 PR check |
| PR rebuilt tree | isolated affected-closure rebuild | 否 | 单次 PR check |
| Warm IDB | binary/IDA identity 绑定的中性 IDB | 否 | 可删除、可重建 |
| Accepted-bin | binary 与明确 allowlisted side files | 否 | 可删除、可重建 |
| Release rebuilt tree | fresh full rebuild + `-rename` actual | 否 | 单次 release run |
| BinSync candidate | 无凭证 Git bundles + publication manifest | 候选 | 单次 release run |
| Release bundle | snapshot、metadata、gamedata、archives、manifest、checksums | 候选 | 单次 release run |
| Actions Artifact | build → verify/publish 传输层 | 否 | Actions retention |
| Remote BinSync refs | 已验证 IDA rename state | 发布状态 | 按版本长期保存 |
| Published GitHub Release | 对外分发资产 | 发布 truth | 永久、不可覆盖 |

### 6.1 PR 数据流

```text
trusted base planner + prospective merge tree
  ├─ source/config/bin-artifact Git blobs
  ├─ binary/SDK identities
  └─ reference YAML
            │
            ▼
affected nodes + producer groups + downstream closure
            │
            ▼
$RUNNER_TEMP/rebuilt-bin-artifacts
  ├─ 复制未失效的 prospective merge artifacts
  └─ 强制重跑 selected producer groups
            │
            ▼
formal inventory + canonical bytes + Git blob exact comparison
            │
            ▼
check 绑定 base/head/merge tree，Merge Queue 只合并 exact verified combination
```

### 6.2 Release 与 BinSync 数据流

```text
preflight(source SHA + GAMEVER + binary inventory)
  -> warmup-idb
  -> full rebuild on self-hosted runner
       ida_analyze_bin.py -force_all -rename
       actual artifacts == Git truth
       local BinSync changes only
  -> snapshot/gamedata/C++/release bundle
  -> internal BinSync publication candidate
  -> GitHub-hosted verify
  -> protected publish-binsync
  -> protected publish-release
  -> Pages deploy from published immutable Release
```

## 7. Formal artifact contract

### 7.1 Inventory 来源

formal inventory 必须复用当前 config parser、execution planner 与 snapshot contract 中已经存在的路径
解析语义，不得用 symbol basename 集合重新拼路径。

formal paths 至少包括：

- required `expected_output` 与 platform-specific outputs；
- optional outputs，仅在 producer 实际生成时进入 materialized inventory；
- required/optional inputs，用于 dependency graph 与 invalidation；input 必须解析到另一 formal output，
  或显式声明为独立 Git-owned external input，不能仅因被引用就凭空创建第二份 inventory entry；
- 跨 module `../<module>/...` 路径，最终必须 contained 于同一 artifact game root；
- Windows/Linux platform 展开后的 canonical paths；
- vtable、func、vfunc、global variable、patch、struct member 等现有 artifact categories。

`symbols[].source_alias` 是 downstream artifact filename fallback，不是新的 artifact owner，也不复制一份
alias artifact。formal owner 继续绑定 producer output path；gamedata lookup 保持 canonical name →
`source_alias` → compatibility alias 的读取顺序。

### 7.2 Required、optional 与 stale 策略

- required artifact 缺失：失败；
- optional artifact：仅当 producer 本次实际生成或 Git truth 已声明存在时进入 inventory；
- extra/stale YAML：失败；
- 未知 module、嵌套目录、非 YAML 普通文件：失败；
- artifact root、gamever、module、file 的 casefold collision：失败；
- config 删除 output 时，PR 必须同步删除原 artifact；
- artifact rename 必须同时验证 old owner 与 new owner；
- artifact-only PR 不能产生空计划。

### 7.3 Producer group

CS2 现有 inline/noinline、deinlined/inlined 等 fallback producers 会有意声明同一路径。不能照搬
GoldSrc 的单 producer 约束。

新契约定义：

```text
formal artifact path
  -> exactly one producer group
       -> one or more ordered alternative producer nodes
```

规则：

1. 同一路径的多个 owners 必须显式形成一个有序 group，隐式重复 owner 失败；
2. group order 来自 config 顺序并进入 group fingerprint；
3. 执行按顺序尝试 alternatives；已有 output 使后续 alternatives skip；
4. 一次 fresh group run 最终必须产生零个或一个 payload：required 为一个，optional 为零或一个；
5. alternative 成功后，后续 alternative 不得重写该 output；
6. 任一 alternative source、config 或 dependency 变化都会 invalidate 整个 group；
7. bound plan 记录 selected group、attempted nodes、winning node 和 output digest；
8. 同一次 group execution 观察到多个 success、later alternative 重写 output 或 winner 与 bound plan
   不一致时 fail closed，不能依赖偶然调度顺序；
9. downstream edge 指向 producer group，而不是任一单独 alternative。

### 7.4 Canonical per-symbol bytes

所有 producer 只负责生成语义 payload。可信 analyzer pipeline 在 runtime validation 成功后统一执行
central finalization：

1. 按 Source2 category schema 验证 identity fields、address、signature、offset、slot/pointer size；
2. 使用中央 category field order；
3. 对 nested mappings 使用稳定排序；
4. 统一 UTF-8、无 BOM、LF、末尾单换行、稳定 scalar spelling 与固定折行宽度；
5. 使用同目录 temporary file、flush/fsync 和 `os.replace` 原子写入；
6. repository contract 重新 parse/serialize 每个 tracked artifact 并比较 exact bytes；
7. preprocessor 和 Agent fallback 成功路径必须调用同一 finalizer；
8. writer skills 不作为字段顺序、换行或 scalar style 的信任边界。

GoldSrc 的 x86 4-byte vfunc 规则不得复制。CS2 canonicalizer 必须基于当前 Source2 x64 数据结构、现有
snapshot schema 和 C++ validation 语义设计。

`.gitattributes` 增加：

```gitattributes
/bin_artifacts/**/*.yaml text eol=lf
```

### 7.5 路径与文件系统安全

- artifact root、gamever、module、file 及已存在 ancestors 不得是 symlink/reparse point；
- 禁止 absolute path、反斜杠、`..` 逃逸、空段、`.` 与非 canonical spelling；
- 允许现有跨 module output/input，但最终 real path 必须仍在 artifact game root；
- expected Git bytes 使用 `git cat-file`/tree blobs，不依赖 checkout newline conversion；
- actual rebuild root 必须位于 source checkout 外；
- repository contract 不跟随 links；
- Windows casefold 后的 path 和 module spelling 必须唯一。

## 8. Analyzer 与核心代码改造

### 8.1 `ida_analyze_bin.py`

新增或重构：

- `ARTIFACTS_DIR = "bin_artifacts"`；
- CLI `-artifactdir`，默认 `bin_artifacts`；
- CLI `-oldartifactdir` 或内部 resolved old artifact root；
- CLI `-force_all`，禁止 existing-output skip，且报告每个 selected group 实际执行情况；
- `analyze()`、execution plan、process module/platform、selected-node execution 显式接收 binary root 与
  artifact root；
- binary path 继续来自 `get_binary_path(bindir, ...)`；
- output/input/skip/post-process/old YAML 全部从 artifact module dir 解析；
- `new_binary_dir` 参数名暂时保留，实际传 artifact module dir；
- runtime artifact classifier 以 artifact module dir 为 current-module root；
- `-rename` 在 producer execution 结束后，从最终 validated actual artifacts 应用 IDA name/comment；
- fresh full rebuild 中 `-rename` 与 artifact generation 复用同一次 IDA session；
- checkout 中 expected artifacts 在运行前后 digest 必须不变。

### 8.2 `ida_analyze_util.py` 与 writers

- 提供 Source2 `normalize_symbol_artifact()`；
- 提供 `canonical_symbol_yaml_bytes()`；
- 提供 atomic `canonicalize_symbol_yaml_file()`；
- 所有 `write_*_yaml()` 复用中央 serializer；
- dependency lookup、vtable lookup、LLM template、`source_alias` 和 cross-module resolution 从
  artifact root 读取；
- 现有 skill/preprocessor ABI 保持兼容；
- Agent writer skill 文档说明自身只生成语义 payload，trusted analyzer 负责最终 bytes。

### 8.3 Snapshot/candidate/store 双根化

`SnapshotContract.game_root` 拆为：

- `binary_game_root`：binary metadata、hash、path identity；
- `artifact_game_root`：per-symbol inventory 与 payload。

对应修改：

- `gamesymbol_snapshot_lib/config.py`；
- `gamesymbol_snapshot_lib/model.py`；
- `gamesymbol_snapshot_lib/operations.py`；
- `gamesymbol_snapshot_lib/candidate.py`；
- `gamesymbol_candidate.py`；
- `gamesymbol_store.py`。

行为要求：

- `collect_actual_files()` 只扫 artifact root，并在正式路径始终 strict；
- `collect_binary_metadata()` 只扫 binary root；
- candidate CLI 增加 `-artifactdir`；
- `DirectorySymbolStore` 扫 artifact game root；
- `SnapshotSymbolStore` 继续作为 release candidate/downstream reader；
- `restore_snapshot()` 退出正常 correctness 路径，只保留显式 rollback/compatibility 命令，且只能写
  isolated artifact root；
- 不允许 snapshot 正常 hydrate tracked expected 或 accepted-bin YAML。

### 8.4 Downstream consumers

- `gamedata_candidate.py` 从同一次 validated snapshot candidate 生成；
- `run_cpp_tests.py` 使用同一 candidate snapshot 与 exact SDK identity；
- `generate_reference_yaml.py` 查找 existing per-symbol YAML 时改读 `bin_artifacts`，binary/IDA export
  仍走 `bin`；
- Pages build 从已发布 Release 下载 snapshot、metadata 和 gamedata，不再读取 main tracked outputs；
- `idb_cache.py`、`warmup_idb.py`、`download_depot.py`、`copy_depot_bin.py` 保持 binary-root 语义；
- BinSync sidecars、`.bsproj` 和 IDA database 不进入 artifact inventory。

### 8.5 Repository artifact contract

新增独立 `bin_artifact_contract.py`，负责：

- 枚举全部 configured gamevers；
- 构建 required/optional/producer-group formal inventory；
- canonical YAML、path、casefold、link/reparse、ownership 校验；
- Git tracked `bin_artifacts` 与 formal materialized paths 完全一致；
- 拒绝 Git tracked `bin/**/*.yaml`；
- 拒绝 Git tracked versioned `gamesymbols/**`、`gamedata/**`、`release-manifests/**`；
- 返回每 gamever 排序后的 `path + size + sha256` inventory 与 domain-separated digest；
- 比较 checkout 外 actual root 与 Git expected blobs；
- 提供 repository-contract test suite entrypoint。

release bundle contract 与 repository artifact contract 分离，避免继续使用“generated output 必须提交 Git”的
旧模块语义。

## 9. Trusted PR validation

### 9.1 Trusted planner

PR workflow 必须：

- 从 PR base/default branch checkout planner、routing rules、lockfile 和 runner policy；
- `persist-credentials: false`；
- 将 base/head/prospective merge trees 只作为数据读取；
- 从 trusted base 获取 submodule URL、runner labels、secret requirements；
- 不执行 PR head 自带的 planner 来决定是否需要自托管分析；
- fork PR 不得接触 self-hosted runner、IDA、LLM secrets 或 persisted workspace。

### 9.2 Bound plan schema

plan 至少绑定：

- schema version；
- base/head/prospective merge commit 与 tree SHA；
- configured GAMEVER set；
- binary inventory、download/depot identity 和 SDK gitlink；
- 每 gamever base/merge config digest；
- base/merge artifact inventory digest；
- reference/preprocessor/skill source digests；
- affected producer groups；
- selected alternative nodes；
- invalidated formal paths；
- downstream closure；
- release/gamedata/C++/Pages impact flags；
- canonical plan digest。

### 9.3 Changed-path 与 invalidation

- artifact A/M：使用 merge ownership；
- artifact D：使用 base ownership，并验证 merge contract 已删除或仍声明；
- artifact R/C：同时处理 old/new path；
- unknown artifact path：失败；
- source/config/reference/skill change：由 trusted ownership/source index 映射 seeds；
- shared analyzer/serializer/runtime contract change：按规则扩大到所有 affected gamevers/groups；
- producer-group 任一 alternative 变化：group 作为 seed；
- seeds 之后计算完整 downstream closure；
- PR 必须提交 closure 对应 artifacts，不能只提交直接 output。

### 9.4 隔离增量重建

对每个 affected GAMEVER：

1. 从 prospective merge Git tree 导出 expected manifest 与 blobs；
2. 创建 checkout 外 fresh actual root；
3. 复制未 invalidated 的 merge artifacts；
4. 恢复 exact warm IDB generation；
5. 强制执行 selected producer groups，禁止 existing-output skip；
6. 记录 attempted/winning alternatives；
7. 验证 selected groups 全部按计划执行；
8. 运行完整 formal inventory 与 canonical-byte contract；
9. 对完整 expected/actual inventory 做 Git blob exact comparison；
10. 断言 source checkout tracked artifacts 前后 digest 不变。

故意提交一字节错误、缺失、额外、错误 rename、伪造空计划或错误 producer winner 必须使 required check
失败。

### 9.5 Merge Queue 与最终组合证明

启用 GitHub Merge Queue；若暂不可用，则 branch protection 必须开启严格 up-to-date requirement。

规则：

- required artifact check 必须运行在 queued/prospective merge tree，而非仅 PR head；
- main 前进后，尚未合并 PR 必须重新生成 merge tree 并重新验证；
- check result 必须绑定 exact tree SHA；
- 禁止管理员绕过 artifact-related required checks 或直接 push 相关 source/artifact changes；
- merge method 与验证 tree 的等价关系必须由 repository contract 测试和运维文档明确；
- Release preflight 只接受可达 default branch 且满足 protected merge policy 的 source SHA。

### 9.6 Fork 策略

- trusted hosted planner 仍计算 fork 影响；
- 只需 light validation 的 fork PR 可运行 hosted checks；
- 需要 IDA/LLM/Agent 的 fork PR fail closed，并提示 maintainer 镜像到 same-repository branch；
- fork 修改 planner/routing rules 不能把 full plan 伪造成 empty/light；
- secrets 和 self-hosted jobs 不得由未经信任的 fork payload 触发。

### 9.7 Source PR 作者工作流

正常 source PR 的作者流程是：

1. 基于最新 default branch 创建分支；
2. 修改 producer/config/reference/source；
3. 使用 local planner 预览 affected producer groups 与 downstream closure；
4. 在 `bin_artifacts` tracked root 中定向重建 closure；
5. 提交 source change 与对应 per-symbol artifact A/M/D/R；
6. 运行 local repository artifact contract；
7. 不提交 snapshot、metadata、gamedata 或 release manifest；
8. PR CI 使用 trusted planner 独立重算并复验，不能信任作者提供的 affected list。

无法本地运行 IDA/LLM/Agent 的普通 same-repository contributor 可以显式调用受信的
`prepare-artifact-patch` workflow。该 workflow：

- 绑定调用时的 exact branch head SHA；
- 在 self-hosted runner 生成可下载的 artifact patch/inventory，不直接合并、不改 main；
- 默认不持有 branch push credential；新 GAMEVER 的 `bump-download/<GAMEVER>` PAT publication 是
  `9.8` 定义的唯一自动 push 特例；
- fork 只能由 maintainer 镜像为 same-repository branch 后使用。

### 9.8 新 GAMEVER bootstrap

新 GAMEVER 没有 base artifacts，不能直接套用“expected Git blobs 与 selected rebuild 比较”的普通路径，
也不能先把不完整版本合并到 main，再让 Release build 首次创建 truth。

版本 PR 必须使用两阶段 bootstrap：

```text
initial version PR head
  download/config/new binary identity
  no artifacts for the new GAMEVER yet
            │
            ▼
trusted planner -> bootstrap_required
            │
            ▼
self-hosted full bootstrap from empty artifact root
  ida_analyze_bin.py -force_all -rename
  rename + BinSync prepare are local-only / no remote write
            │
            ▼
canonical artifact candidate + inventory + snapshot/gamedata/C++ gates
            │
            ▼
artifact commit/patch applied to the same version PR
            │
            ▼
normal trusted PR validation reruns
  prospective merge artifacts == isolated rebuild bytes
            │
            ▼
Merge Queue -> main -> Release full rebuild -force_all -rename
```

#### Bootstrap detection

trusted planner 在以下条件下输出 `bootstrap_required`，不能输出 light/empty/success：

- prospective merge 新增 configured GAMEVER；
- base tree 没有该 GAMEVER 的 formal artifact inventory；
- merge config 已能构建 formal producer groups 与 binary targets；
- merge tree 尚未包含完整 required + generated optional artifacts。

如果 merge tree 已包含新版本 artifacts，planner 直接进入普通 exact-byte validation，不重复发布 candidate。

#### Bootstrap build

- planner、routing policy、runner labels 和 publication rules 来自 trusted base；
- config、download entry、producer code 与 binary identity 来自 exact prospective merge tree；
- 仅允许 same-repository branch；fork 必须先由 maintainer 镜像；
- warm IDB producer 为新 binary inventory 创建 exact generation；
- 从 empty actual artifact game root 执行所有 formal producer groups；
- 使用 prior source-owned GAMEVER artifacts 作为 old-signature baseline；没有合法 prior GAMEVER 时显式使用
  no-old-baseline 模式，不能从 private snapshot/bin 猜测；
- 完整执行 `ida_analyze_bin.py -force_all -rename`；`-rename` 只修改该 run 的隔离 IDB，并执行
  local-only BinSync prepare，用于提前验证 rename/comment post-process 与 BinSync candidate 构建；
- self-hosted bootstrap 不持有 BinSync remote write credential；运行前后 remote refs 必须不变，本阶段生成的
  local BinSync candidate 仅作为验证证据，不得上传给 publisher、复用为 Release candidate 或推送远端；
- 不创建 tag/Release；合并后的 Release 必须再次从 main 的 Git truth 执行 `-force_all -rename`，重新构建并
  通过 protected publisher 正式发布 BinSync；
- 运行 canonical artifact contract、snapshot candidate、gamedata 和 C++ gates；
- 输出完整 new-GAMEVER artifact tree、inventory digest、bound source/head SHA 和 provenance。

#### 使用 PAT 将 artifacts 带回 Bump Download PR

branch policy 不接受 `GITHUB_TOKEN` bot push。新 GAMEVER 的标准 publication 路径是独立的
GitHub-hosted `publish-new-gamever-artifacts` job，使用专用 fine-grained PAT 将 candidate commit
fast-forward push 到同一个 `bump-download/<GAMEVER>` branch。

job 分界：

1. self-hosted bootstrap job 只生成并上传 exact artifact candidate/inventory Actions Artifact，不持有 PAT；
2. hosted publisher 使用 trusted base/default-branch tooling，不执行 prospective merge 中的 Python、script、
   action 或其他可执行 payload；
3. publisher 下载 exact bootstrap candidate，验证 run/artifact name、Actions Artifact digest、bound head、
   GAMEVER、formal inventory 和 per-file hashes；
4. PAT 只在 publisher job 的 protected `artifact-bootstrap` environment 中可用；
5. PAT 使用专用 automation account，fine-grained repository access 仅限 `HLND2T/CS2_VibeSignatures`，
   repository permission 仅授予 `Contents: Read and write`；PR 查询使用 read-only `github.token`；
6. fine-grained PAT 本身不能按 branch、tag 或 path 限权，因此 repository rulesets 是必要的权限边界：
   `bump-download/*` ruleset 允许该 actor 普通 push；覆盖其余 branches 的 ruleset 不给该 actor bypass；覆盖
   所有 tags 的 ruleset 也不给该 actor create/update/delete bypass；
7. PAT actor 不得拥有 main direct-push、required-check bypass、force-push、Actions、administration、secrets
   或 repository ruleset bypass；专用 rulesets 必须禁止 ref deletion 与 force-push；
8. checkout 使用 `persist-credentials: false`；PAT 只注入最终 authenticated push，不写入可上传的 Git
   config、logs、candidate 或 cache；
9. workflow 使用 repository + PR number + GAMEVER concurrency，`cancel-in-progress: false`；
10. PAT 使用短有效期、定期轮换、push/API audit 与可立即吊销的 secret inventory。由于 `Contents: write`
    也能调用部分 contents/Release APIs，workflow 契约必须禁止这些调用；这项残余权限不能由 fine-grained PAT
    原生消除，只能通过不执行 PR payload、environment protection、rulesets、审计与快速吊销降低风险。

push transaction：

1. 确认 repository 精确为 allowlisted source repository；
2. 确认 PR 仍 open、base 是 default branch、head repo 是同一 repository；
3. 确认 head ref 精确匹配 `bump-download/<GAMEVER>`，并与 config/download GAMEVER 一致；
4. 查询 remote head，必须仍等于 bootstrap candidate 绑定的 head SHA；
5. checkout/detach exact bound head，在临时 worktree materialize candidate artifacts；
6. changed paths 只能是 `bin_artifacts/<new-gamever>/**`；bootstrap provenance 放在 commit trailers、
   bound plan 和 workflow evidence 中，不新增另一类 tracked metadata truth；
7. staged bytes/inventory 必须再次等于 candidate digest；
8. commit parent 必须是 bound head；commit message/trailers 绑定 source head、GAMEVER、inventory digest、
   workflow run 与 candidate Actions Artifact digest；
9. 使用 PAT 执行普通 fast-forward push，禁止 force、delete 或 refspec 扩张；
10. push 后查询 remote head，必须等于新 artifact commit；
11. PAT push 必须产生 `pull_request.synchronize` 并在 artifact-bearing 新 head 上重新触发完整 trusted
    PR validation；
12. bootstrap run/publication job 本身不能把 `pr-validate` 标为成功，只有新 head exact-byte
    revalidation 通过后才可合并。

防循环规则：新 head 已包含完整 artifacts 时 planner 必须走普通 validation，不能再次进入
`bootstrap_required` 或重复 PAT publication。remote head 漂移、PAT 失效、branch rule 拒绝或 candidate
digest 不一致时 publication fail closed，保持 PR 不可合并并重新 bootstrap；不得 force push 或绕过规则。

仅在 PAT publication 基础设施故障且用户明确授权人工恢复时，才允许下载 exact patch 后由授权用户应用到
同一 Bump Download branch；人工路径仍必须满足相同 digest、allowed-path 和新 head revalidation 契约。

#### Main 与 Release 不变量

- configured GAMEVER、config、download identity 与完整 source-owned artifact inventory 必须原子进入 main；
- repository contract 拒绝 main 中任何 configured-but-unmaterialized GAMEVER；
- 自动 bump PR 只有在 bootstrap commit 与普通 validation 完成后才能 merge；
- bump merge 后的 release dispatcher 必须先运行 repository artifact preflight，才能 dispatch Release；
- Release preflight 发现 source SHA 缺少该 GAMEVER artifacts 时 fail closed，报告
  `new GAMEVER source artifact bootstrap required`，可创建/提示 bootstrap PR，但不得继续 full build、
  push BinSync 或发布 Release；
- Release full rebuild 始终是验证既有 Git truth，不是新 GAMEVER artifact publication mechanism。

## 10. Release full rebuild 与 BinSync publication

### 10.1 Preflight（GitHub-hosted）

- 只允许 allowlisted repository；
- source SHA 默认解析 immutable `origin/main`，必须可达 default branch；
- 解析 GAMEVER、config、download/depot identity、SDK SHA 与 binary inventory；
- 要求 source SHA 已包含该 GAMEVER 完整、tracked、canonical artifact inventory；缺失时以
  `bootstrap_required` fail closed；
- 校验 tag/Release/draft/BinSync publication 状态；
- repository + GAMEVER + version concurrency，`cancel-in-progress: false`；
- 已存在 published Release 只允许 exact idempotent success；
- 内容变化禁止 same-version republish；
- 输出 source SHA、GAMEVER、version、artifact digest、binary identity、恢复模式和 artifact names。

### 10.2 Warm IDB

- 复用 immutable warm generation 模型；
- selection 绑定 configured binary inventory 与 IDA kernel/runtime；
- 不把 artifact content 加入 warm cache identity；
- release consumer 必须恢复 producer 返回的 exact generation；
- cache absence、damage、identity mismatch 或 runtime drift 阻止 release analysis。

### 10.3 Build-release（self-hosted、无远端发布权限）

该 job 只拥有主仓库 `contents: read`，不得持有主仓库 PAT、tag/Release 权限或 BinSync remote write
credential。

步骤：

1. checkout exact source SHA、SDK gitlink 与 binary identity；
2. materialize binary-only workspace 与 exact warm IDB；
3. 从 Git blobs 只读加载 expected `bin_artifacts/<GAMEVER>`；
4. 创建 checkout 外 empty actual artifact root；
5. 完整执行：

   ```powershell
   uv run ida_analyze_bin.py `
     -gamever <GAMEVER> `
     -configyaml configs/<GAMEVER>.yaml `
     -bindir bin `
     -artifactdir <fresh-actual-root> `
     -oldartifactdir bin_artifacts `
     -require_warm_idb `
     -force_all `
     -rename `
     -debug
   ```

6. 禁止 skip/error fallback 掩盖 producer failure；
7. 要求 actual formal inventory 与 expected Git blobs exact-byte 一致；
8. `-rename` 应用到本地 IDB/BinSync working state，但不推送 remote；
9. 从 validated actual tree 生成 snapshot candidate、metadata、gamedata 和 C++ validation input；
10. 运行 gamedata 与 C++ gates；
11. 构建 release bundle、internal BinSync candidate、manifests 与 checksums；
12. 上传两个独立 Actions Artifacts；
13. 清理仅限本 job 创建的 temporary state，失败诊断按有限 retention 保存。

BinSync 必须新增 local-only prepare 模式。`-rename`/BinSync plugin 在 build job 中不得自动 push；
`push_binsync_symbols.py` 拆为“创建本地 commits/bundles”的 prepare 阶段与“推送 verified bundles”的
publish 阶段。build 环境没有 write credential，即使 plugin 或脚本误尝试 remote write 也必须失败且被
检测。workflow 在运行前后读取并比较 remote refs，证明 build phase 没有副作用。

### 10.4 Internal BinSync publication candidate

build job 不直接 push。对每个需要发布的 BinSync repository 创建普通、无凭证、可传输的 Git bundle：

```text
binsync-candidate/
  manifest.json
  SHA256SUMS.txt
  repositories/
    <canonical-repository-id>.bundle
```

manifest 至少绑定：

- schema version；
- source SHA、GAMEVER、release version、build ID；
- artifact inventory digest；
- binary path/hash、IDA runtime identity；
- canonical BinSync repository owner/name；
- allowlisted refs；
- expected remote head per ref；
- candidate commit per ref；
- fast-forward relationship；
- Git bundle path、size、SHA-256；
- aggregate publication digest。

构建规则：

- `git bundle verify` 必须成功；
- bundle 只包含 allowlisted BinSync refs/objects；
- 不包含 credential、working-tree secrets、主仓库 remote token 或无关 branches；
- expected remote heads 在 build preflight 时读取并绑定；
- candidate commit 必须绑定匹配的 binary hash 与 source/artifact provenance；
- internal Actions Artifact 名称绑定 run ID/attempt/source SHA/GAMEVER；
- candidate 不作为公开 Release asset。

### 10.5 Hosted verifier

GitHub-hosted verifier 使用 `contents: read, actions: read`：

- checkout exact source SHA，并在 publish 模式确认仍可达 default branch；
- 从 Git objects 重算 repository/gamever artifact inventory；
- 验证 binary/download/SDK identities；
- 下载 exact release bundle 与 BinSync candidate Actions Artifacts；
- 验证 Actions Artifact name/digest/allowlist；
- 重跑 snapshot、metadata、gamedata、C++ evidence、archive、manifest 与 checksum contracts；
- 校验 release bundle 只有 allowlisted canonical paths；
- 对 BinSync candidate 运行 `git bundle verify`、ref/object、fast-forward plan 和 checksum contract；
- 输出 verified release artifact digest 与 verified BinSync candidate digest；
- 上传的 verified artifacts 必须保持原 bytes，禁止 verifier 重新生成内容；
- 不持有任何远端写权限。

### 10.6 Protected `publish-binsync`

该 job：

- 依赖 hosted verifier 成功；
- 使用独立受保护的 `binsync-release` environment；
- 使用 GitHub App 或 token，只允许写 allowlisted
  `CS2_VibeSignatures_binsync_*` repositories；
- 不拥有主仓库 contents/tag/Release write 权限；
- 下载 exact verified BinSync candidate；
- 再次核对 Actions Artifact digest、source SHA、GAMEVER、binary/artifact identity；
- 逐 repository 获取当前 remote refs；
- remote head 等于 expected head：只允许 fast-forward push candidate；
- remote 已等于 candidate：幂等成功；
- remote 为其他值、需要 force push、ref deletion 或 non-fast-forward：失败；
- 每次 push 后重新读取 remote ref 并验证 exact commit；
- 所有 targets 成功后输出 canonical remote publication receipt digest。

不使用 `--force`，不移动未知 refs，不修改 default branch，不创建未在 plan 声明的 repository。

### 10.7 Protected `publish-release`

该 job：

- 依赖 hosted verifier 与 `publish-binsync` 成功；
- 使用独立受保护的 `release` environment；
- 是主仓库唯一允许创建或修改 tag、Release 和 Release assets 的 job；除 `9.8` 中只能写
  `bump-download/<GAMEVER>` 的 artifact publisher 外，不允许其他主仓库 contents writer；
- 下载 exact verified release bundle；
- 从 release manifest 读取 intended BinSync target-state digest，并重新查询 remote refs，要求已与
  verified candidate 完全一致；
- tag absent：创建直接指向 source SHA 的 tag；
- tag present：必须已经指向 source SHA；
- 创建或恢复相同 identity 的 draft Release；
- asset 不存在：上传；已存在：remote hash 必须完全一致；
- 禁止 `--clobber`；
- 上传后复验 remote asset name、size、digest；
- 所有条件满足后 draft → published；
- published Release 已完全一致时幂等成功，否则失败。

### 10.8 失败恢复

- analysis/byte comparison 失败：不生成远端副作用，回 source PR 修复；
- 新 GAMEVER artifacts 缺失：不启动 release analysis，回版本 PR/bootstrap workflow 补齐；
- hosted verification 失败：不推 BinSync、不发布 Release；
- 部分 BinSync refs 已推送：相同 candidate ref 幂等复用，其余继续；任一 remote divergence 失败；
- BinSync 全部成功、Release 尚未发布：重跑复验 exact BinSync receipt 后恢复 draft/publish；
- tag 已创建、draft 未完成：相同 identity 重跑；
- 部分 Release assets 已上传：相同 hash 复用，不同 hash 失败；
- published Release 已存在：仅 exact identity/content 视为成功；
- 禁止用新 build ID 绕过同 version/source 的既有 draft 或 BinSync candidate identity；
- Actions Artifact 过期时，只有 source SHA 仍满足 immutable preflight 才允许重新 full-build，并要求结果
  与 Git truth、既有远端 BinSync refs/draft assets 一致。

## 11. Release bundle 与 manifest

### 11.1 Bundle layout

```text
release-bundle/
  gamesymbols/
    <gamever>.yaml
    <gamever>.metadata.yaml
  gamedata/
    <gamever>/...
  archives/
    gamedata-<gamever>.7z
    gamebin-<gamever>.7z
  release-manifest-<version>.json
  SHA256SUMS-<version>.txt
```

`gamedata-<gamever>.7z` 至少包含：

- `configs/<gamever>.yaml`；
- `bin_artifacts/<gamever>`；
- snapshot 与 metadata；
- `gamedata/<gamever>`；
- exact SDK content/identity；
- 当前消费者兼容所需的 binary 内容。

`gamebin-<gamever>.7z` 保持 binary-only，不包含 per-symbol YAML、IDB、BinSync repos 或 sidecars。

### 11.2 Release manifest

canonical JSON manifest 至少绑定：

- schema/version/build/workflow identity；
- source SHA 与 commit subject；
- GAMEVER 与 configured inventory；
- analysis config digest；
- binary inventory、Depot/download identity；
- SDK gitlink 与 C++ validation identity；
- artifact inventory digest；
- canonical serializer/producer-group contract digest；
- IDA kernel/runtime 与 warm IDB selection digest；
- full rebuild execution evidence；
- snapshot/metadata/gamedata/generator digests；
- BinSync candidate digest、target refs/commits 与 intended remote target-state digest；
- 每个 public payload asset 的 path、size、SHA-256。

manifest 不记录自身 digest，避免自引用。`SHA256SUMS` 包含 public payload assets 与 manifest，不包含自身。
内部 BinSync bundles 只通过 candidate/target-state digest 绑定，不作为公开 assets。实际 publication receipt
是运维恢复证据；Release publisher 必须独立读取 remote state 对照 manifest，不能把 publisher 自报 receipt
当作 correctness 依据，也不能在 BinSync push 后修改已验证的 release manifest。

## 12. Pages 迁移

当前 Pages 从 main tracked `gamesymbols/gamedata` 构建。cutover 后改为：

1. `publish-release` 完成后 dispatch Pages，并传 immutable release tag/source SHA；
2. Pages workflow 下载对应 published Release assets；
3. 验证 release manifest、SHA256SUMS、snapshot/metadata/gamedata digests；
4. 只从已验证的 release staging 构建静态资产；
5. 保留现有 immutable pages-snapshots/CDN byte verification 语义；
6. 日常 source/artifact PR 不再因 tracked generated outputs 触发 Pages publish。

Pages hosted job 不接受 Actions Artifact 作为长期历史 source；公开历史由 immutable GitHub Releases 提供。

## 13. Accepted-bin、IDB 与 persisted workspace

### 13.1 Accepted-bin

`PERSISTED_WORKSPACE/bin/<gamever>` 降级为 binary-only cache：

- 允许 configured binaries 与明确 allowlisted side files；
- 禁止 per-symbol YAML、snapshot、gamedata、release manifest；
- 不参与 Release truth；
- 更新失败不回滚已发布 Release；
- 可从 Depot/Release gamebin asset 重建。

### 13.2 Warm IDB

- warm IDB generation 继续独立于 artifacts；
- selection 绑定 binary inventory 与 IDA runtime；
- Release full rebuild 恢复 exact generation；
- `-rename` 修改的是 release-local IDB/BinSync working state，不回写 warm neutral generation；
- warm generation 不包含已应用 source-owned symbol rename 的可变 truth。

### 13.3 Legacy YAML cleanup

在 per-GAMEVER lock 下：

1. 验证新的 binary-only materialization；
2. inventory legacy accepted-bin YAML；
3. 创建 canonical exact-hash backup；
4. 支持 `.incoming` 与 partial deletion 幂等恢复；
5. 删除 legacy YAML；
6. 再验证 accepted-bin allowlist。

清理不是 cutover correctness 的前置读取源；新代码从启用时起必须忽略 persisted YAML。

## 14. 一次性数据 bootstrap

### 14.1 Source of truth

bootstrap 输入是 16 份当前 contract 可验证的 tracked canonical snapshots，不是 private `bin`。

输入约束：

- snapshot canonical bytes 通过；
- config digest、analysis output contract、required/optional paths 通过；
- snapshot files payload 与 binary metadata schema 通过；
- 不读取 private extra/stale YAML；
- 不因 private required 缺失而降低 snapshot trust。

### 14.2 解包过程

迁移工具必须：

1. 枚举 configured gamevers；
2. load/validate snapshot against exact config；
3. 枚举 snapshot `files` payload；
4. 验证每个 key 属于 formal contract；
5. 用新的 Source2 central serializer 写入
   `bin_artifacts/<gamever>/<module>/<artifact>.yaml`；
6. 拒绝 case collision、link/reparse、path escape、extra path；
7. 计算 destination `path + size + sha256` inventory；
8. 从 destination artifacts 重建 snapshot document；
9. 要求重建后的 `files` payload 与 source snapshot 语义完全一致；
10. 要求 required 全部存在，optional presence 与 source snapshot 一致；
11. 记录每 gamever file count/digest 与 aggregate digest；
12. 预计 materialize 51,299 个 files；数量必须由 contract 动态计算，测试不硬编码易变总数。

旧 snapshot 的 publication timestamp、binary metadata 等非 per-symbol fields 不写入 artifact YAML；它们在
Release candidate 中从 exact source/binary identity 重新生成。

### 14.3 5 万文件的 Git 成本与缓解

基线 tracked files 为 2,471；迁移后约 53,770，约 21.8 倍。内容约 15 MiB，主要成本是 NTFS metadata、
Defender、checkout、index 和 watcher。

实施前在临时 worktree 记录：

- fresh checkout；
- warm/cold `git status`；
- branch switch（artifact tree unchanged/changed）；
- repository contract scan；
- Actions checkout/upload/download；
- formatter/test discovery；
- IDE/Defender 影响。

无论 benchmark 结果如何，本计划已决定使用 per-symbol Git truth；benchmark 用于优化与容量规划，不再回退到
monolithic snapshot truth。

缓解措施：

- 不需要 artifacts 的 jobs 使用 sparse checkout；
- 单 GAMEVER jobs 只 materialize所需 artifact subtree；
- hosted repository-wide verifier 优先从 Git tree/blob 读取，不无条件 checkout 全部 files；
- self-hosted runner 启用受控 Git FSMonitor/untracked cache；
- formatter、frontend、IDE watcher 排除 `bin_artifacts`；
- serializer 不重写 bytes 未变化的文件；
- bootstrap review 以生成器、contract、per-gamever counts/digests 为单位；
- 监控 Git pack/repository growth，避免日常全树机械重写。

## 15. 删除与替换的旧机制

cutover 同时删除或重构：

- PR CI 向 source PR head push snapshot/gamedata 的 publication path；
- generated-output branch `gamesymbols/build/*`；
- generated-output PR creation/validation；
- `.github/workflows/validate-generated-output-pr.yml`；
- `.github/workflows/promote-release-after-output-merge.yml`；
- abandon/cleanup staged-release workflows 和 skills；
- output PR route、trusted author/output branch parser；
- PR index、READY、PROMOTION_STARTED、PROMOTION_COMPLETE 状态机；
- private release-staging correctness source；
- stage/finalize/reconstruct/promote-bin/finalize-promotion 命令；
- tracked `gamesymbols/**`、`gamedata/**`、`release-manifests/**`；
- accepted-bin YAML reuse；
- normal snapshot → `bin` restore；
- same-version content republish 与 `--clobber`。

现有自动 version bump/release dispatch 改为：version PR bootstrap → artifact-bearing head 普通验证 →
merge → repository artifact preflight → Release dispatch。禁止“先合并无 artifacts 的 bump，再在 Release
中首次生成”的旧顺序。

可保留并重用：

- canonical snapshot codec 与 candidate guards；
- gamedata candidate/generator contracts；
- C++ validation；
- binary hashing/inventory helpers；
- warm IDB generation/restore；
- repository/version/source validation；
- filesystem locks 与 recoverable atomic operations；
- Pages immutable asset verification；
- binary-only accepted-bin materializer。

## 16. Cutover 方案

### 16.1 PR A：trust bridge/bootstrap

先合并小型、行为保持兼容的 trust bridge：

- trusted base planner；
- prospective merge tree binding；
- forthcoming artifact schema recognition；
- Merge Queue required-check wiring；
- cutover feature flag/compatibility routing；
- 不启用 `bin_artifacts` reader/writer；
- 不删除旧 outputs/workflows。

PR A 必须先进入 default branch，使 PR B 不能用自己携带的 planner 验证自己。

### 16.2 PR B：atomic migration

PR B 包含按逻辑分离的 commits，但作为一个不可拆分的最终 cutover 合并：

1. formal contract 与 producer groups；
2. binary/artifact 双根 API；
3. central canonicalizer；
4. snapshot bootstrap tool 与 51,299 个 artifacts；
5. trusted PR isolated rebuild；
6. Release full rebuild + `-rename`；
7. internal BinSync candidate、hosted verify 与 protected publishers；
8. Pages Release input；
9. tracked generated output 和旧 workflow/state machine 删除；
10. docs、skills、Basic Memory 更新。

PR B 合并前冻结：

- 新 release dispatch；
- artifact/config/producer/source changes；
- generated-output PR creation；
- BinSync schema/default-branch maintenance。

freeze 期间重新基于最新 main：

- regenerate bootstrap artifacts；
- 重新计算所有 inventory digests；
- 重新生成 prospective merge tree；
- 完成 full PR validation。

不得出现“新 writer 写 `bin_artifacts`，旧 candidate 仍读 `bin`”或“Git 已删除 snapshot，Pages 仍从 main
读取”的中间可合并状态。

### 16.3 合并前 drain

1. 完成、恢复或明确 abandon 所有 release staging；
2. 确认无 open generated-output PR；
3. 审计两个现存 `gamesymbols/build/14174/*` remote branches，确认无 recovery value 后再按授权删除；
4. 备份 `PERSISTED_WORKSPACE/bin`、release staging、BinSync local repos 与 manifests；
5. 记录最后一次旧 release dry run 基线；
6. 配置并验证 `artifact-bootstrap`、`release`、`binsync-release` environments、reviewers、PAT expiry/rotation、
   GitHub App scopes 与 branch/tag rulesets；
7. 启用 Merge Queue/strict required checks；
8. 验证 fork、PAT actor、tag 与 direct-push policy。

### 16.4 合并后顺序

1. 合并 PR A；
2. 等待 required checks/branch policy 生效；
3. 重新验证并合并 PR B；
4. 运行 non-publishing full Release build；
5. 验证 hosted release/BinSync candidates；
6. 使用 sandbox version 执行 protected BinSync + draft/publish；
7. 验证幂等重跑；
8. 执行 legacy accepted-bin YAML cleanup；
9. 更新 branch protection required checks；
10. 解除 source/release freeze。

## 17. Rollback

rollback 不是只 revert workflow。

必须保留：

- cutover 前最后一版 tracked snapshot/gamedata/manifests 的 Git history；
- 显式 `bin_artifacts -> isolated bin YAML` compatibility hydrate tool；
- accepted-bin backup 与 cleanup receipts；
- BinSync publication receipts 与 pre-push expected refs；
- draft Release identity 与 assets digest。

回滚规则：

- 已发布的新模型 Release 不删除、不覆盖；
- 已 fast-forward 发布的 BinSync refs不 force-reset；必要时用新的显式修复 commit；
- 恢复旧 accepted-bin include 前先验证 compatibility hydrate 与 Git artifact digest；
- 已开始的新 draft 必须先完成、精确恢复或按受控 identity 流程处理；
- rollback branch 仍须通过 trusted merge validation，禁止直接 push；
- 若旧 workflow 需要 tracked outputs，必须从最后可信 commit 或 immutable Release 显式恢复，不能从
  private mutable bin 猜测。

## 18. 测试策略与质量门禁

本迁移改变共享路径契约、PR 信任边界、Release 状态机和跨 repository BinSync publication，采用：

- Level 2：TDD；
- Level 3：独立 code review；
- Level 4：completion verification 与真实 workflow 验收。

### 18.1 单元与合同测试

必须覆盖：

- binary/artifact root 完全分离；
- cross-module path contained semantics；
- `source_alias` 不创建第二 owner；
- producer-group order、winner、zero/multiple payload、fingerprint/invalidation；
- analyzer read/write/skip/oldgamever/post-process/runtime classifier；
- preprocessor 与 Agent 输出统一 canonical rewrite；
- Source2 category fields、nested mapping、UTF-8/LF、atomic write；
- required/optional/extra/stale/case collision；
- symlink/reparse/path traversal；
- snapshot pack/candidate/store 从正确 root 读取；
- restore 不修改 binary 或 tracked expected；
- artifact A/M/D/R/C → owner group/downstream；
- artifact-only PR 不能产生空计划；
- trusted plan/source/config/artifact manifest tamper；
- fork planner/empty-plan bypass；
- new GAMEVER 无 base artifacts → `bootstrap_required`，不能 empty/light/pass；
- new GAMEVER bootstrap 必须执行 `-force_all -rename`，只产生隔离 local BinSync prepare，且 remote refs 不变；
- bootstrap candidate changed-path allowlist、head drift、provenance 与 PAT fast-forward publication；
- PAT 不进入 self-hosted bootstrap job，不泄漏到 Git config/log/artifact/cache；
- hosted PAT publisher 不执行 prospective merge payload，只允许目标 repository/ref/path；
- PAT artifact commit 后必须触发 synchronize，并在 artifact-bearing head 重新 exact-byte validation；
- publication loop prevention、PAT expiry/rule rejection 与 concurrent head update；
- Release preflight 拒绝 configured-but-unmaterialized GAMEVER；
- selected groups 全部实际执行；
- exact inventory 和单字节 drift；
- merge queue tree binding/base advance revalidation；
- Release `-force_all -rename` 使用 fresh actual root；
- checkout expected 不被 full rebuild 修改；
- local BinSync changes 在 gate 前不 push；
- BinSync bundle allowlist、bundle verify、remote-head/fast-forward/idempotency；
- partial BinSync push recovery 与 divergence refusal；
- release bundle allowlist、manifest canonical、asset tamper；
- tag/draft/published immutability；
- published Release 禁止 clobber；
- accepted-bin 不包含/materialize YAML；
- warm IDB identity 不受 artifact content 影响；
- Pages 只消费 verified immutable Release inputs。

重点测试模块预计包括：

- `tests/test_analysis_planner.py`；
- `tests/test_binary_and_symbols.py`；
- `tests/test_gamesymbol_snapshot_config.py`；
- `tests/test_gamesymbol_snapshot_ops.py`；
- `tests/test_snapshot_candidate.py`；
- `tests/test_gamesymbol_pr_validation.py`；
- `tests/test_bin_artifact_contract.py`；
- `tests/test_migrate_bin_artifacts.py`；
- `tests/test_release_bundle.py`；
- `tests/test_release_publish.py`；
- `tests/test_release_workflow.py`；
- `tests/test_release_workflow_guards.py`；
- `tests/test_idb_cache.py`；
- 新增 `tests/test_binsync_publish.py` 与 workflow behavior tests。

测试断言 Python contract 和行为，不以文本搜索锁定 workflow、skill、docs、frontend 或配置内容。

### 18.2 数据迁移验证

- 16 份 source snapshot 全部通过现有 trust probe；
- 解包后的 required/optional presence 与 source snapshot 一致；
- 预计 51,299 文件，但以动态 contract 结果为准；
- artifact → snapshot round trip 的 `files` payload 语义完全一致；
- 两次独立 bootstrap 输出 inventory 与 bytes 完全一致；
- private bin 的 50 missing required/1,295 extra 不进入 destination；
- Git tracked artifacts 与 generated inventory 完全一致；
- Git 不再跟踪 versioned release outputs。

后续新 GAMEVER 另验证：

- empty-root bootstrap 生成完整 required/present-optional inventory；
- prior-GAMEVER/no-old-baseline 策略显式且可复现；
- bootstrap 执行 `-force_all -rename` 并完成 local-only BinSync prepare，但不产生 BinSync/tag/Release remote
  side effects；合并后 Release 重新生成正式 BinSync candidate；
- PAT/受控人工 patch 带回 PR 后，normal validation 可从 Git expected bytes 完整复验。

### 18.3 PR 集成验证

- 正确 source + closure artifacts 通过；
- 缺直接 output、缺 downstream、额外/stale、一字节错误失败；
- 两个互不相干 artifact PR 可无冲突合并；
- 两个修改同 artifact 的 PR 产生真实冲突或重新验证；
- PR A 合并后 PR B 的 merge tree 自动更新并重跑；
- 新 GAMEVER 初始 PR 不可在无 artifacts 时合并；
- bootstrap branch head 漂移时拒绝 PAT push；
- artifact-bearing bootstrap commit 进入普通 Merge Queue validation；
- producer alternative 变化使整个 group invalidated；
- shared serializer change 扩大到所有 affected gamevers；
- fork 无法使用 self-hosted runner/secrets；
- planner/head tamper 不能绕过。

### 18.4 Release 与外部验收

- target GAMEVER 两个 fresh full rebuild exact-byte 一致；
- `-force_all -rename` 实际执行全部 planned groups；
- local BinSync candidate 在 hosted verify 前无 remote write；
- self-hosted build 无主仓库/BinSync publish credentials；
- hosted verifier 无写权限；
- protected BinSync job 只写 allowlisted repos/refs；
- BinSync partial push 后 exact rerun可恢复；
- remote divergence 与 non-fast-forward 拒绝；
- PAT artifact publisher 是唯一 source-branch contents-write 特例，且只能更新对应
  `bump-download/<GAMEVER>`；protected Release job 是唯一 tag/Release/assets publisher；
- release dry run 完成 build → upload → hosted verify，不创建 remote refs/tag/Release；
- sandbox version 完成 BinSync push、draft assets、publish 和幂等重跑；
- tag 指向 source SHA；
- remote assets、manifest、checksums、BinSync receipts exact；
- Pages 从 published Release 构建并完成 CDN byte verification。

### 18.5 完成前命令

按实施时仓库支持的命令执行并如实记录，至少包括：

```powershell
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py redis-integration -b --durations 30
uv run python tests/run_test_suite.py release-integration -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
git diff --check
```

并运行仓库支持的 action/workflow validation、Pages tests、C++ gate、artifact bootstrap/rebuild integration 与
真实 non-publishing Actions run。关键外部验收无法执行时不得声明迁移完成或可合并。

## 19. 实施顺序

1. 增加 trust bridge 与 merge-tree tests；
2. 增加 producer-group/formal inventory tests；
3. 实现双根 contract；
4. 实现 Source2 central canonicalizer 与 producer finalization；
5. 修改 analyzer、snapshot/candidate/store/reference/downstream readers；
6. 实现 snapshot-driven bootstrap tool；
7. 生成并验证 51,299 个 source-owned artifacts；
8. 接入 repository artifact contract；
9. 重构 trusted PR planner 与 isolated rebuild；
10. 接入 Merge Queue required check；
11. 实现新 GAMEVER bootstrap、受控 artifact publication 与二次 validation；
12. 实现 Release fresh full rebuild + `-force_all -rename`；
13. 实现 internal BinSync candidate 与 hosted verifier；
14. 拆分 BinSync local prepare 与 protected publisher；
15. 实现 immutable protected Release publisher；
16. 迁移 Pages Release input；
17. 删除旧 tracked outputs/generated-output promotion；
18. 执行 drain、freeze、PR A → PR B cutover；
19. 完成 new-GAMEVER bootstrap drill、dry run、sandbox publish、legacy cleanup；
20. 独立 code review、全量 completion verification 与文档/Memory 更新。

## 20. 验收标准

以下条件全部满足才可声明迁移完成：

- `bin_artifacts` 是 per-symbol YAML 的唯一正常 Git truth；
- source PR 只提交 source change 与 computed affected/downstream artifacts；
- 新 GAMEVER 的 config/download identity 与完整 artifacts 在同一版本 PR 原子进入 main；
- 无 artifacts 的新 GAMEVER bootstrap run 不能直接满足 required check，必须在 artifact-bearing head
  重新 exact-byte validation；
- 新 GAMEVER bootstrap 完整执行 local-only `-force_all -rename`；它验证 rename/BinSync prepare，但只有合并后
  Release 重新生成的 BinSync candidate 才允许正式发布；
- 新 GAMEVER artifact publication 使用 hosted job + 专用 fine-grained PAT，PAT 不进入 self-hosted
  bootstrap job，且只能 fast-forward push 对应 `bump-download/<GAMEVER>` branch；
- Git 不跟踪 versioned snapshots、metadata、gamedata、release manifests；
- formal inventory 覆盖 required/optional/cross-module/source-alias/producer-group 语义；
- private `bin/**/*.yaml` 不参与 correctness；
- artifact-only/source/config PR 都能正确计算 affected groups；
- Merge Queue 验证 exact final combination；
- PR 在 isolated root 重跑并与 Git blobs 完整 exact-byte 比较；
- fork、planner tamper、empty-plan 不能绕过 required check；
- Release 对目标 GAMEVER 完整执行 fresh `-force_all -rename`；
- Release preflight 拒绝 configured-but-unmaterialized GAMEVER，且 Release 从不首次创建 source truth；
- Release rebuilt artifacts 与 source truth exact-byte 一致；
- `-rename` 产生的 BinSync changes 只在所有 build/hosted gates 后推送；
- BinSync publisher 权限与主仓库 publisher 权限隔离；
- BinSync publish fast-forward、idempotent、可恢复且拒绝 divergence；
- snapshot、metadata、gamedata、C++ evidence、archives 可从 source SHA + binary identity +
  `bin_artifacts` 重建；
- self-hosted build 没有主仓库 contents write/Release 权限；
- hosted verifier 无写权限并完整复验两个 candidates；
- PAT artifact publisher 是唯一 source-branch contents-write 特例；`publish-release` 是唯一
  tag/Release/assets publisher；
- tag 直接指向 source SHA；
- published Release 不允许覆盖；
- accepted-bin/IDB 明确为 binary/cache 层且不含 artifact truth；
- Pages 仅消费 published immutable Release；
- 不存在 generated-output PR、output branch correctness 或独立旧 promotion workflow；
- 全量测试、repository contract、两次 fresh rebuild、C++ gate、release dry run、sandbox publish、
  `git diff --check` 均有真实通过证据。

## 21. 主要风险与应对

1. **双根漏改**：任一 reader 继续读 private `bin` 会形成第二 truth。通过全仓精确搜索、negative tests 和
   runtime path reporting 约束。
2. **多 producer 非确定性**：inline/noinline alternatives 可能产生不同 bytes。使用显式 ordered group、winner
   evidence 与 conflicting-output failure。
3. **自比较绕过**：在 checkout 原地重跑会 skip 或覆盖 expected。actual root 强制位于 checkout 外。
4. **Merge Queue 缺失**：并行 PR 分别通过不证明组合正确。没有 exact merge-tree required check 不允许 cutover。
5. **canonical drift**：PyYAML/runtime/Agent writer 差异导致 byte mismatch。central finalizer 与 pinned environment
   是唯一 bytes trust boundary。
6. **5 万文件性能**：checkout/status/Defender/CI 变慢。使用 sparse checkout、Git-object validation、watcher
   exclusions 和稳定不重写策略。
7. **BinSync 过早副作用**：后续 gate 失败但 remote 已变化。build 只产 candidate，protected publisher 在 hosted
   verify 后运行。
8. **BinSync partial publish**：多 repository push 无法原子完成。per-ref exact receipt、fast-forward、idempotent
   resume 与 divergence refusal。
9. **权限泄漏**：self-hosted runner 持有主仓库或 BinSync write token。使用三个彼此隔离的 protected
   publishers、专用 PAT actor 与最小 GitHub App scope。
10. **旧 stage 不兼容**：READY/PROMOTION_STARTED 无法套用新 schema。cutover 前 drain/abandon，不强行迁移。
11. **同版本覆盖**：保留 republish/`--clobber` 破坏不可变性。相同内容幂等，不同内容必须新版本。
12. **Actions retention 误用**：candidate 不能作为长期 truth。Git source、remote BinSync refs、draft/published
    Release 才是持久状态。
13. **Pages 回归**：删除 tracked outputs 后 Pages 仍读取 main。Pages Release input 必须在同一 atomic cutover
    生效。
14. **archive 丢 artifact**：gamedata archive 未显式加入 `bin_artifacts`。bundle allowlist/manifest/hosted verify
    强制覆盖。
15. **rollback 跨系统不原子**：Git、BinSync、Release 无法整体 revert。使用 immutable identity、forward repair
    与逐系统 receipts，不 force-reset 已发布状态。
16. **新 GAMEVER 先合并后补 artifact**：main 暂时违反 source-truth contract，Release 被迫成为首次
    producer。使用 version-PR two-pass bootstrap、PAT/受控人工 patch publication 和 artifact-bearing head
    二次验证；
    repository/Release preflight 对缺失 artifacts fail closed。
17. **PAT 泄漏或越权**：把 publication PAT 放进 self-hosted analysis job 会让 prospective merge payload
    获得 repository write。PAT 只存在于 trusted hosted publisher 的 protected environment，使用专用账号、
    short expiry/rotation、repository scope、rulesets 与 ref/path/head locks；PAT 不具备 main/tag ruleset bypass、
    Actions/admin 权限。`Contents: write` 不能原生缩到单 branch/path，且包含部分 Release API authority；这是
    PAT 方案的明确残余风险，依靠 trusted code、environment review、API audit 与快速吊销控制。

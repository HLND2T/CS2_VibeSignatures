[返回中文 README](../../README_CN.md) | [English](../en/ci-cd.md)

# CI/CD 与 Jenkins 工作流参考

## Pull Request 与 Merge Queue

`source-artifact-required.yml` 使用 default-branch planner 绑定 exact prospective merge tree。light change 运行 hosted tests；full change 计算 affected producer groups 与 downstream closure，再由 `pr-self-runner.yml` 对每个 affected GAMEVER 执行 empty-root rebuild，并按 [anchor drift 契约](#anchor-drift-契约)与 `bin_artifacts` Git blobs 比较。

因此 source/config/reference PR 必须同时包含计算出的 `bin_artifacts` change。PR CI 绝不把 `gamesymbols/`、`gamedata/` 或 release manifest 写回分支。新 GAMEVER bootstrap 是唯一 source-branch writer：受 environment 保护的 hosted publisher 只能 fast-forward `bump-download/<GAMEVER>`，artifact-bearing head 必须再次通过 validation。

稳定 required checks 为 `source-artifact-required` 与 `pr-validate`。Merge Queue 还必须通过 GitHub ruleset Required Workflow（或独立 trust root）安装验证，防止 prospective workflow change 自行伪造同名 check。

## anchor drift 契约

`LLM_DECOMPILE` producer 由模型自行挑选一条参考指令，再由确定性签名生成器从该指令展开签名，因此两次同样合规的运行可能对同一符号采样到不同指令。PR 与 Release validation 因此按同一条规则比较重建产物与 Git truth：符号身份与已解析的地址/偏移必须逐字节一致，只有描述“如何定位该符号”的字段允许不同。

| category | 允许漂移 | 必须钉死 |
| --- | --- | --- |
| `gv` | `gv_sig`、`gv_sig_va`、`gv_inst_offset`、`gv_inst_length`、`gv_inst_disp` | `gv_name`、`gv_va`、`gv_rva` |
| `vfunc` | `vfunc_sig`、`vfunc_sig_disp` | `func_name`、`func_va/rva/size`、`func_sig`、`vtable_name`、`vfunc_offset`、`vfunc_index` |
| `structmember` | `offset_sig`、`offset_sig_disp` | `struct_name`、`member_name`、`offset`、`size` |
| `func`、`vtable`、`patch` | 无 | 全部字段 |

搜索策略开关（`*_max_match`、`*_allow_across_function_boundary`）保持钉死：放松它们等于接受一次不同的搜索，而不是同一次搜索的等价采样。缺少已解析事实的 artifact 仍走逐字节门禁，因为此时签名本身就是唯一真相。每一条被接受的漂移都会按 artifact 打印，其余差异一律 fail closed。

由于重建产物可能与 checkout 合法地不一致，它只作为可复现性证据：Release 发布的 snapshot、gamedata、BinSync projection 与 archive 全部来自已提交的 `bin_artifacts` 树。

## Warm IDB 与 accepted binaries

PR 与 Release analysis 都调用 `warmup-idb.yml`，将 configured binary hashes 和 IDA runtime 绑定到 immutable cache generation。accepted-bin 是 exact configured-binary cache：YAML、IDA databases、BinSync state 与未声明 side files 均被拒绝。这些 cache 只用于性能，不是 symbol truth。

## Immutable Release pipeline

version source commit 进入 default branch 后：

1. source preflight 证明目标 GAMEVER 有完整 tracked artifact tree；
2. hosted job 依据 tracked binary lock 为该 GAMEVER 创建并初始化缺失的 per-module BinSync remote，绑定同一 immutable source SHA，且在 self-hosted 只读代理之外运行：新 GAMEVER 尚无任何 remote，而 builder 只会 clone 它们；
3. self-hosted builder 执行 fresh `-force_all -rename`，按 [anchor drift 契约](#anchor-drift-契约)校验重建产物与 tracked tree，并从已提交的 `bin_artifacts` 生成无凭证的 BinSync/Release candidates；
4. hosted jobs 独立验证 candidate bundles、archive allowlists、manifest、checksums、C++ evidence 与 BinSync target-state identity；
5. protected BinSync publisher 只执行 fast-forward ref updates；
6. protected Release publisher 创建/复用 source tag，上传 exact immutable assets，发布一次并 dispatch Pages；
7. Pages 只 hydrate published Release assets，验证 manifest/SHA256SUMS/archive inventories，构建全部已发布版本并验证 CDN bytes。

workflow transaction identity 在 GitHub rerun 之间保持稳定（`run_id`）；`run_attempt` 只属于 transport metadata。
`publish` 保持已发布内容不被覆盖。普通构建和 rebuild-free 的手动入口另提供 `republish`，触发 CLI 可使用
`--mode republish`；自动流程继续使用 `publish`。

手动 rebuild-free 路径（`rebuild-free-release.yml`，`source_artifact_mode: tracked`）直接发布 tracked
`bin_artifacts/<GAMEVER>`，不做 rebuild。它不分析任何内容，因此完全不运行 IDA：`warmup-idb.yml`、BinSync candidate
导出以及 BinSync 的验证与发布都被整体跳过，不读写任何 BinSync remote；二进制由 build job 自身的
`init_gamebin.py prepare` 置备并对 source binary lock 校验。其 Release manifest 中 `binsync`、`ida_runtime_identity`、
`warm_idb_generation`、`warm_idb_cache_key` 均记为 `null`，且 `release_bundle.py` 将其与 source binding mode 双向绑定：
tracked binding 不得声明这些证据，rebuild binding 也不得省略。该绑定只对声明了 `full_rebuild.binding_rule_version`
的 manifest 生效；规则生效前发布的 manifest 不声明该版本，仅豁免这一条规则，因此仍在声明 BinSync 与 warm IDB 的早期
tracked 发布可以继续参与 hydration，其余全部 manifest 校验对它们照旧生效。Pages hydration receipt 会记录它 stage 的
每个 Release 的 binding 规则版本。因此 rebuild-free 发布不会发布 BinSync 符号。

`republish` 要求已有可修改的 Release 和直接指向 commit 的标签。它保留 Release ID 和标签 URL，先转为 draft，
使用绑定旧 SHA 的 lease 移动标签，再更新说明和附件，验证全部字节及 BinSync 目标后重新发布并触发 Pages。
附件 ID 可以变化。目标不存在时应使用 `publish`；GitHub `immutable: true` 的 Release 不允许更新。
源提交及 bundle 的完整验证保持不变，目标在 BinSync 发布前和 Release 实际更新前分别检查。移动标签会使 draft
脱离标签，因此 metadata 更新会先重新绑定真实标签名，之后才做按标签寻址的附件操作；republish 中断遗留的
orphaned draft 也会在重跑时被识别并修复。两处检查都需要 push 权限，因为 GitHub 只向具备该权限的 token
列出 draft Release。

draft 期间下载暂时不可用。上传或校验失败后保留 draft，同 bundle 重跑补齐，不自动回滚旧内容。
若发布请求已生效但最终校验失败，会尝试恢复 draft；恢复失败会明确记录，需检查远端状态。
日志及 job summary 记录 Release ID、旧/新 SHA、bundle digest 和失败阶段。新的 CLI dispatch 会选择当时的
`origin/main`，需要复用原 bundle 时应重跑已有发布 job。两种发布模式共用每版本并发锁。

本地 candidate 命令与 artifact ownership 见 [Snapshot、gamedata 与 C++ 验证](snapshot-and-gamedata.md)。

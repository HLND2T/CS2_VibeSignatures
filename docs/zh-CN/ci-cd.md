[返回中文 README](../../README_CN.md) | [English](../en/ci-cd.md)

# CI/CD 与 Jenkins 工作流参考

## Pull Request 与 Merge Queue

`source-artifact-required.yml` 使用 default-branch planner 绑定 exact prospective merge tree。light change 运行 hosted tests；full change 计算 affected producer groups 与 downstream closure，再由 `pr-self-runner.yml` 对每个 affected GAMEVER 执行 empty-root rebuild，并按 [anchor drift 契约](#anchor-drift-契约)与 `bin_artifacts` Git blobs 比较。

因此 source/config/reference PR 必须同时包含计算出的 `bin_artifacts` change。PR CI 绝不把 `gamesymbols/`、`gamedata/` 或 release manifest 写回分支。新 GAMEVER bootstrap 是唯一 source-branch writer：受 environment 保护的 hosted publisher 只能 fast-forward `bump-download/<GAMEVER>`，artifact-bearing head 必须再次通过 validation。

稳定 required checks 为 `source-artifact-required` 与 `pr-validate`。Merge Queue 还必须通过 GitHub ruleset Required Workflow（或独立 trust root）安装验证，防止 prospective workflow change 自行伪造同名 check。

## Workflow artifacts 保留策略

临时计划、bump/bootstrap 候选包、分析日志、失败诊断及 PR C++ inputs/evidence 使用 `retention-days: 3`，由 GitHub 在上传后 3 天自动过期。
Release 待验证资产包和最终 bundle 保留 30 天；Release C++ inputs/results/evidence 保留 14 天；Pages 临时 artifacts 保留 1 天。
这里控制的是 workflow artifacts，GitHub Release 附件及 S3 binary/IDB cache 使用各自的生命周期。变更只影响新上传的 artifacts，已有文件维持原过期时间。

## Workflow artifact 传输

`actions/download-artifact` 每次 API 调用只发一次请求，因此列取或流式下载 artifact 时的一次连接重置就会让整个 job 失败，
`pr-self-runner` 就曾因 `ListArtifacts: ECONNRESET` 丢掉整次 validation。因此 workflow 的下载统一走
`.github/actions/artifact-download`，它在可信的 workflow revision checkout 上运行 `ci_artifacts.py`
（`.cache-tools` 或 `.ci-tools`，取自 `github.workflow_sha`）：每个请求按有界指数退避重试，归档包与 GitHub 报告的
artifact digest 比对，展开时若某个成员可能逃出目标目录或不是普通文件则直接拒绝。仅把 action 固定到 SHA 只修好了上游
[下载超时未拒绝 Promise 的缺陷](https://github.com/actions/toolkit/pull/2124)，任何瞬时重置依然是致命的。

由此带来一个约束：传输脚本与被调用的 workflow 必须属于同一 revision，因此下载 artifact 的 job 要 checkout
`github.workflow_sha`，而不能复用 base SHA 的工具 checkout。`deploy-pages.yml` 仍直接使用
`actions/download-artifact`，因为这些 job 没有 uv 工具链，也不是 required check。

## anchor drift 契约

`LLM_DECOMPILE` producer 由模型自行挑选一条参考指令，再由确定性签名生成器从该指令展开签名，因此两次同样合规的运行可能对同一符号采样到不同指令。PR 与 Release validation 因此按同一条规则比较重建产物与 Git truth：符号身份与已解析的地址/偏移必须逐字节一致，只有描述“如何定位该符号”的字段允许不同。

| category | 允许漂移 | 必须钉死 |
| --- | --- | --- |
| `gv` | `gv_sig`、`gv_sig_va`、`gv_inst_offset`、`gv_inst_length`、`gv_inst_disp` | `gv_name`、`gv_va`、`gv_rva` |
| `vfunc` | `vfunc_sig`、`vfunc_sig_disp` | `func_name`、`func_va/rva/size`、`func_sig`、`vtable_name`、`vfunc_offset`、`vfunc_index` |
| `structmember` | `offset_sig`、`offset_sig_disp` | `struct_name`、`member_name`、`offset`、`size` |
| `func`、`vtable`、`patch` | 无 | 全部字段 |

搜索策略开关（`*_max_match`、`*_allow_across_function_boundary`）保持钉死：放松它们等于接受一次不同的搜索，而不是同一次搜索的等价采样。缺少已解析事实的 artifact 仍走逐字节门禁，因为此时签名本身就是唯一真相。每一条被接受的漂移都会按 artifact 打印，其余差异一律 fail closed。

由于重建产物可能与 checkout 合法地不一致，它只作为可复现性证据：Release 发布的 snapshot、gamedata 与 archive 全部来自已提交的 `bin_artifacts` 树。

## Warm IDB 与 accepted binaries

PR 与 Release analysis 都调用 `warmup-idb.yml`，将 configured binary hashes 和 IDA runtime 绑定到 immutable cache generation。accepted-bin 是 exact configured-binary cache：YAML、IDA databases、历史分析状态 与未声明 side files 均被拒绝。这些 cache 只用于性能，不是 symbol truth。

持久化由 `tespkg/actions-cache/restore@v1` 和 `/save@v1` 负责，bucket 为
`actions-cache-cs2-vibesignatures`。`win64` environment 需要 `S3_ENDPOINT_URL`、
`S3_ACCESS_KEY_ID` 和 `S3_SECRET_ACCESS_KEY` secrets。URL 只允许 HTTP(S) origin；
`http://HZVM:8333` 解析为 `endpoint: HZVM`、`port: 8333`、`insecure: true`，HTTPS 则为 false。
Runner 必须支持这些 actions 使用的 Node 24 runtime（现有 `actions/checkout@v5` 同样需要）。
关闭 GitHub cache fallback，S3 上传后以独立 lookup 验证对象存在；必需缓存恢复失败会终止 job。

缓存 key 按仓库和版本化 transport namespace 隔离，两种 runner OS 共用 `shared` key。Producer 优先恢复 shared，
再按完整身份读取旧 Windows、Linux、macOS key；验证后将旧 binary cache 和 IDB generation 发布到 shared key，
不删除或覆盖旧对象。`cache-restored` 包含兼容恢复，`cache-hit` 表示命中 shared primary key。
Depot 只归档 source lock 声明的下载文件，
按下载身份与目标文件集合区分，不包含下载器登录状态；accepted binaries 按 source lock 与配置目标集合精确匹配。
恢复命中后先验证文件集合与哈希；仅 depot 命中时先物化 accepted binaries，避免重复下载。
Key 不包含路径分隔符，避免 action 的 Windows `path.join` 改写 key 导致无法恢复。
IDB generation 按现有 binary/IDA identity 复用，每次 producer 都创建新的 lease。
Generation 的 payload/manifest 与当前 run/attempt 的 lease 分开保存，下游使用 producer 的原始 generation、
cache key、lease ID 和 lease SHA-256 精确恢复，不回退选择，也不回写分析后的 IDB。

每个 job 在干净的 `.ci-cache/store/` 暂存恢复结果，`--persisted-root` 只指向该本地暂存目录。
归档使用工作区相对路径，不依赖 runner 盘符、checkout 绝对路径或宿主共享目录。
缓存工具从 workflow SHA 单独检出到 `.cache-tools/`，因此 source SHA 可以早于本次缓存迁移。
本地 restore 仍在文件锁内校验 lease owner、manifest 与全部 binary/IDB，成功后释放本地 lease。
租约有效期仍为 36 天；缺失、过期、损坏或绑定不一致会失败。GitHub rerun 改变 attempt 时，
必须重跑包含 producer 的完整 workflow。远程 lease 是不可变传输副本，本地 release 不回写远程对象。

CI 不再调用共享目录 prune，也不自动删除远程对象或配置 bucket 生命周期；本地文件锁不承担分布式锁职责。
保留 GAMEVER warmup concurrency。首次 S3 未命中会重新置备、预热，S3 迁移前的共享目录缓存不自动导入或删除。
上线验证应从空缓存运行两次，再清空本地 workspace 验证恢复，并检查 binary/IDA 变化、损坏缓存和 S3 失败场景。
GitHub artifacts 继续传递发布候选包与日志；Git 跟踪的 `bin_artifacts` 仍是 symbol truth。

`warmup_idb.py --max-memory-mib <MiB>`（或 `IDB_WARMUP_MAX_MEMORY_MIB`）启用内存准入控制。
Windows 使用聚合 Job Object 上限；Linux 在已有委派权限允许时使用 cgroup v2 子组上限，否则输出
`cap=reservation-only` 和降级原因，改用每 worker 的 `RLIMIT_AS` 与调度进程中的 RSS watchdog。
降级模式没有内核强制的聚合上限，RSS 每两秒采样一次，采样间可能超限；producer 不修改系统 cgroup 委派设置。
兄弟 cgroup 必须仍位于 runner 的委派 unit 内，不能移出到 systemd slice，也不能绕过原叶子组的内存限制；
warmup 收尾时恢复原 cgroup。

`IDB_WARMUP_INITIAL_WORKER_RESERVATION_MIB` 默认 4096 MiB，控制准入预留量；降级时还作为每 worker
的 RSS 上限与地址空间上限（后者最小为 256 MiB）。应根据 IDA 的实际地址空间和常驻内存峰值调整。
基线内存加一个 worker 预留量必须能放入总预算的 85%，否则立即失败。未设置总预算时不启用内存控制；
数据库全部已 warm 时跳过初始化。worker 超限失败会清理半成品 IDB。平台选择依据宿主 OS，而非目标二进制平台。

## Immutable Release pipeline

version source commit 进入 default branch 后：

1. source preflight 证明目标 GAMEVER 有完整 tracked artifact tree；
2. self-hosted builder 执行 fresh `-force_all -rename`，按 [anchor drift 契约](#anchor-drift-契约)校验重建产物，并从已提交的 `bin_artifacts` 生成无凭证的 Release candidates；
3. hosted jobs 独立验证 bundles、archive allowlists、manifest、checksums 与 C++ evidence；
4. protected Release publisher 创建/复用 source tag，上传不可变附件并 dispatch Pages；
5. Pages 验证已发布附件、manifest、SHA256SUMS 与归档清单，构建全部发布版本并验证 CDN bytes。

Self-hosted builder 使用 `release_bundle.py prepare` 校验本地 candidate session，生成可移植的待验证资产包，
此时不生成发布 manifest，也不声明 C++ 成功。`cpp-validation.yml` 在 hosted Windows 和 Ubuntu 上使用同一
snapshot/configuration 和 source SDK gitlink 测试；aggregate 要求两端结果被接受，按 Windows/Linux 顺序合并日志。
Hosted `release_bundle.py finalize` 核对待验证包 inventory 和内容身份，将日志摘要写入现有
`cpp_validation_sha256`，生成最终 manifest/checksums 并验证 bundle。新 manifest 使用 schema 3，读取入口兼容历史 schema 2，
独立 Release verifier 同样重跑两个 hosted ABI。

PR/full bridge 与新 GAMEVER bootstrap 共用这一门禁；bootstrap 等双端结果被接受后才生成 canonical candidate
和 gate evidence，再进入 protected publisher。本地路径/inode 绑定的 session 留在原 job，跨 job 证据绑定
snapshot/configuration/source/SDK 内容。旧版本没有 Linux 用例时报告 `no-tests`，已有 ABI target 不支持时必须失败。

workflow transaction identity 在 GitHub rerun 之间保持稳定（`run_id`）；`run_attempt` 只属于 transport metadata。
`publish` 保持已发布内容不被覆盖。三种构建路径的手动入口均提供 `republish`，触发 CLI 可使用
`--mode republish`；自动流程继续使用 `publish`。

触发 CLI 的 `--workflow full-rebuild` 会向 `build-on-self-runner.yml` 传入 `source_artifact_mode: full-rebuild`。
该模式使用 `-force_all -rename -oldgamever none`，在空的外部输出目录中重建所有配置的 artifacts，old-artifact root
也指向该隔离目录。任何旧版本 artifacts 都不会作为参考或 old-signatures 来源；验证阶段拒绝含 prior GAMEVER 或
非隔离 old-artifact root 的执行证据。普通 `release` 继续自动复用可用的旧版本签名。两者均可使用源码中的静态
preprocessor references，并按相同 anchor drift 契约与目标 GAMEVER 已提交的 artifacts 比对，发布物仍从该 committed
tree 派生。warm IDB 流程保持一致。

rebuild 发布除 `gamebin-<GAMEVER>.7z` 外还会发布 `gamebin-with-idb-<GAMEVER>.7z`：即每个 configured binary 的
warm IDA database（`<binary>.i64`），取自 build 实际分析所用的那一份 generation。本地 `init-gamebin` skill 通过
`init_gamebin.py check-idb <GAMEVER>` 探测该归档，并用 `init_gamebin.py prepare --with-idb` 合并它，从而跳过缓慢的
本机 warmup。该归档与 gamebin 归档同源于同一 binary inventory，因此不依赖磁盘上恰好存在什么 database。

手动 rebuild-free 路径（`rebuild-free-release.yml`，`source_artifact_mode: tracked`）直接发布 tracked
`bin_artifacts/<GAMEVER>`，不运行 IDA 或 warmup；build 通过 `init_gamebin.py prepare` 置备二进制并校验 source binary lock。
其 IDA runtime、warm IDB identity 为 null，也不声明 IDB 归档；rebuild 发布必须提供这些 identity 和完整 IDB 归档。
新 manifest 使用 schema 3，省略已退役的发布字段；读取入口同时支持历史 schema 2，保留原始字节、checksum 和旧说明格式。
历史 evidence 仍按 binding rule version 校验，Pages receipt 记录每个版本。Bootstrap gate evidence 使用 schema 3，
candidate 使用 schema 4，旧临时候选需要重新生成。

`republish` 要求已有可修改的 Release 和直接指向 commit 的标签。它保留 Release ID 和标签 URL，先转为 draft，
使用绑定旧 SHA 的 lease 移动标签，再更新说明和附件，验证全部字节后重新发布并触发 Pages。
附件 ID 可以变化。目标不存在时应使用 `publish`；GitHub `immutable: true` 的 Release 不允许更新。
源提交及 bundle 的完整验证保持不变，目标在发布预检和 Release 实际更新前分别检查。移动标签会使 draft
脱离标签，因此 metadata 更新会先重新绑定真实标签名，之后才做按标签寻址的附件操作；republish 中断遗留的
orphaned draft 也会在重跑时被识别并修复。两处检查都需要 push 权限，因为 GitHub 只向具备该权限的 token
列出 draft Release。

draft 期间下载暂时不可用。上传或校验失败后保留 draft，同 bundle 重跑补齐，不自动回滚旧内容。
若发布请求已生效但最终校验失败，会尝试恢复 draft；恢复失败会明确记录，需检查远端状态。
日志及 job summary 记录 Release ID、旧/新 SHA、bundle digest 和失败阶段。新的 CLI dispatch 会选择当时的
`origin/main`，需要复用原 bundle 时应重跑已有发布 job。两种发布模式共用每版本并发锁。

本地 candidate 命令与 artifact ownership 见 [Snapshot、gamedata 与 C++ 验证](snapshot-and-gamedata.md)。

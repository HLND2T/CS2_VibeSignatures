# 按 submodule hash 缓存 hl2sdk_cs2（per-hash SDK mirror）计划 v2

状态：设计已定，未实施

日期：2026-09-07（v2 已并入评审反馈）

合入决策（2026-09-07）：**一次合入（选项 B）**——消费端改造（`sdk_mirror.py` +
`run_cpp_tests.py` / `release_bundle.py` 参数化）+ 四个 workflow 切镜像，作为一个 PR 原子合入，
不做分步推广（§7.5 已按此更新，§10 问题 1 关闭）。

只读实现决策（2026-09-07）：镜像工作树只读采用**清写位**实现（简单、幂等），不做 ACL 级只读
（§10 问题 2 关闭）。

范围与语义决策（2026-09-07）：`phase-d-validation.yml`（临时入口，`#926` 合并后删除）**不纳入本次**，
保持一次合入范围为长期维护的 4 个 workflow（§10 问题 3 关闭）；`run_cpp_tests.py` 对映射后的
`headers` **不补 `is_file` 断言**，与现状一致只做路径合法性校验（§10 问题 4 关闭）。

评估基线：`main@22a91104`（评审以 `main@30623314` 复核）

## 1. 决策摘要

在 `PERSISTED_WORKSPACE` 下建立**按 SDK gitlink commit 内容寻址的本地只读镜像**，供 self-hosted
各 job 以**绝对路径**消费；**不在 workspace 内创建 junction**。`hl2sdk_cs2` 在 checkout 里保持
未初始化的空子模块，CI 不再触碰它。

```text
镜像目录  = <PERSISTED_WORKSPACE>/sdk_mirror/<40位 gitlink sha>
镜像内容  = 该 commit 的独立 git 仓库：对象库（ls-tree/cat-file 可用）+ 只读工作树
复用规则  = 镜像存在且 HEAD == gitlink 且 status 干净且只读位完好 -> 复用（0 网络）
           否则（缺失 / gitlink 变化 / 损坏 / 非只读）-> 锁内隔离损坏目录并以该 commit 重建
消费方式  = 绝对路径（--sdk-root），不绑定进仓库；仓库内 hl2sdk_cs2 路径不再被消费
```

gitlink 变化即自动重建，gitlink 未变即零网络复用。多个 GAMEVER / 多次 rerun / merge_queue 复验共享
同一份镜像。该方案取代 build job 现用的 submodule actions/cache
（[build-on-self-runner.yml:165-200](.github/workflows/build-on-self-runner.yml#L165-L200)）。

> v1→v2 关键转向：v1「只加 junction、原消费步骤不变」的结论有误——C++ 路径检查会拒绝仓库外镜像
> （评审第 1 点实证：`relative source path escapes repository root: hl2sdk_cs2/public`）。v2 改为
> **显式适配 C++ / release bundle 的 SDK 根路径**，从而取消 workspace junction，连带消除 v1 的
> 绑定规则、checkout 前残留链接窗口、mklink 权限等全部问题。

## 2. 背景与动机

### 2.1 现状：哪些 self-hosted job 每次全量拉 SDK

`.gitmodules` 把 `hl2sdk_cs2` pin 到 `HLND2T/hl2sdk` 的 `cs2_vibe`（无 nested submodule）：

| workflow / job | 现状 SDK 拉取 | 需改 |
|---|---|---|
| `build-on-self-runner.yml` `build` | actions/cache + `git submodule update --depth 1` | 是（pilot） |
| `pr-self-runner.yml` `validate` | `actions/checkout` `submodules: recursive` | 是 |
| `source-artifact-full-bridge.yml` `validate` | `actions/checkout` `submodules: recursive` | 是 |
| `bootstrap-new-gamever-artifacts.yml` `build-bootstrap-candidate` | `git submodule update --depth 1`（:85-86） | 是 |
| `phase-d-validation.yml` `compare` | `submodules: recursive`（临时入口，#926 后删除） | 不纳入（§7.4 单独补丁可选） |

### 2.2 为什么现状不够

- **PR / full-bridge / phase-D / bootstrap**：无缓存，每次从 `github.com` git 协议全量拉取。
- **build 的 actions/cache**：缓存在 GitHub 云端；命中也要 restore 下载 + save 上传两次网络往返，
  受仓库总量与逐出策略约束。

### 2.3 复用粒度是 commit，不是 GAMEVER

SDK 的复用粒度是父仓库记录的 gitlink commit，同一 commit 跨 gamever / rerun 共用；按 hash 只存一份。

## 3. SDK 消费端事实核查（约束来源）

已核对当前消费者，SDK 被三种方式使用：

1. **工作树文件（C++ 编译）**：`run_cpp_tests.py` 按 config 的
   `include_directories`/`headers` 相对路径（`hl2sdk_cs2/public/...`）编译
   （[configs/14178b.yaml:13573-13579](configs/14178b.yaml#L13573-L13579)）。
   - 解析函数 `_resolve_source_path`（[run_cpp_tests.py:94-104](run_cpp_tests.py#L94-L104)）对相对路径
     `resolve()` 后强制要求仍在 `source_root`（= 仓库根，[run_cpp_tests.py:486](run_cpp_tests.py#L486)）
     内，因此**任何把 SDK 放到仓库外的做法（含 junction）都会被拒绝**。这是必须改造点。
   - C++ 步骤只读 SDK：写临时对象文件到 `tempfile`，不改头文件；CI 亦未触发 `fix-cppheaders` 写路径。
2. **SDK 自己的 git 对象库（release 归档）**：`release_bundle.py::_sdk_inventory/_copy_sdk` 用
   `git -C <sdk_root> rev-parse/ls-tree/cat-file` 生成归档与 inventory（[release_bundle.py:125-155](release_bundle.py#L125-L155)）。
   内容寻址，只要求 `<sdk_root>` 是含该 commit 完整 tree/blob 的 git 仓库；与「是否注册为 submodule」
   无关。评审已实证 `_sdk_inventory` 经 junction 与直接路径结果一致 → 接受外部仓库路径。
3. **gitlink 元数据读取**：`rev-parse <sha>:hl2sdk_cs2` / `ls-tree -- hl2sdk_cs2`
   （[binsync_candidate.py:676](binsync_candidate.py#L676)、[release_artifact_rebuild.py:106](release_artifact_rebuild.py#L106)、
   [release_bundle.py:737](release_bundle.py#L737)）从父仓库 Git 对象读取，不依赖工作区子模块注册。

**消费端结论**：C++ 必须适配（引入可信外部 SDK 根）；release 对象库读取天然兼容外部路径；gitlink
元数据读取不依赖注册。改造范围因此扩展到 `run_cpp_tests.py` 与 `release_bundle.py` 的 SDK 根解析。

## 4. 目标与非目标

### 4.1 目标

1. self-hosted job 在 gitlink 未变时对 SDK **零网络拉取**（含去掉 actions/cache 云端整包往返）。
2. gitlink 变化时自动重建；新 hash 按精确 commit **下载所需快照**（空仓库 fetch 该 commit 整树，不跨
   hash 复用对象），同 hash 复用零网络。
3. 同一 self-hosted 机器上多 job / 多 GAMEVER 共享同一份镜像。
4. 适配 `run_cpp_tests.py` / `release_bundle.py`，让已校验的 SDK 根可位于仓库外（受限例外），其余
   相对路径越界检查不变。
5. 保持全部 provenance 不变量（§6），release 发布门禁不削弱。
6. 纳入 bootstrap 消费链（新 GAMEVER 的 self-hosted bootstrap job）。

### 4.2 非目标

- 不改变 `.gitmodules` / SDK pinning / gitlink 语义；bootstrap 的 `.gitmodules` 路由守卫
  （[bootstrap-new-gamever-artifacts.yml:83](.github/workflows/bootstrap-new-gamever-artifacts.yml#L83)）保留。
- 不服务 hosted ubuntu job：`verify-release-bundle.yml` / `publish-release-bundle.yml` 的 verify/publish，
  以及 `source-artifact-required.yml` 的 hosted `test-prospective-tree`（:217）——均无
  `PERSISTED_WORKSPACE`，继续 `submodules: recursive`；是否上 actions/cache 单独评估。
- 不引入自托管 cache 后端 / `ACTIONS_CACHE_URL` / `--reference` alternates。
- 不自动 GC（首次只提供手动 `prune`；自动回收 + 并发保护留待单独决策）。
- 不动 `cs2_depot`、accepted-bin、warm IDB。
- 不在 workspace 建 junction；不为旧方案保留 mklink / 绑定状态机。

## 5. 镜像与消费设计

### 5.1 目录与内容契约

```text
<PERSISTED_WORKSPACE>/
  sdk_mirror/
    <gitlink 40hex>/          # 独立 git 仓库
      .git/                   # 含该 commit 完整 tree/blob（浅 depth 1）
      public/...              # 只读工作树（HEAD == gitlink），供 clang -I 读取
```

- 目录名是 gitlink 的纯函数，内容不可变；同机器所有 job 共享。
- 镜像为**追加型**：已存在目录只读复用；同 gitlink 永不原地改写。
- 工作树在创建时从对象库 `checkout` 后**整体置为只读**（清写位），杜绝「编译读工作树 / 归档读对象库」
  内容分叉（评审第 7 点；CI 无 SDK 写者，只读后漂移仅剩外部篡改，见 §6 界定）。
- `prune --keep N` 按 mtime 手动清理，见 §5.3。

### 5.2 唯一 helper：`sdk_mirror.py`

```text
sdk_mirror.py ensure --repo-root <ws> --persisted-root <PERSISTED_WORKSPACE>
                      [--source-sha <commit>] [--checkout-path hl2sdk_cs2] [--dry-run]
sdk_mirror.py verify --repo-root <ws> --persisted-root <PERSISTED_WORKSPACE>
                      [--source-sha <commit>] [--checkout-path hl2sdk_cs2]
sdk_mirror.py prune --persisted-root <PERSISTED_WORKSPACE> --keep <N> [--dry-run]
```

`ensure` 内部顺序（无 workspace 写入；只在镜像区操作）：

1. `gitlink = git rev-parse <source-sha>:<checkout-path>`（缺省 HEAD；必须存在且 40hex）。
2. 从 checkout 的 `.gitmodules` 读该 submodule 的 `url`/`branch`（单一来源；bootstrap 的
   `.gitmodules` 路由守卫仍独立生效）。
3. `mirror = <persisted>/sdk_mirror/<gitlink>`。
4. 加 per-mirror 文件锁 `<mirror>.lock`（原子创建）。
5. **复用判定（锁内复核）**：目录存在 **且** `rev-parse <gitlink>^{commit}` 成功 **且**
   `HEAD == gitlink` **且** `status --porcelain` 为空 **且** 工作树只读位完好 → 复用（`reused=true`）。
6. **损坏处理（锁内）**：目录存在但不满足复用判定 → 原子 rename 到 `<gitlink>.corrupt-<ts>`
   （隔离，不删除），随后重建。绝不在判定失败后把临时目录丢弃造成「复核必然仍失败」。
7. **重建（锁内）**：建临时目录 → `git init` + remote add + `core.longpaths true` → fetch → checkout →
   `fsck --no-dangling`（可选）→ 置只读 → rename 到位；rename 目标被并发占用则复核既有并复用。
8. 复核 `HEAD == gitlink`；输出 `gitlink` / `reused|created|recovered` 与 `mirror` 路径。

**fetch 语义（评审第 5 点）**：任何路径都不得 checkout 分支头。主路径
`git fetch --depth 1 origin <gitlink>`（github.com 支持可达 commit）；失败回退按 `.gitmodules` 的
branch 先 `git fetch origin <branch>`，再 `git fetch --depth 1 origin <gitlink>`；**两种路径都以
`git checkout --detach <gitlink>` 结束并断言 `HEAD == gitlink`**。gitlink 确不可达（被 force-push
移出、镜像已 prune）→ 明确失败并保留诊断，绝不回退到分支头。

### 5.3 生命周期、并发与只读安全

- **仓库内不留任何链接/目录**：`hl2sdk_cs2` 在 checkout 中保持未初始化。无跨 actions/checkout 的
  junction 窗口、无清理时序依赖、崩溃/强制中断也不留残留（评审第 3 点）。
- **迁移首轮残留归一（评审第 2 点，作为卫生步骤而非绑定前提）**：切到 `submodules: false` 后的
  第一次 checkout 可能残留上一轮 `submodules: recursive` 的旧子模块工作树或空目录。新增幂等卫生步骤
  在 checkout 后执行：`hl2sdk_cs2` 若是已初始化子模块工作树（含 `.git` 标记）→ `git submodule deinit
  -f hl2sdk_cs2`；若是空目录 → 删除；若不存在 → 不变；若是未知非空真实目录 → **fail closed**。
  此后所有运行该路径保持缺席，卫生步骤幂等。
- **并发**：同一 gitlink 多 job 同建 → per-mirror 锁 + 临时目录 + rename，存在者胜；已存在目录只读
  复用，不写。
- **损坏镜像恢复（评审第 4 点）**：判定/隔离/重建全程持锁；隔离用 rename（不删除）便于诊断。
- **`prune` 与使用中保护（评审第 4 点）**：prune 只删满足「未被锁占用且 mtime 足够旧」的目录；删除失败
  （Windows 打开句柄/占用）一律保留并报告，绝不强制。手动执行；不自动回收。

## 6. 信任模型（按评审收紧，不削弱发布门禁）

镜像**不是信任源**，只是可重建缓存。正确性由「内容寻址 + 每消费入口的 gitlink 绑定」保证：

- 归档内容（release_bundle）读的是 gitlink commit 的**对象库**，git 内容寻址；与镜像如何产生无关。
- C++ 编译读镜像**只读工作树**；复用门槛（HEAD==gitlink + status 干净 + 只读位完好）保证其由该 commit
  对象库检出且 CI 无写者，故与归档同源。**明确不作过度宣称**：该门槛不防外部绕过只读位的字节篡改
  （等价于任何磁盘缓存）；此类漂移若发生，由发布前 hosted verifier 用**全新 `submodules: recursive`
  checkout 重跑同一 C++ 校验**（[verify-release-bundle.yml:133-140](.github/workflows/verify-release-bundle.yml#L133-L140)）
  在发布前兜底捕获。
- build job 的 `select-sdk` gitlink 等式改在 mirror 上执行（`verify`），并保留 `SDK_ABI_REF/SHA` 进入
  manifest 的绑定（现有 `cpp_sdk.sha == preparation.sdk_gitlink_sha` 交叉校验不变）。
- PR / full-bridge 各自在 C++ 入口前以 mirror 的 `HEAD == merge-tree gitlink` 显式断言
  （现状 `submodules: recursive` 隐含该保证但无独立校验，v2 改为显式）。
- 父仓库 gitlink 元数据读取不依赖工作区子模块注册（§3），不受「未初始化」影响。

## 7. 消费端改造与工作流改动

### 7.1 消费端代码（评审第 1 点）

**`run_cpp_tests.py`** 新增 CLI `--sdk-root <path>`（缺省空 = 当前行为）与 `--sdk-root-sha <sha>`：

- 新增解析 `_resolve_cpp_path(value, repo_root, sdk_root)`：仅当相对路径首段恰为 `hl2sdk_cs2` 时，
  映射为 `<sdk_root>/<余下段>` 并校验 `resolve()` 后仍在 `sdk_root` 内（受控例外）；其余相对路径一律
  走原 `_resolve_source_path` 的仓库边界检查，越界检查**不放松**。`headers` 与 `include_directories`
  均经此解析（替换 [run_cpp_tests.py:315-330](run_cpp_tests.py#L315-L330) 的调用点）。
- 若给 `--sdk-root-sha`，编译前断言 `git -C <sdk_root> rev-parse HEAD == <sha>`。
- hosted（无 `--sdk-root`）保持现状：默认 `hl2sdk_cs2` 仍映射回仓库内路径。

**`release_bundle.py`** 的 build/verify SDK 根参数化：`_sdk_inventory`/`_copy_sdk` 的
`<sdk_root>` 不再硬编码 `repo_root/hl2sdk_cs2`（[release_bundle.py:416](release_bundle.py#L416)、
[release_bundle.py:742](release_bundle.py#L742)），改为 `build`/`verify` CLI 可选 `--sdk-root`
（缺省当前路径）。manifest 归档布局前缀 `hl2sdk_cs2/...` 不变，与源路径无关。

### 7.2 pilot：`build-on-self-runner.yml` `build`

1. 删除 `SUBMODULE_CACHE_VERSION` env 与三段子模块逻辑：`Compute submodule cache key` /
   `Restore submodule cache` / `Sync and update submodules`（[build-on-self-runner.yml:155-200](.github/workflows/build-on-self-runner.yml#L155-L200)）。
2. checkout-source 保持 `submodules: false`；其后加幂等卫生步骤（§5.3）归一 `hl2sdk_cs2` 残留。
3. `select-sdk`（[build-on-self-runner.yml:398-413](.github/workflows/build-on-self-runner.yml#L398-L413)）
   改为：`sdk_mirror.py ensure` 得到 mirror 路径 → `sdk_mirror.py verify` 断言 HEAD==gitlink →
   产出 `SDK_ROOT` / `SDK_ABI_REF=source-gitlink` / `SDK_ABI_SHA`（原 env 契约不变，manifest 绑定不变量
   保持）。
4. `Run C++ tests` 传 `--sdk-root $SDK_ROOT --sdk-root-sha $SDK_ABI_SHA`。
5. `build-release-bundle` 传 `--sdk-root $SDK_ROOT`。
6. 无需新增 cleanup：仓库内无任何链接/目录残留。

### 7.3 `pr-self-runner.yml` `validate` / `source-artifact-full-bridge.yml` `validate`

1. 主 checkout 改 `submodules: false`（[pr-self-runner.yml:51-57](.github/workflows/pr-self-runner.yml#L51-L57) /
   [source-artifact-full-bridge.yml:51-57](.github/workflows/source-artifact-full-bridge.yml#L51-L57)）；加
   幂等卫生步骤。
2. `Run C++ ABI validation` 前插入：`ensure` + `verify`（断言 mirror HEAD == merge-tree gitlink）；
   `run_cpp_tests.py` 传 `--sdk-root` / `--sdk-root-sha`。
3. 分析 / verify / 上传证据不变。`trusted_artifact_pr.py` 的 `sdk_gitlink_sha`（:905）仍读 Git 对象，
   不受影响。

### 7.4 `bootstrap-new-gamever-artifacts.yml` `build-bootstrap-candidate`（评审第 6 点）

1. 把 :85-86 的 `git submodule sync/update` 换成 `ensure` + 卫生步骤；保留 :83 的 `.gitmodules`
   路由守卫（镜像 URL 从 checkout `.gitmodules` 读取，语义等价）。
2. C++ 校验步骤（约 :185）传 `--sdk-root` / `--sdk-root-sha`。
3. 纳入 §8 验收。

### 7.5 实施顺序（一次合入）

1. `sdk_mirror.py` + `run_cpp_tests.py` / `release_bundle.py` 消费端改造 + 行为测试（含 hosted
   缺省路径回归、§8.1/§8.2 全部矩阵）。
2. 四个 workflow 一并切换（§7.2-§7.4）：`build-on-self-runner`、`pr-self-runner`、
   `source-artifact-full-bridge`、`bootstrap-new-gamever-artifacts`。
3. 作为一个 PR 原子合入；按仓库既有 trusted-root / bridge 门禁合入（改动文件若属受信根则走独立
   bridge 流程，不因此拆业务改动）。
4. 合入后按 §8.3 完成真实 self-hosted 验证（本地不可执行项如实标注）。
5. 文档与 memory 更新。

### 7.6 Rollback

- workflow 侧：`git revert` 改动即回到 `submodules: recursive` / actions/cache 现状。
- 消费端：`--sdk-root` 缺省路径即旧行为，互不冲突。
- 数据侧：镜像为纯追加目录；`prune --keep 0` 清空，不影响任何 git 状态。

## 8. 测试策略与质量门禁

### 8.1 消费端行为测试

`run_cpp_tests.py`：

- 仓库内相对路径（`cpp_tests/...`、非 SDK include）越界拒绝语义不变；
- `hl2sdk_cs2/*` 在有 `--sdk-root` 时映射到外部根；映射后 `..` 逃逸 / 越出 `sdk_root` 拒绝；
- 无 `--sdk-root`（hosted）时行为与现状逐字节一致（回归）；
- `--sdk-root-sha` 与 mirror HEAD 不符 → 明确失败。

`release_bundle.py`：外部 `--sdk-root` 与仓库内路径产生相同 `_sdk_inventory` 结果（评审已实证），
回归测试固化。

### 8.2 `sdk_mirror.py` 行为测试（本地临时 remote + 父仓库构造 gitlink）

- 路径派生、首建、复用（commit 存在 + HEAD==gitlink + 干净 + 只读 → 复用且**无 fetch**，以日志断言）；
- 损坏镜像恢复：HEAD 漂移 / status 脏 / 只读位缺失 → 锁内隔离 + 重建，二次复核通过；
- 分支头领先 gitlink：确保 final HEAD==gitlink 而非分支头（评审第 5 点复现场景）；
- gitlink 变化 → 新目录，旧目录不动；
- 并发同建同一 gitlink → 一个创建、其余复用，目录不损坏；
- 卫生步骤幂等：空目录 / 旧子模块工作树 / 未知非空目录（fail closed）三态；
- URL 从 `.gitmodules` 解析，缺失字段明确失败；
- `prune --keep N`：只删满足条件的镜像；被占用删除失败则保留（评审第 4 点）。

### 8.3 完成判据（评审建议的验收项）

1. 消费端测试 + 既有 `unit`/`repository-contract` 套件通过（如实记录命令与结果）。
2. 真实 self-hosted run（无法在本机执行时如实声明未验证，不宣称完成）：
   - **首次迁移**：卫生步骤把旧子模块/空目录归一为缺席；
   - 同一 gitlink 连续两轮：第二轮打印 `reused`，无 SDK fetch 网络开销；
   - **gitlink 变化轮**自动重建并下载该 commit 快照，C++ / release 门禁通过；
   - **分支头领先 gitlink**样本：final HEAD 等于 gitlink；
   - **异常中断后重新 checkout**：仓库无残留、卫生幂等、可继续；
   - **已有损坏镜像恢复**：隔离 + 重建后门禁通过；
   - build / PR / full-bridge / **bootstrap** 四类 job 各至少一次通过；
   - **使用中 prune**：不删被占用镜像（报告保留）。
3. provenance：build `select-sdk` 等式、release manifest `cpp_sdk` 绑定、PR/full-bridge C++ 入口
   显式 gitlink 断言、bootstrap `.gitmodules` 路由守卫均绿。
4. 越界检查回归：非 SDK 相对路径逃逸仍失败（C++ 例外只作用于已验证的 SDK 根）。
5. rollback 演练按 §7.6 生效。

## 9. 主要风险与应对

1. **C++ 例外被滥用**：只允许首段为 `hl2sdk_cs2` 的映射且须落在 `sdk_root` 内；其余越界检查不动；
   用负向测试锁定。
2. **仓库残留旧子模块**：切 `submodules: false` 首轮可能留旧工作树/空目录 → 幂等卫生步骤 + 未知
   非空目录 fail closed。
3. **分支头领先 gitlink**：fetch 后一律 `checkout --detach <gitlink>` + HEAD 断言，绝不取分支头。
4. **损坏镜像无恢复路径**：锁内隔离（rename）+ 重建；prune 不删被锁/被占用镜像。
5. **gitlink 被 force-push 移出可达**：精确 fetch 失败 → 报错保留诊断；镜像未 prune 前仍可复用。
6. **镜像工作树与对象库分叉**：工作树只读 + CI 无写者 + 复用门槛；发布前 hosted 全新 checkout 重跑
   C++ 兜底（§6）。不宣称可防外部绕过只读的字节篡改。
7. **hosted 行为回归**：`--sdk-root` 缺省即旧路径；release verify/publish 与 test-prospective-tree
   不在范围，保持 `submodules: recursive`。
8. **Windows 长路径 / 权限**：镜像 `core.longpaths true`；只读位用清写位实现，不依赖 ACL。

## 10. 待评审问题

1. ~~pilot 单独合入验证后再推广，还是一次合入全部四个 workflow？~~ **已定：一次合入（§7.5）。**
2. ~~镜像只读用「清写位」还是 ACL？~~ **已定：清写位（简单、幂等），不做 ACL。**
3. ~~`phase-d-validation.yml`（#926 前）是否纳入？~~ **已定：不纳入本次**；若在清理前仍被使用，
   按 §7.4 同款步骤单独补丁，不进入本迁移 PR。
4. ~~`headers` 映射后是否补 `is_file`？~~ **已定：不补**，与现状一致仅做路径合法性校验；映射/镜像
   内容错误由编译自然暴露。

# 按 submodule hash 缓存 hl2sdk_cs2（per-hash SDK mirror）计划 v2.2

状态：设计已定，未实施

日期：2026-09-07（v2.2 并入第三轮评审：消费期保护改为「消费者自持共享锁」，取消独立 holder）

评估基线：`main@22a91104`（评审分别以 `main@30623314` 复核）

## 0. 已定决策汇总（截至 v2.2）

- 一次合入（选项 B）：消费端改造 + 四个长期 workflow 一个 PR 原子合入（§7.5）。
- 镜像只读用**清写位**，不做 ACL。
- `phase-d-validation.yml`（临时入口，`#926` 合并后删除）不纳入本次。
- `run_cpp_tests.py` 对映射后的 `headers` 不补 `is_file`，与现状一致只做路径合法性校验。
- 并发/使用中保护以 **OS 文件锁**（共享读锁 + 排他锁，进程退出即释放）为准，不以「Windows 删除失败」
  作为使用中判定。
- **消费期保护 = 实际消费者进程自持共享锁**（v2.2 起，替代 v2.1 的独立 holder）：只有真正读 SDK 的
  进程（`run_cpp_tests.py`、`release_bundle.py`）在自身生命周期内持有共享锁并复核镜像；锁随消费者进程
  生死自动释放。取消独立 holder / PID 文件（§5.3 说明为何更稳）。
- `ensure` 复用作共享锁快速路径，仅缺失/损坏时才升级排他锁（避免正常复用被串行化）。
- Release 可通过历史 source SHA dispatch（[build-on-self-runner.yml:24](.github/workflows/build-on-self-runner.yml#L24)）：
  新 workflow 必须对「迁移前源码」做**能力路由**（镜像模式 / legacy submodule 模式）。

## 1. 决策摘要

在 `PERSISTED_WORKSPACE` 下建立**按 SDK gitlink commit 内容寻址的本地只读镜像**，供 self-hosted
各 job 以**绝对路径**消费；**不在 workspace 内创建 junction**。`hl2sdk_cs2` 在 checkout 里保持
未初始化的空子模块，CI 不再触碰它。

```text
镜像目录  = <PERSISTED_WORKSPACE>/sdk_mirror/<40位 gitlink sha>
镜像内容  = 该 commit 的独立 git 仓库：对象库（ls-tree/cat-file 可用）+ 只读工作树
复用规则  = 共享锁下复核：存在 + HEAD==gitlink + status 干净 + 只读位完好 -> 复用（0 网络）
           缺失/损坏 -> 升级排他锁（锁内复核后）隔离并重建
消费方式  = 绝对路径（--sdk-root）；消费进程自身持共享锁并锁内复核后才读
并发保护  = OS 文件锁（共享/排他，进程退出即释放）；无独立 holder、无 PID 文件
```

gitlink 变化即自动重建，gitlink 未变即零网络复用。多个 GAMEVER / 多次 rerun / merge_queue 复验共享
同一份镜像。该方案取代 build job 现用的 submodule actions/cache
（[build-on-self-runner.yml:165-200](.github/workflows/build-on-self-runner.yml#L165-L200)）。

> v1→v2：v1「只加 junction、原消费步骤不变」有误——C++ 路径检查拒绝仓库外镜像（
> `relative source path escapes repository root: hl2sdk_cs2/public`）。v2 改为显式适配 C++ /
> release bundle 的 SDK 根路径，取消 junction。v2.1 补齐历史 source SHA 路由。v2.2 把消费期保护
> 收敛到消费者自持共享锁，取消独立 holder 协议。

## 2. 背景与动机

### 2.1 现状：哪些 self-hosted job 每次全量拉 SDK

`.gitmodules` 把 `hl2sdk_cs2` pin 到 `HLND2T/hl2sdk` 的 `cs2_vibe`（无 nested submodule）：

| workflow / job | 现状 SDK 拉取 | 需改 |
|---|---|---|
| `build-on-self-runner.yml` `build` | actions/cache + `git submodule update --depth 1` | 是（含历史 SHA 双模路由） |
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
   - 现有 cpp_tests 的 include 写法可通过映射后的 `-I` 消费外部 SDK，无需改测试文件。
2. **SDK 自己的 git 对象库（release 归档）**：`release_bundle.py::_sdk_inventory/_copy_sdk` 用
   `git -C <sdk_root> rev-parse/ls-tree/cat-file` 生成归档与 inventory（[release_bundle.py:125-155](release_bundle.py#L125-L155)）。
   内容寻址，只要求 `<sdk_root>` 是含该 commit 完整 tree/blob 的 git 仓库；与「是否注册为 submodule」
   无关。评审已实证 `_sdk_inventory` 经 junction 与直接路径结果一致 → 接受外部仓库路径。
   Release 归档内保留 `hl2sdk_cs2/...` 前缀，下游无需改路径。
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
3. 同一 self-hosted 机器上多 job / 多 GAMEVER 共享同一份镜像；正常复用以共享锁并行，不被排他串行化。
4. 消费期受锁保护：只有真正读取的消费者进程持共享锁，prune/恢复不能删除正在被读的 SDK。
5. 适配 `run_cpp_tests.py` / `release_bundle.py`，让已校验的 SDK 根可位于仓库外（受限例外），其余
   相对路径越界检查不变。
6. 保持全部 provenance 不变量（§6），release 发布门禁不削弱。
7. 纳入 bootstrap 消费链；支持历史 source SHA 的 Release dispatch（legacy 路由）。

### 4.2 非目标

- 不改变 `.gitmodules` / SDK pinning / gitlink 语义；bootstrap 的 `.gitmodules` 路由守卫
  （[bootstrap-new-gamever-artifacts.yml:83](.github/workflows/bootstrap-new-gamever-artifacts.yml#L83)）保留。
- 不服务 hosted ubuntu job：`verify-release-bundle.yml` / `publish-release-bundle.yml` 的 verify/publish，
  以及 `source-artifact-required.yml` 的 hosted `test-prospective-tree`（:217）——均无
  `PERSISTED_WORKSPACE`，继续 `submodules: recursive`；是否上 actions/cache 单独评估。
- 不引入自托管 cache 后端 / `ACTIONS_CACHE_URL` / `--reference` alternates。
- 不自动 GC（首次只提供手动 `prune`；自动回收 + 并发保护留待单独决策）。
- 不动 `cs2_depot`、accepted-bin、warm IDB。
- 不在 workspace 建 junction；不引入独立 holder 进程 / PID 文件协议。
- 不把「迁移前源码」纳入镜像模式：历史源码走 legacy submodule（网络拉取），仅保证功能正确，
  不为历史 SHA 造镜像缓存。

## 5. 镜像与消费设计

### 5.1 目录与内容契约

```text
<PERSISTED_WORKSPACE>/
  sdk_mirror/
    <gitlink 40hex>/          # 独立 git 仓库（只读工作树 + 对象库）
      .git/
      public/...
    locks/                    # 锁文件区（在镜像目录外）
      <gitlink 40hex>.lock    # 唯一锁文件：共享=消费/复用，排他=恢复/prune
    .corrupt/<ts>-<gitlink>/  # 隔离的损坏目录（rename 进去，便于诊断）
```

- 目录名是 gitlink 的纯函数，内容不可变；同机器所有 job 共享。
- 镜像为**追加型**：已存在目录只读复用；同 gitlink 永不原地改写。
- 工作树在创建时从对象库 `checkout` 后**整体清写位只读**，杜绝「编译读工作树 / 归档读对象库」内容
  分叉（CI 无 SDK 写者；漂移仅剩外部绕过只读的篡改，见 §6 界定）。
- **无 holder PID 文件**：保护与读取绑定在同一进程，不存在跨 job 的 PID 记录（v2.2）。
- `prune --keep N` 按 mtime 手动清理，见 §5.3。

### 5.2 唯一 helper：`sdk_mirror.py`（含锁原语与消费者 lease API）

```text
sdk_mirror.py ensure  --repo-root <ws> --persisted-root <PERSISTED_WORKSPACE>
                      [--source-sha <commit>] [--checkout-path hl2sdk_cs2] [--dry-run]
sdk_mirror.py verify  --repo-root <ws> --persisted-root <PERSISTED_WORKSPACE>
                      [--source-sha <commit>] [--checkout-path hl2sdk_cs2]
sdk_mirror.py prune   --persisted-root <PERSISTED_WORKSPACE> --keep <N> [--dry-run]

# 库 API（被 run_cpp_tests.py / release_bundle.py 以 --sdk-lock 传入后调用）：
#   acquire_read_lease(lock_path, sdk_root, expected_sha) -> context manager
#     共享锁下复核 reuse gate；不通过则抛错（调用方可重试 ensure 一次）
```

**锁语义（评审第 1、3 点，v2.2 收敛）**：所有锁是 **OS 文件锁**（Windows `LockFileEx` 共享/排他；
POSIX `flock LOCK_SH/LOCK_EX`）加在 `locks/<gitlink>.lock` 上——**进程退出即自动释放**，无占位文件、
无失效锁回收问题。

- **消费者自持共享锁（v2.2 核心）**：真正读 SDK 的进程（`run_cpp_tests.py`、`release_bundle.py`
  build/verify）在镜像模式下，于进程启动时 `acquire_read_lease()`——**在共享锁内重新复核**
  （HEAD==gitlink + status 干净 + 只读位完好）通过后，进程才开始任何 SDK 读取，并**持续持有共享锁
  至进程退出**。锁随消费者进程生死自动释放：
  - 消费者运行期间，任何 `prune`/损坏恢复要取排他锁都会失败/跳过 → 不可能删到正在被读的 SDK；
  - 消费者崩溃/被杀 → OS 释放锁，但崩溃即停止读取，不存在「锁已放、读还在」的窗口；
  - 不存在独立 holder，故没有「holder 死了但消费者还在跑」的错配（v2.1 的问题 3 消除）。
- **README 握手即消费者取锁+复核**：workflow 不设独立就绪信号；消费者共享锁内复核通过 = 可安全读；
  复核失败（镜像在 ensure 后被外部删除/损坏）→ 明确报错，workflow 可 `ensure` 一次后重试消费者一次。

`ensure` 内部顺序（不写 workspace；只在镜像区操作）：

1. `gitlink = git rev-parse <source-sha>:<checkout-path>`（缺省 HEAD；必须存在且 40hex）。
2. 从 checkout 的 `.gitmodules` 读该 submodule 的 `url`/`branch`（单一来源；bootstrap 的
   `.gitmodules` 路由守卫仍独立生效）。
3. `mirror = <persisted>/sdk_mirror/<gitlink>`，锁文件 `locks/<gitlink>.lock`。
4. **共享锁快速路径（评审第 4 点）**：先取**共享锁**并复核复用门槛（目录存在 + commit 可达 +
   HEAD==gitlink + status 干净 + 只读完好）→ 通过即 `reused=true`，释放共享锁返回。**正常复用不取
   排他锁，不阻塞他 job 的并发消费/复用**。
5. **升级排他锁（仅缺失/损坏时）**：释放共享锁，取**排他锁**；**在排他锁内重新复核**（可能已被其他
   进程修复）：通过则返回 `reused`；否则执行 6–7。
6. **损坏处理（锁内）**：目录存在但不满足门槛 → rename 到 `.corrupt/<ts>-<gitlink>`（隔离不删除），
   随后重建；绝不丢弃临时目录造成「复核必然仍失败」。
7. **重建（锁内）**：临时目录 → `git init` + remote add + `core.longpaths true` → fetch → checkout →
   `fsck --no-dangling`（可选）→ 清写位只读 → rename 到位；rename 目标被并发占用则复核既有并复用。
8. 复核 `HEAD == gitlink`；输出 `gitlink` / `reused|created|recovered` / `mirror` 路径；释放锁。

**fetch 语义（评审第 5 点）**：任何路径都不得 checkout 分支头。主路径
`git fetch --depth 1 origin <gitlink>`（github.com 支持可达 commit）；失败回退按 `.gitmodules` 的
branch 先 `git fetch origin <branch>`，再 `git fetch --depth 1 origin <gitlink>`；**两种路径都以
`git checkout --detach <gitlink>` 结束并断言 `HEAD == gitlink`**。gitlink 确不可达（被 force-push
移出、镜像已 prune）→ 明确失败并保留诊断，绝不回退到分支头。

### 5.3 生命周期、并发与只读安全

- **仓库内不留任何链接/目录**：`hl2sdk_cs2` 在 checkout 中保持未初始化。无跨 actions/checkout 的
  junction 窗口、无清理时序依赖、崩溃/强制中断也不留残留。
- **消费期保护**：由消费者进程自持共享锁承担（§5.2），与读取进程同生命周期；不需要 job 级 holder，
  无 holder 启动/停止步骤、无 README PID、无「ensure→holder 空窗」（评审第 2 点由消费者锁内复核补上）。
- **排他操作与使用中互斥**：恢复（ensure 损坏分支）与 `prune` 必须先取得同一 lock 的**排他锁**；取不到
  即证明存在存活消费者/持共享锁进程 → 跳过并报告。**使用中保护以锁为准**；「Windows 删除失败」仅作
  补充信号。
- **`prune` 删除规则（评审收紧）**：取得排他锁后，先清待删镜像内文件与目录的**只读位**再删除；
  Windows 只读属性本身不构成「占用」。取得排他锁后删除仍失败 = 真实占用（如镜像内仍有瞬时打开句柄）
  或 IO 错误 → 保留并报告，绝不强制。`prune` 只删 mtime 足够旧的镜像；新建镜像不被选中，进一步缩小
  ensure 与消费者首读之间的理论空窗。
- **迁移首轮残留归一（卫生步骤）**：切 `submodules: false` 后第一次 checkout 可能残留旧子模块工作树
  或空目录。幂等卫生步骤在 checkout 后执行：`hl2sdk_cs2` 是已初始化子模块（含 `.git` 标记）→
  `git submodule deinit -f hl2sdk_cs2`；空目录 → 删除；不存在 → 不变；未知非空真实目录 → **fail closed**。
  仅镜像模式执行（legacy 模式需要该目录存在）。
- **并发复用/建镜像**：复用走共享锁并行；首建/损坏走排他锁串行；临时目录 + rename，存在者胜。

## 6. 信任模型（按三轮评审收紧，不削弱发布门禁）

镜像**不是信任源**，只是可重建缓存。正确性由「内容寻址 + 每消费入口的 gitlink 绑定」保证：

- 归档内容（release_bundle）读的是 gitlink commit 的**对象库**，git 内容寻址；与镜像如何产生无关。
- C++ 编译读镜像**只读工作树**；消费者在**共享锁内复核**（HEAD==gitlink + status 干净 + 只读位完好）
  通过后才读，故其读取对象由该 commit 对象库检出且 CI 无写者，与归档同源。**明确不作过度宣称**：该
  门槛不防外部绕过只读位的字节篡改（等价于任何磁盘缓存）。
- **兜底范围（评审收紧）**：发布前 hosted verifier 用真实 SDK（fresh `submodules: recursive`）独立
  重跑同一 C++ ABI 门禁（[verify-release-bundle.yml:133-140](.github/workflows/verify-release-bundle.yml#L133-L140)），
  是「被测 ABI 与真实 SDK 一致」的发布前独立复核；但它**不能证明镜像字节与真实 SDK 逐字节一致**——
  不影响被测 ABI 的漂移不会被发现，且 PR/bootstrap 不经此 Release 复验链。镜像正确性**不依赖**该兜底，
  兜底仅为发布前附加复核；清写位决策不变。
- build job 的 `select-sdk` gitlink 等式改在 mirror 上执行（`verify`），并保留 `SDK_ABI_REF/SHA` 进入
  manifest 的绑定（现有 `cpp_sdk.sha == preparation.sdk_gitlink_sha` 交叉校验不变）。
- PR / full-bridge 各自在 C++ 入口前以 mirror 的 `HEAD == merge-tree gitlink` 显式断言（现状
  `submodules: recursive` 隐含该保证但无独立校验，v2 改为显式；由消费者共享锁内复核承担）。
- 父仓库 gitlink 元数据读取不依赖工作区子模块注册（§3），不受「未初始化」影响。

## 7. 消费端改造与工作流改动

### 7.1 消费端代码（评审第 1 点 + v2.2 lease API）

**`run_cpp_tests.py`** 新增 CLI `--sdk-root <path>`、`--sdk-root-sha <sha>`、`--sdk-lock <lock>`：

- 新增解析 `_resolve_cpp_path(value, repo_root, sdk_root)`：仅当相对路径首段恰为 `hl2sdk_cs2` 时，
  映射为 `<sdk_root>/<余下段>` 并校验 `resolve()` 后仍在 `sdk_root` 内（受控例外）；其余相对路径一律
  走原 `_resolve_source_path` 的仓库边界检查，越界检查**不放松**。`headers` 与 `include_directories`
  均经此解析（替换 [run_cpp_tests.py:315-330](run_cpp_tests.py#L315-L330) 的调用点）。
- 镜像模式（给了 `--sdk-root`/`--sdk-lock`）：进程启动先
  `acquire_read_lease(sdk_lock, sdk_root, sdk_root_sha)`（共享锁内复核 HEAD==sha + 干净 + 只读），
  持有至退出；复核失败明确报错（workflow 可 ensure 一次后重试）。
- hosted（无 `--sdk-root`/`--sdk-lock`）保持现状：默认 `hl2sdk_cs2` 映射回仓库内路径，不取锁。
- 不补 `headers` 的 `is_file` 断言（已定）。

**`release_bundle.py`** 的 build/verify SDK 根参数化：`_sdk_inventory`/`_copy_sdk` 的
`<sdk_root>` 不再硬编码 `repo_root/hl2sdk_cs2`（[release_bundle.py:416](release_bundle.py#L416)、
[release_bundle.py:742](release_bundle.py#L742)），改为 `build`/`verify` CLI 可选 `--sdk-root`；
镜像模式下同样经 `--sdk-lock`（+ 内部 `preparation.sdk_gitlink_sha`）在共享锁内复核后读取
（hosted 缺省走仓库内路径、不取锁）。manifest 归档布局前缀 `hl2sdk_cs2/...` 不变，与源路径无关。

### 7.2 `build-on-self-runner.yml` `build`（含历史 SHA 双模路由）

**能力路由（评审第 2 点）**：workflow 代码来自当前 default branch，但脚本从 checkout 出的
`source_sha` 树执行（`uv run python ...`），历史 SHA 树的 `sdk_mirror.py` 与
`run_cpp_tests.py`/`release_bundle.py` 可能不存在或不支持 `--sdk-root`。checkout 后先探测
`git cat-file -e <source_sha>:sdk_mirror.py`：

- **SDK_MODE=mirror**（源码含 helper，即迁移后提交）：走下述镜像路径。
- **SDK_MODE=legacy**（迁移前源码）：走现役路径——`git submodule sync/update --init --recursive
  --depth 1` 在仓库内物化 SDK；`select-sdk` 读 `workspace/hl2sdk_cs2`；C++/release 不传
  `--sdk-root`/`--sdk-lock`（旧树不认识）。历史 SHA 每次仍网络拉取，仅保证功能正确；不做卫生归一。

镜像模式步骤：

1. 删除 `SUBMODULE_CACHE_VERSION` env 与 actions/cache 三段逻辑：`Compute submodule cache key` /
   `Restore submodule cache` / `Sync and update submodules`
   （[build-on-self-runner.yml:155-200](.github/workflows/build-on-self-runner.yml#L155-L200)）。
2. checkout-source 保持 `submodules: false`；其后加幂等卫生步骤（§5.3）。
3. `select-sdk`（[build-on-self-runner.yml:398-413](.github/workflows/build-on-self-runner.yml#L398-L413)）
   改为：`sdk_mirror.py ensure` → 产出 `SDK_ROOT`（mirror 路径）/ `SDK_LOCK`（locks 路径）/
   `SDK_ABI_REF=source-gitlink` / `SDK_ABI_SHA`。
4. `Run C++ tests` 传 `--sdk-root $SDK_ROOT --sdk-root-sha $SDK_ABI_SHA --sdk-lock $SDK_LOCK`
   （消费者自持共享锁）。
5. `build-release-bundle` 传 `--sdk-root $SDK_ROOT --sdk-lock $SDK_LOCK`。
6. 无独立 holder / cleanup 无需释放锁：锁随各消费进程退出自动释放。

### 7.3 `pr-self-runner.yml` `validate` / `source-artifact-full-bridge.yml` `validate`

这些 job 的 `source_sha` 是 **merge/prospective 树**：无论 PR 建于迁移前还是后，merge 树都并入
default branch 的 `sdk_mirror.py`，因此恒为镜像模式。步骤：

1. 主 checkout 改 `submodules: false`（[pr-self-runner.yml:51-57](.github/workflows/pr-self-runner.yml#L51-L57) /
   [source-artifact-full-bridge.yml:51-57](.github/workflows/source-artifact-full-bridge.yml#L51-L57)）；加
   幂等卫生步骤 + **能力断言**（merge 树缺 `sdk_mirror.py` → 明确失败并提示，不静默回退）。
2. `Run C++ ABI validation` 前插入：`ensure` → `run_cpp_tests.py` 传 `--sdk-root`/`--sdk-root-sha`/
   `--sdk-lock`（消费者共享锁内断言 mirror HEAD == merge-tree gitlink）。
3. 分析 / verify / 上传证据不变；`trusted_artifact_pr.py` 的 `sdk_gitlink_sha`（:905）仍读 Git 对象，
   不受影响。

### 7.4 `bootstrap-new-gamever-artifacts.yml` `build-bootstrap-candidate`（评审第 6 点）

1. 把 :85-86 的 `git submodule sync/update` 换成 `ensure` + 卫生步骤；保留 :83 的 `.gitmodules`
   路由守卫（镜像 URL 从 checkout `.gitmodules` 读取，语义等价）。
2. C++ 校验步骤（约 :185）传 `--sdk-root`/`--sdk-root-sha`/`--sdk-lock`；纳入 §8 验收。

### 7.5 实施顺序（一次合入）

1. `sdk_mirror.py`（锁原语、共享复用/排他恢复、消费者 lease API）+ `run_cpp_tests.py` /
   `release_bundle.py` 消费端改造 + 行为测试（hosted 缺省路径回归、§8.1/§8.2 全部矩阵）。
2. 四个 workflow 一并切换（§7.2-§7.4），`build-on-self-runner` 含 legacy 双模路由。
3. 作为一个 PR 原子合入；按仓库既有 trusted-root / bridge 门禁合入（改动文件若属受信根则走独立
   bridge 流程，不因此拆业务改动）。原子合入只保证**新提交内的文件一致**；「新 workflow + 旧
   source_sha」由 §7.2 能力路由显式解决。
4. 合入后按 §8.3 完成真实 self-hosted 验证（本地不可执行项如实标注）。
5. 文档与 memory 更新。

### 7.6 Rollback

- workflow 侧：`git revert` 改动即回到 `submodules: recursive` / actions/cache 现状；legacy 分支路径
  在回滚前与旧行为一致。
- 消费端：`--sdk-root`/`--sdk-lock` 缺省即旧行为，互不冲突。
- 数据侧：镜像为纯追加目录；`prune --keep 0`（在无消费者持锁时）清空，不影响任何 git 状态。
- 进程/锁：锁随持有进程退出自动释放，回滚无需清理。

## 8. 测试策略与质量门禁

### 8.1 消费端行为测试

`run_cpp_tests.py`：

- 仓库内相对路径（`cpp_tests/...`、非 SDK include）越界拒绝语义不变；
- `hl2sdk_cs2/*` 在有 `--sdk-root` 时映射到外部根；映射后 `..` 逃逸 / 越出 `sdk_root` 拒绝；
- 无 `--sdk-root`/`--sdk-lock`（hosted）时行为与现状逐字节一致（回归，不取锁）；
- `--sdk-root-sha` 与 mirror HEAD 不符 / 锁内复核失败 → 明确失败。

`release_bundle.py`：外部 `--sdk-root` 与仓库内路径产生相同 `_sdk_inventory` 结果（评审已实证），
回归测试固化；`--sdk-lock` 锁内复核失败 → 明确失败。

### 8.2 `sdk_mirror.py` 行为测试（本地临时 remote + 父仓库构造 gitlink）

- 路径派生、首建、复用（commit 存在 + HEAD==gitlink + 干净 + 只读 → 复用且**无 fetch**，以日志断言）；
- **复用走共享锁，不被排他串行化（评审第 4 点）**：job A 持共享锁消费时，job B 完整
  ensure+acquire_read_lease 走共享复用**成功且不等 A 结束**（断言无排他等待）；
- 损坏镜像恢复：HEAD 漂移 / status 脏 / 只读位缺失 → 排他锁内复核 + 隔离 + 重建，二次复核通过；
- 分支头领先 gitlink：final HEAD==gitlink 而非分支头；
- gitlink 变化 → 新目录，旧目录不动；
- **消费期使用中保护（评审第 3 点）**：进程 A 持共享锁执行读取期间（模拟消费者仍在运行），
  `prune`/损坏恢复取排他锁失败跳过、不能删除正在被读目录——**不是「杀掉 holder 后可删」**；
  进程 A 正常结束或崩溃退出后锁释放，此时才可 prune；
- **消费者崩溃 → 锁自动释放且无读中删除**：A 崩溃（读取即停止）→ B 可正常 prune；验证无残留锁；
- **prune 清只读后删除**：只读镜像取得排他锁后可删；删除失败区分「只读（已清）」与「真实占用/IO」；
- 卫生步骤幂等：空目录 / 旧子模块工作树 / 未知非空目录（fail closed）三态；
- URL 从 `.gitmodules` 解析，缺失字段明确失败；
- **能力探测**：`git cat-file -e <sha>:sdk_mirror.py` 命中/未命中 → mirror/legacy 路由正确。
- **完整 workflow 协议演练（评审建议）**：不止验证「两个 holder 同时取共享锁」，而是在临时镜像上跑
  「ensure → 消费者取锁+锁内复核 → 读取 → 释放」，覆盖复用/恢复/使用中保护/崩溃全序列。

### 8.3 完成判据（评审建议的验收项）

1. 消费端测试 + 既有 `unit`/`repository-contract` 套件通过（如实记录命令与结果）。
2. 真实 self-hosted run（无法在本机执行时如实声明未验证，不宣称完成）：
   - **首次迁移**：卫生步骤把旧子模块/空目录归一为缺席；
   - 同一 gitlink 连续两轮：第二轮打印 `reused`，无 SDK fetch 网络开销；
   - **gitlink 变化轮**自动重建并下载该 commit 快照，C++ / release 门禁通过；
   - **分支头领先 gitlink**样本：final HEAD 等于 gitlink；
   - **异常中断后重新 checkout**：仓库无残留、卫生幂等、消费者崩溃后锁自动释放、可继续；
   - **已有损坏镜像恢复**：隔离 + 重建后门禁通过；
   - **消费期使用中保护**：job A 消费期间 `prune`/并发恢复被跳过；A 结束后可正常删；
   - **A 消费 / B 复用并存**：A 持共享锁时，B 完整走 ensure+消费者取锁仍成功复用（评审第 4 点验收）；
   - **历史 source SHA**：以**迁移前 commit** dispatch 一次 verify-only 走 legacy 路径成功；迁移后
     commit 走镜像路径；
   - build / PR / full-bridge / **bootstrap** 四类 job 各至少一次通过。
3. provenance：build `select-sdk` 等式、release manifest `cpp_sdk` 绑定、PR/full-bridge C++ 入口
   显式 gitlink 断言（消费者锁内复核）、bootstrap `.gitmodules` 路由守卫均绿。
4. 越界检查回归：非 SDK 相对路径逃逸仍失败（C++ 例外只作用于已验证的 SDK 根）。
5. rollback 演练按 §7.6 生效。

## 9. 主要风险与应对

1. **C++ 例外被滥用**：只允许首段为 `hl2sdk_cs2` 的映射且须落在 `sdk_root` 内；其余越界检查不动；
   负向测试锁定。
2. **仓库残留旧子模块**：切 `submodules: false` 首轮可能留旧工作树/空目录 → 幂等卫生步骤 + 未知
   非空目录 fail closed。
3. **分支头领先 gitlink**：fetch 后一律 `checkout --detach <gitlink>` + HEAD 断言，绝不取分支头。
4. **损坏/删除竞态**：消费期由消费者共享锁覆盖；恢复/prune 以排他锁判互斥（锁为准），Windows 删除
   失败仅补充；prune 先清只读再删；新建镜像 mtime 新，不被 prune 选中。
5. **历史 source SHA**：新 workflow 遇到迁移前源码 → 能力路由到 legacy submodule 路径；历史 SHA 不造
   镜像、仍网络拉取，仅保证正确；atomic merge 不覆盖「新 workflow + 旧 source_sha」组合。
6. **gitlink 被 force-push 移出可达**：精确 fetch 失败 → 报错保留诊断；镜像未 prune 前仍可复用。
7. **镜像工作树与对象库分叉**：工作树只读（清写位）+ CI 无写者 + 消费者锁内复核；发布前 hosted 用真实
   SDK 独立重跑 C++ 作为**附加复核**（§6 限定范围）。不宣称可防外部绕过只读的字节篡改。
8. **hosted 行为回归**：`--sdk-root`/`--sdk-lock` 缺省即旧路径；release verify/publish 与
   test-prospective-tree 不在范围，保持 `submodules: recursive`。
9. **锁可移植性与消费者侵入**：Windows `LockFileEx` / POSIX `flock` 封装进 sdk_mirror，consumer 以可选
   `--sdk-lock` 启用（hosted 不启用）；lease API 需在 run_cpp_tests / release_bundle 两处正确包裹
   「取锁+复核」在最外侧，覆盖其全部子进程/子调用读取。
10. **Windows 长路径 / 权限**：镜像 `core.longpaths true`；只读位用清写位实现，不依赖 ACL。

## 10. 待评审问题

1. ~~pilot 单独合入验证后再推广，还是一次合入全部四个 workflow？~~ **已定：一次合入（§7.5）。**
2. ~~镜像只读用「清写位」还是 ACL？~~ **已定：清写位（简单、幂等），不做 ACL。**
3. ~~`phase-d-validation.yml`（#926 前）是否纳入？~~ **已定：不纳入本次**；若在清理前仍被使用，
   按 §7.4 同款步骤单独补丁，不进入本迁移 PR。
4. ~~`headers` 映射后是否补 `is_file`？~~ **已定：不补**，与现状一致仅做路径合法性校验；映射/镜像
   内容错误由编译自然暴露。
5. ~~独立 holder 的 PID/README/崩溃错配问题如何解？~~ **已定（v2.2）：取消独立 holder，改为消费者
   进程自持共享锁 + 锁内复核（§5.2/§5.3）。**

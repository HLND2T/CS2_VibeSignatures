[返回中文 README](../../README_CN.md) | [English](../en/ci-cd.md)

# CI/CD 与 Jenkins 工作流参考

## Pull Request 与 Merge Queue

`source-artifact-required.yml` 使用 default-branch planner 绑定 exact prospective merge tree。light change 运行 hosted tests；full change 计算 affected producer groups 与 downstream closure，再由 `pr-self-runner.yml` 对每个 affected GAMEVER 执行 empty-root rebuild，并与 `bin_artifacts` Git blobs 逐字节比较。

因此 source/config/reference PR 必须同时包含计算出的 `bin_artifacts` change。PR CI 绝不把 `gamesymbols/`、`gamedata/` 或 release manifest 写回分支。新 GAMEVER bootstrap 是唯一 source-branch writer：受 environment 保护的 hosted publisher 只能 fast-forward `bump-download/<GAMEVER>`，artifact-bearing head 必须再次通过 validation。

稳定 required checks 为 `source-artifact-required` 与 `pr-validate`。Merge Queue 还必须通过 GitHub ruleset Required Workflow（或独立 trust root）安装验证，防止 prospective workflow change 自行伪造同名 check。

## Warm IDB 与 accepted binaries

PR 与 Release analysis 都调用 `warmup-idb.yml`，将 configured binary hashes 和 IDA runtime 绑定到 immutable cache generation。accepted-bin 是 exact configured-binary cache：YAML、IDA databases、BinSync state 与未声明 side files 均被拒绝。这些 cache 只用于性能，不是 symbol truth。

## Immutable Release pipeline

version source commit 进入 default branch 后：

1. source preflight 证明目标 GAMEVER 有完整 tracked artifact tree；
2. self-hosted builder 执行 fresh `-force_all -rename`，验证 exact artifact bytes，并生成无凭证的 BinSync/Release candidates；
3. hosted jobs 独立验证 candidate bundles、archive allowlists、manifest、checksums、C++ evidence 与 BinSync target-state identity；
4. protected BinSync publisher 只执行 fast-forward ref updates；
5. protected Release publisher 创建/复用 source tag，上传 exact immutable assets，发布一次并 dispatch Pages；
6. Pages 只 hydrate published Release assets，验证 manifest/SHA256SUMS/archive inventories，构建全部已发布版本并验证 CDN bytes。

workflow transaction identity 在 GitHub rerun 之间保持稳定（`run_id`）；`run_attempt` 只属于 transport metadata。published tag/assets 禁止 clobber 或内容不同的 republish。

本地 candidate 命令与 artifact ownership 见 [Snapshot、gamedata 与 C++ 验证](snapshot-and-gamedata.md)。

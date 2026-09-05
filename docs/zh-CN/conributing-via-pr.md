[返回中文 README](../../README_CN.md) | [English](../en/conributing-via-pr.md) | [创建符号分析 skill](creating-skills.md)

# 通过 Pull Request 贡献符号分析 skill

完成符号分析 skill 与本地定向测试后，应在 `bin_artifacts/` 中重建受影响的 producer groups 及完整 downstream closure。将 source/config/reference change 与生成的 canonical per-symbol artifacts 一起 stage，再使用 `SKILL: create-pr`（调用方式为 `/create-pr`）提交到项目。

不要 stage Release 派生的 `gamesymbols/`、`gamedata/`、metadata、archives、checksums 或 `release-manifests/`。`bin/` 下的 binary/IDA workspace 也不是 source truth。

## 调用 skill

可以这样请求 agent：

```text
Use SKILL: create-pr to share the staged symbol-analysis change and artifact closure.
gamever: 14156
branch: dev-find-example
commit_title: feat(skills): add find-example symbol-analysis skill
```

`branch`、commit title、PR 标题/正文以及 issue 编号都是可选的；省略时，`create-pr` 会根据 staged diff 生成合适值。它会从 `dev*` 分支针对 `main` 创建 PR，不会直接向 `main` 提交。

## 必须 stage 的内容

staged set 是一个原子的 source-owned change：

1. 发生变化的 producer、config、reference 或 source files。
2. `bin_artifacts/<GAMEVER>/` 下所有受影响 artifact A/M/D/R。
3. 计算出的 downstream closure 中每个 artifact，包括 cross-module outputs。
4. 与本次变更直接相关的 tests 或长期文档。

使用 local planner 与 repository artifact contract 计算并验证 closure。不要信任人工列出的 affected list；CI 会使用 default-branch planner 独立重算 ownership 与 invalidation。

## `create-pr` 执行的步骤

1. 捕获并检查准确的 staged path set，包括 `bin_artifacts` closure。
2. 拒绝 tracked `gamesymbols/`、`gamedata/`、`release-manifests/` 与 `bin/**/*.yaml`。
3. 仅提交捕获到的 paths，使用仓库 Conventional Commit 格式并附带 `Co-Authored-By: Codex`。
4. 推送 `dev*` 分支，并针对 `main` 创建一个 PR。
5. 等待最新 head 上稳定的 `source-artifact-required` 与 `pr-validate` checks。

full validation 会绑定 exact prospective merge tree，在 checkout-external root 中重建 affected producer groups，并将完整 actual inventory 与 Git blobs 逐字节比较。Merge Queue 会对最终 queued tree 重新执行该证明。

对于新 GAMEVER，初始 PR 可能进入 `bootstrap_required`。受保护的 bootstrap publisher 只能向匹配的 `bump-download/<GAMEVER>` branch 追加 fast-forward artifact commit；artifact-bearing head 随后必须通过普通 exact-byte validation，bootstrap run 本身不能满足 required check。

## 完成后

记录 branch、source commit SHA、PR URL、最终提交 paths 与 verification results。Snapshot、metadata、gamedata、archives、manifests、BinSync changes 和 Pages inputs 会在后续 immutable Release pipeline 中重建，绝不会发布回 source PR。

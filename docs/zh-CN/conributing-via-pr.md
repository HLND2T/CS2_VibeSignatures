[返回中文 README](../../README_CN.md) | [English](../en/conributing-via-pr.md) | [创建符号分析 skill](creating-skills.md)

# 通过 Pull Request 贡献符号分析 skill

完成符号分析 skill 并运行本地定向测试后，可使用 `SKILL: create-pr`（调用方式为 `/create-pr`）将其共享到项目中。该 skill 只提交 staged source change；`pr-self-runner.yml` 会根据 changed paths 独立选择 PR 验证路径；snapshot/gamedata 发布只在 release 流水线进行。

## 调用 skill

可以这样请求 agent：

```text
Use SKILL: create-pr to share the staged symbol-analysis skill.
gamever: 14156
branch: dev-find-example
commit_title: feat(skills): add find-example symbol-analysis skill
```

`branch`、commit title、PR 标题/正文以及 issue 编号都是可选的。省略时，`create-pr` 会根据 staged diff 生成合适的值。

它会从 `dev*` 分支针对 `main` 创建 PR，不会直接向 `main` 提交。

## `create-pr` 执行的步骤

该流程交付捕获到的 source change，不预测或影响 workflow 的验证路由：

1. 记录并检查准确的 staged paths。
2. 只提交这些 source paths，使用仓库 Conventional Commit 格式并附带 `Co-Authored-By: Codex`。
3. 推送 `dev*` 分支，并针对 `main` 创建一个 PR。
4. `pr-self-runner.yml` 使用 `pr_validation_mode.py` 与受信任的 `pr_validation_mode.yaml` 对 changed paths 分类，然后执行选定的 light 或 full 验证路径。
5. 在 full 路径中，CI 从 immutable merge ref 分析二进制，构建 snapshot/gamedata candidate，并用同一份 candidate bytes 运行 C++ 验证。
6. `gamesymbols/<GAMEVER>.yaml` 与 `gamedata/<GAMEVER>/` 只在 release 时推进；PR workflow 不会把它们发布回 PR head。

如果没有 staged changes、存在未暂存 tracked changes、认证失败或出现未预期的路径变化，skill 会在提交和创建 PR 前停止。不要在本地加入生成的 snapshot/gamedata；这些输出归 CI 所有。

## 完成后

记录 skill 返回的分支、source commit SHA、PR URL 和最终提交路径列表。等待最新 PR head 上稳定的 `pr-validate` check；snapshot/gamedata 输出稍后由 release 流水线发布，而非由本 PR 发布。

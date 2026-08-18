[返回中文 README](../../README_CN.md) | [English](../en/conributing-via-pr.md) | [创建符号分析 skill](creating-skills.md)

# 通过 Pull Request 贡献符号分析 skill

完成符号分析 skill 的创建并在本地验证后，可使用 `SKILL: create-pr`（调用方式为 `/create-pr`）将其共享到项目中。该 skill 会先对 staged change 分类：涉及 CS2 Symbols 的路径会走 candidate 准备、验证和发布，再提交、推送并创建 Pull Request；不涉及 symbols 的改动则直接创建 PR。

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

该流程用 `.claude/skills/create-pr/scripts/classify_delivery.py` 对交付的变更分类。如果任意 staged path 涉及 CS2 symbols 管线（例如 `configs/`、`ida_preprocessor_scripts/`、`cpp_tests/`、`hl2sdk_cs2/`、`gamesymbols/`、`gamedata/`，或根目录的分析/快照/C++ 模块），则按顺序执行以下门禁：

1. 记录并检查准确的 staged paths。
2. 针对选定的游戏版本运行 `/prepare-post-change-candidate`。
3. 对 immutable candidate 运行 `/post-change-validation`。
4. 仅在验证成功后运行 `/publish-post-change-candidate`。
5. 只暂存授权范围内的格式化变更和当前版本生成输出。
6. 按仓库 Conventional Commit 格式提交，并附带 `Co-Authored-By: Codex`。
7. 推送 `dev*` 分支，并针对 `main` 创建一个 PR。

如果没有 staged path 涉及 CS2 symbols（例如变更只包含文档、workflow、skill 或进程监控），`create-pr` 会完全跳过上述 2 到 5 步，不解析 `gamever`，直接从捕获的变更创建 PR。此时 PR 正文不会声称进行过 candidate 准备、C++ 验证或发布。

如果没有 staged changes、存在未暂存 tracked changes、认证失败、任一门禁失败或出现未预期的路径变化，skill 会在提交和创建 PR 前停止。不要绕过失败门禁，也不要手动发布 candidate。

## 完成后

记录 skill 返回的分支、commit SHA、PR URL 和最终提交路径列表。若本次走了 symbols 管线，再记录游戏版本和 candidate SHA-256，并检查 PR 确实只包含目标 skill、其配套文件，以及选定游戏版本的生成输出。

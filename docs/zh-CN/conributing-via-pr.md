[返回中文 README](../../README_CN.md) | [English](../en/conributing-via-pr.md) | [创建符号分析 skill](creating-skills.md)

# 通过 Pull Request 贡献符号分析 skill

完成符号分析 skill 并运行本地定向测试后，可使用 `SKILL: create-pr`（调用方式为 `/create-pr`）将其共享到项目中。该 skill 只分类并提交 staged source change；涉及 CS2 Symbols 的 candidate 准备、C++ 验证以及 snapshot/gamedata 发布由 PR 创建后的 `pr-self-runner.yml` CI 完成。

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

该流程用 `.claude/skills/create-pr/scripts/classify_delivery.py` 对交付的变更分类。如果任意 staged path 涉及 CS2 symbols 管线（例如 `configs/`、`ida_preprocessor_scripts/`、`cpp_tests/`、`hl2sdk_cs2/`、`gamesymbols/`、`gamedata/`，或根目录的分析/快照/C++ 模块），则按顺序执行：

1. 记录并检查准确的 staged paths。
2. 只提交这些 source paths，使用仓库 Conventional Commit 格式并附带 `Co-Authored-By: Codex`。
3. 推送 `dev*` 分支，并针对 `main` 创建一个 PR。
4. `pr-self-runner.yml` 从 immutable merge ref 分析二进制，构建 snapshot/gamedata candidate，并用同一份 candidate bytes 运行 C++ 验证。
5. 全部门禁通过后，CI 发布 `gamesymbols/<GAMEVER>.yaml` 与 `gamedata/<GAMEVER>/`，以 `github-actions[bot]` 在 PR head branch 创建 commit，再显式 dispatch 针对新 head 的轻量 provenance/digest 复核。

如果没有 staged path 涉及 CS2 symbols（例如变更只包含文档、workflow、skill 或进程监控），`create-pr` 会直接从捕获的变更创建 PR，并且不会在 PR 正文中声称执行 symbols lifecycle。

如果没有 staged changes、存在未暂存 tracked changes、认证失败或出现未预期的路径变化，skill 会在提交和创建 PR 前停止。不要在本地加入生成的 snapshot/gamedata；这些输出归 CI 所有。

## 完成后

记录 skill 返回的分支、source commit SHA、PR URL 和最终提交路径列表。若本次涉及 symbols 管线，等待最新 PR head 上稳定的 `pr-validate` check；确认 bot commit 只改动对应 snapshot/gamedata，且 published recheck 成功。

[返回中文 README](../../README_CN.md) | [English](../en/development.md)

# 开发检查

## 代码格式化

本仓库使用 `ruff format` 格式化由 Git 跟踪的 `*.py` 文件，并使用 `yamlfix` 格式化由 Git 跟踪的 `*.yaml` 文件。

提交前在本地运行格式化：

```bash
uv run python format_repo_files.py
```

运行与 GitHub Actions 相同的格式化检查：

```bash
uv run python format_repo_files.py --check
```

格式化脚本只处理 `git ls-files --cached -- '*.py' '*.yaml'` 返回的文件，因此会跳过被 ignore 的文件与未跟踪的临时文件。`ida_preprocessor_scripts/references/` 下的生成 YAML 和 `bin_artifacts/` 下的 canonical symbol artifacts 也会被跳过，由 producer/canonicalizer 保证 exact bytes。

## 测试

本地编辑与快速回归使用隔离的 unit suite：

```bash
uv run python tests/run_test_suite.py unit -b --durations 30
```

其余 primary suite 分别保留仓库状态、Redis 与 Git release transaction 覆盖：

```bash
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py redis-integration -b --durations 30
uv run python tests/run_test_suite.py release-integration -b --durations 30
```

完成任务前运行 aggregate suite，并审计所有 discovered tests 均恰好归属一个 primary suite：

```bash
uv run python tests/run_test_suite.py all -b --durations 30
```

suite runner 迁移期间还应交叉验证 legacy discovery：

```bash
uv run python -m unittest discover -s tests -b
```

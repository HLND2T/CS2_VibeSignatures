[Back to README](../../README.md) | [中文](../zh-CN/development.md)

# Development checks

## Formatting

This repository formats Git-tracked `*.py` files with `ruff format` and Git-tracked `*.yaml` files with `yamlfix`.

Format locally before committing:

```bash
uv run python format_repo_files.py
```

Run the same formatting gate used by GitHub Actions:

```bash
uv run python format_repo_files.py --check
```

The formatter only uses files returned by `git ls-files --cached -- '*.py' '*.yaml'`, so ignored files and untracked scratch files are skipped. YAML under `ida_preprocessor_scripts/references/` and canonical symbol artifacts under `bin_artifacts/` are also skipped because their producers/canonicalizer control exact bytes.

## Tests

Use the fast isolated suite during local edit-test loops:

```bash
uv run python tests/run_test_suite.py unit -b --durations 30
```

The remaining primary suites keep repository-state, Redis, and Git release-transaction coverage explicit:

```bash
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py redis-integration -b --durations 30
uv run python tests/run_test_suite.py release-integration -b --durations 30
```

Run every assigned test and audit that no discovered test is missing or duplicated before completion:

```bash
uv run python tests/run_test_suite.py all -b --durations 30
```

During the suite-runner migration, also cross-check legacy discovery with:

```bash
uv run python -m unittest discover -s tests -b
```

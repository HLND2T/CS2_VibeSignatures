---
title: completion_checklist
type: note
permalink: cs2-vibesignatures/completion-checklist
---

# Completion checklist

- If changing scripts/config, ensure CLI usage in README and docstrings stays accurate.
- Before completion, run `uv run python format_repo_files.py --check` to verify formatting for tracked Python/YAML files. Use `uv run python format_repo_files.py` to apply formatting when needed.
- Before completion, run `uv run python -m unittest discover -s tests -b` to verify the regression tests. We should keep 0 unittest failure before committing.
- Formatting uses Ruff for `*.py` and yamlfix for tracked `*.yaml`; generated YAML under `ida_preprocessor_scripts/references/` is intentionally skipped.
- If outputs are expected, verify YAML in bin/<gamever>/... and versioned gamedata outputs in gamedata/<gamever>/...

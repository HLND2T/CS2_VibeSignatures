---
title: completion_checklist
type: note
permalink: cs2-vibesignatures/completion-checklist
---

# Completion checklist
- Confirm `bin_artifacts/<GAMEVER>/` is the only tracked per-symbol truth and the source/config/reference change includes its complete affected/downstream closure.
- Reject tracked `gamesymbols/**`, `gamedata/**`, `release-manifests/**`, and `bin/**/*.yaml`.
- Run `uv run python format_repo_files.py --check`; the formatter skips canonical `bin_artifacts` and reference YAML controlled by their producers.
- Run focused tests, then the primary unit, repository-contract, Redis, release-integration, and aggregate suites required by the change.
- Run repository artifact validation and verify required/optional/extra/stale/path/canonical/ownership contracts.
- For PR/release behavior, require isolated rebuild evidence and assert checkout expected artifacts stay unchanged.
- Run Pages tests/lint/build, action/workflow validation, C++ gates, and `git diff --check` when in scope.
- Do not claim completion or merge readiness without real new-GAMEVER bootstrap, Merge Queue trust-root, release dry-run, sandbox publish, and external byte-verification evidence when the migration plan requires them.
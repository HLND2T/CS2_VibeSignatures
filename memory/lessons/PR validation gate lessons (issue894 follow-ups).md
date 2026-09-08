---
title: PR validation gate lessons (issue894 follow-ups)
type: guide
permalink: cs2-vibesignatures/lessons/pr-validation-gate-lessons-issue894-follow-ups
tags:
- cs2vibesignatures
- ci
- pr-validation
- bin-artifacts
- formatter
---

# PR validation lessons (trusted planner / format gate)

## Symptom
- Trusted planner fails with `extra/stale Git artifacts for <gamever>` on a PR that changed configs for two gamevers (e.g. 14178 + 14178b) but only recomputed bin_artifacts for one.
- `test-prospective-tree` fails inside `format_repo_files.py --check` with ruyaml `DuplicateKeyError` even though local `unittest discover` is green (PyYAML tolerates duplicate mapping keys by silently overwriting).

## Root causes
1. Skill scripts are shared across gamevers: renaming/deleting a finder forces every `configs/*.yaml` to migrate, and each affected gamever needs its own recomputed `bin_artifacts/<gamever>/` closure. b-suffix gamevers are DIFFERENT binaries (thousands of artifacts differ), so values must be recomputed per gamever, never copied.
2. `ida_analyze_bin.py` preprocess runs under PyYAML semantics; the CI formatter uses ruyaml strict mode. A hand-repaired YAML block can contain a fully duplicated `expected_output:` pair that local tests never see.

## Correct workflow (pre-push gate for any config/artifact PR)
```bash
# 1. contract closure per affected gamever: expect EXTRA=0 MISSING=0
uv run python -c "from bin_artifact_contract import load_contract; ..."  # compare formal_paths vs git ls-files bin_artifacts/<gamever>/
# 2. formatter gate exactly as CI runs it
uv run python format_repo_files.py --check
# 3. suites as CI: unit, repository-contract, redis-integration, release-integration
uv run python tests/run_test_suite.py unit -b
```

## Recompute recipe (per gamever, checkout-external temp root)
- Artifact root must be nested `<tmp>/<gamever>/<module>/*.yaml` (a missing gamever layer disables the "all outputs exist" skip and triggers full recompute).
- Seed from `bin_artifacts/<gamever>/`, delete only affected outputs, run with `-oldgamever none -platform windows|linux -modules <m1>,<m2>`; existing outputs are auto-skipped.
- A killed ida_analyze_bin leaves `<binary>.id0` lock files: kill all idalib-mcp and delete locks before rerun, else "IDB lock file detected" aborts remaining modules.
- Cross-gamever acceptance: regenerated files must match the reference gamever's field sets and vfunc_offset/vfunc_index; rip-relative func_sig displacement bytes legitimately differ between gamevers.

## Local-vs-CI unit failures
2 unit tests (`test_collect_xref_func_starts_for_string_uses_substring_by_default`, `test_py_eval_extracts_standard_and_extended_registration_calls`) fail locally on this Windows workspace but CI's unit suite is green (proved by successful run 34068962978 on dev 48fbc2e9). Treat them as environment-only baseline noise; verify via an older green run instead of assuming breakage.

## Scope
CS2_VibeSignatures PR delivery: configs/, bin_artifacts/, ida_preprocessor_scripts/, `.github/workflows/\source-artifact-required.yml` jobs bind-source-artifact-plan / test-prospective-tree / validate-full.
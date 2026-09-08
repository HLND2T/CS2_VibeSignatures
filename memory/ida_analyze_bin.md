---
title: ida_analyze_bin
type: note
permalink: cs2-vibesignatures/ida-analyze-bin
---

# ida_analyze_bin

## Overview
`ida_analyze_bin.py` is the main dual-root CS2 analysis CLI. It keeps binaries/IDA state under `-bindir`, reads and writes per-symbol YAML under `-artifactdir`, optionally reuses prior source-owned artifacts from `-oldartifactdir`, and drives deterministic preprocessors, LLM/Agent fallbacks, canonical finalization, execution evidence, and optional release-local rename/comment post-processing.
## Responsibilities
- Parse binary/artifact roots, GAMEVER/config, platform/module/skill filters, force-all/execution-report, warm-IDB, Agent, and LLM options.
- Build ordered producer groups and dependencies from `configs/<GAMEVER>.yaml`.
- Run preprocessors and Agent fallbacks against the active artifact module directory; the legacy `new_binary_dir` ABI parameter carries this artifact path.
- Canonicalize every produced semantic payload through the central Source2 finalizer.
- Enforce selected-group execution/winner evidence for isolated PR/Release rebuilds.
- Keep binary hashing, loader, IDA database, and BinSync operations on the binary root; apply `-rename` only after validated producer execution.
## Involved Files & Symbols
- `ida_analyze_bin.py` - `parse_args`
- `ida_analyze_bin.py` - `resolve_oldgamever`
- `ida_analyze_bin.py` - `_is_major_update_gamever`
- `ida_analyze_bin.py` - `parse_vcall_finder_filter`
- `ida_analyze_bin.py` - `start_idalib_mcp`
- `ida_analyze_bin.py` - `process_binary`
- `ida_analyze_bin.py` - `main`
- `README.md` - `ida_analyze_bin.py` command examples, `-llm_*` parameter documentation, and IDA preprocessor environment variable notes
- `configs/<GAMEVER>.yaml` - module and skill metadata input
- `ida_skill_preprocessor.py` - downstream preprocessing stage used by `process_binary`

## Architecture
```text
config + binary root + artifact root + optional old artifact root
  -> ordered producer groups / dependencies
  -> per module/platform IDA session
  -> old-artifact reuse or deterministic/LLM/Agent producer
  -> central schema validation + canonical YAML finalization
  -> selected-group execution evidence
  -> optional rename/comment over validated actual artifacts
```

Normal local authoring writes tracked `bin_artifacts`; trusted PR/Release validation passes a checkout-external fresh actual root and compares it with Git expected bytes.
## Dependencies
- Python libraries: PyYAML, httpx, MCP SDK.
- External tools: uv, IDA/idalib-mcp, configured Agent CLI, optional LLM endpoint.
- Runtime inputs: `configs/<GAMEVER>.yaml`, `download.yaml`, binaries under `bin/<GAMEVER>/`, source-owned artifacts under `bin_artifacts/<GAMEVER>/`, and reference YAML.
## Notes
- `-force_all` disables existing-output skip for selected groups and requires execution evidence.
- `-oldgamever=none` disables old-artifact reuse; auto-resolution enumerates prior versions under the old artifact root, not private binary YAML.
- `-rename` operates on the active validated artifact root and release-local IDB/BinSync state; it never republishes Git truth.
- PR/Release callers use `-require_warm_idb`, checkout-external actual roots, and assert tracked expected artifacts remain unchanged.
- `bin/` is never a per-symbol correctness input.
## CLI Arguments
- `-configyaml`: analysis config; defaults to `configs/<GAMEVER>.yaml`.
- `-bindir`: binary/IDA workspace root; defaults to `bin`.
- `-artifactdir`: active per-symbol artifact root; defaults to tracked `bin_artifacts` for local authoring.
- `-oldartifactdir`: prior-version source-owned artifact root; defaults to `-artifactdir`.
- `-gamever`, `-platform`, `-modules`, `-skill`: execution scope.
- `-force_all`, `-execution_report`: trusted isolated/full rebuild controls and evidence.
- `-require_warm_idb`: forbid inline database creation and require exact warm state.
- `-agent`, `-llm_*`, `-maxretry`: Agent/LLM routing.
- `-rename`: apply rename/comment post-processing after producer validation.
- `-oldgamever`: explicit prior GAMEVER, auto resolution, or `none`.
## Environment Variables
- `CS2VIBE_GAMEVER`: environment-variable fallback for `-gamever`; if unset, `-gamever` must be passed explicitly.
- `CS2VIBE_AGENT`: environment-variable fallback for `-agent`.
- `CS2VIBE_LLM_MODEL`: environment-variable fallback for `-llm_model`.
- `CS2VIBE_LLM_APIKEY`: environment-variable fallback for `-llm_apikey`.
- `CS2VIBE_LLM_BASEURL`: environment-variable fallback for `-llm_baseurl`.
- `CS2VIBE_LLM_TEMPERATURE`: environment-variable fallback for `-llm_temperature`; still validated as a float after parsing.
- `CS2VIBE_LLM_FAKE_AS`: environment-variable fallback for `-llm_fake_as`; only `codex` is allowed after parsing.
- `CS2VIBE_LLM_EFFORT`: environment-variable fallback for `-llm_effort`; only `none|minimal|low|medium|high|xhigh` is allowed after parsing.
- `CS2VIBE_STRING_MIN_LENGTH`: downstream IDA preprocessing environment variable documented only in `README.md`, used to control `minlen` during string enumeration; it is not a direct `parse_args()` fallback.
- `OPENAI_API_KEY`, `OPENAI_API_BASE`, `OPENAI_API_MODEL`: `README.md` explicitly states that the `ida_analyze_bin.py` LLM workflow does not read these generic OpenAI environment variables.

## Callers
- Direct CLI invocation: `uv run ida_analyze_bin.py -gamever 14141 ...`
- Batch/script wrappers: the Windows workflow examples in `README.md` invoke this script

- [fact] Since the base-inherited-selected bridge (2026-09-06) `ida_analyze_bin.py` supports `-selected_execution <manifest>` (mutually exclusive with `-force_all` / `-skill` / `-vcall_finder` / `-rename` / `-skip_error`, requires both platforms): fail-closed manifest loading (digest domain `source-artifact-selected-execution-manifest:v1`, config_sha256 binding), seeded-root validation requiring the GAMEVER subtree to hold exactly the inherited whitelist (checkout-external, no reparse points), stable-node-id skill filtering with same-session prerequisite completeness enforcement, and a dedicated execution report type `source2-selected-execution:v1` (schema 1) that binds plan/manifest/paths/initial seeded inventory and never claims inherited bytes as executed evidence. In selected mode planned nodes skip the existing-output/skip_if_exists early-exits exactly like force_all.

## Gotcha: probe scripts must not reset the IDB string list

- 触发信号: local `force_all`/string-xref skills suddenly report `empty candidate set for string xref: FULLMATCH:<short>` for 4-char anchors (`none`, `rate`) while CI passes; strings-list probe shows `min_len_seen: 5`.
- 根因 / 约束: `idautils.Strings()` (constructor) and `.setup()` without args rebuild the string list with IDA's default `minlen=5`; idalib-mcp saves the IDB on exit, so a read-only-looking probe persists the reset and drops every 4-char string from the list. The repo enumerator (`_build_ida_strings_enumerator_py_lines`) guards setup behind a `$CS2VIBE_STRING_SETUP_STATE` netnode and only re-setups when `CS2VIBE_STRING_MIN_LENGTH` is set.
- 正确做法: in ad-hoc probes use `idautils.Strings(default_setup=False)` (or explicit `setup(minlen=4)`) and never bare `Strings()`. To repair a polluted warm IDB, run once with `CS2VIBE_STRING_MIN_LENGTH=4` in the environment (`.env` is loaded via `load_dotenv()`), which performs the netnode-guarded setup and writes the state back.
- 验证方式: py_eval counting `idautils.Strings()` entries and the minimal observed length; `FULLMATCH:none`/`FULLMATCH:rate` xref skills succeed again.
- 适用范围: any local IDA MCP probing against warm IDBs under `bin/<GAMEVER>/`, plus `find-*` skills anchored on strings shorter than 5 chars.


## Issue #937: finalization belongs inside the Agent attempt

- Trigger: Agent exits successfully and creates YAML, but canonicalization rejects conflicting vfunc_index/vfunc_offset after run_skill has already exhausted its own scope; the old caller aborted the full execution without a repair attempt.
- Root cause/constraint: file existence/Agent exit status are insufficient success criteria. Finalization previously ran after run_skill returned.
- Correct practice: process_binary supplies output_validator to agent_runner.run_skill. Each attempt validates produced artifacts before success; path-specific errors are added to the resumed Agent prompt with an explicit instruction not to skip invalid existing files. CLI and validation failures share one maxretry budget. The callback also checks interrupted/failed attempts. Protected prior-producer output modifications raise NonRetryableOutputError and stop further attempts. Preserve optional-output absence; record successful production evidence only after validated success. Never silently choose which conflicting metadata field is correct.
- Validation: 2026-09-08 real Claude fallback rebuilt CBaseEntity_GetChangeAccessorPathInfo_1.linux.yaml byte-for-byte. In a separate isolated fault injection, the first generated vfunc_index was deliberately incremented; canonicalization rejected it, the second of three permitted Agent attempts repaired it, and the final file matched Git (sha256 3a7d5f62b7393e520c60cad1d25a01302fa7ddbf193b9d7dc4b9e8e044c8b79d). Unit tests cover cross-Agent feedback transport, shared budget exhaustion, protected writes including timeout, and analyzer success evidence.
- Scope: Agent-skill fallback output validation. Deterministic preprocessor finalization and protected-output policy remain separate gates.

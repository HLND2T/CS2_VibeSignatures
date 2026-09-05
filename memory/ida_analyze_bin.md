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

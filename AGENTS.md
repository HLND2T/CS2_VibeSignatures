# AGENTS.md

This file provides guidance for Agent Coding in this repository, using progressive disclosure.

## Basic Memory Knowledge Base (Keep Context Compact)

1. Prefer `search_notes` to inspect notes available in `memory/`. Do not read all notes by default.
2. Use `read_note` to read a specific note only when needed. Load notes on demand.
3. If note information is insufficient or outdated, fall back to repository files or targeted lookup through ContextEngine, symbol tools, or search tools. Use `write_note`, `edit_note`, or `delete_note` to maintain notes.

## High-Level Repository Information (Prefer Relevant Notes)

The following information was summarized into Basic Memory notes during onboarding and is not repeated here:

- Project purpose, technology stack, and key external tools: `project_overview`
- Directory structure, module organization, and data-flow architecture: `project_overview`
- Common development commands: `suggested_commands`
- Code style and conventions: `style_and_conventions`
- Recommended checklist after completing a task: `completion_checklist`

Additional topic notes (search/read on demand):

- Binary acquisition and analysis: `download_depot`, `copy_depot_bin`, `binary_lock`, `ida_analyze_bin`, `warmup_idb`
- IDA / MCP / decompilation: `ida-pro-mcp`, `idalib-mcp`, `llm_decompile`, `ida_vcall_finder`, `generate_reference_yaml`, `ida_skill_preprocessor`
- Signatures and offsets: `func_sig`, `gv_sig`, `vfunc_sig`, `offset_sig`, `symbol_yaml`, `func_xrefs`
- Gamedata and release lifecycle: `gamedata_metadata`, `gamesymbol_metadata`, `gamedata_aliases`, `config_yaml`, `update_gamedata`, `pack_snapshot`, `post_change_candidate_lifecycle`, `release-staging`
- Tests and validation: `run_cpp_tests`, `cpp_tests_util`

## Source File Entry Points When Memories Are Insufficient (Query and Read on Demand)

- Quick overview: `README.md` / `README_CN.md`
- Dependency information: `pyproject.toml`, `uv.lock`
- Configuration: `.mcp.json`, `download.yaml`, `configs/<GAMEVER>.yaml`
- Main script entry points: `download_depot.py`, `copy_depot_bin.py`, `ida_analyze_bin.py`, `generate_reference_yaml.py`, `gamesymbol_candidate.py`, `gamedata_candidate.py`, `run_cpp_tests.py`, `update_gamedata.py`, `bin_artifact_contract.py`
- Large directories. Avoid reading them in full: `bin/`, `bin_artifacts/`, `hl2sdk_cs2/`, `gamedata-generators/`, `gamesymbol_snapshot_lib/`, `ida_preprocessor_scripts/`, `vcall_finder/`

## Progressive Disclosure Guidelines

- Read Basic Memory notes first, then locate individual files or symbols. Do not read the entire repository at once.
- `bin_artifacts/<GAMEVER>/<module>/*.yaml` is the only Git-tracked per-symbol truth. `bin/`, accepted-bin, and warm IDB are disposable cache/workspace layers and must contain no artifact truth.
- For binary/symbol directories, prefer targeted lookup on demand and avoid full scans.
- When external tools are involved (uv, IDA/idalib, ida-pro-mcp, Clang/LLVM, DepotDownloader, GitHub Actions), confirm the environment and path/variable configuration first.

## Explore SKILLs

- Project-level SKILLs should be explored from `.claude/skills` even when using Codex or other harness tools.

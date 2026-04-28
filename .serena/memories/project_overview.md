# Project overview

Purpose:
- Automate CS2 signature, offset, and C++ header updates through Agent SKILLs plus MCP-driven IDA workflows.
- Reduce or eliminate manual reverse-engineering work during game updates.
- Reuse previous-version YAML/signature data whenever possible to cut token cost and speed up refresh cycles.

Primary goals and scope:
- The repository is built to update signatures, offsets, and generated C++ headers with minimal human intervention.
- Fully automated update coverage is explicitly stated for CounterStrikeSharp and CS2Fixes.
- The project also maintains gamedata outputs for swiftlys2, plugify, cs2kz-metamod, modsharp, and CS2Surf/Timer.

Requirements:
- `uv`
- `depotdownloader`
- Claude or Codex
- IDA Pro 9.0+
- `ida-pro-mcp`
- `idalib` (mandatory for `ida_analyze_bin.py`)
- Clang/LLVM (mandatory for `run_cpp_tests.py`)

End-to-end workflow:
1. Download the CS2 depot:
   - `uv download_depot.py`
2. Copy target binaries into the workspace:
   - `uv run copy_depot_bin.py -gamever <ver> -platform <platform>`
   - `-checkonly` is used for CI or preflight validation of expected binary targets.
3. Analyze binaries and generate per-symbol YAML from `config.yaml`:
   - `uv run ida_analyze_bin.py -gamever <ver> ...`
   - The analyzer can reuse prior-version YAML first, before invoking Agent SKILLs, to avoid unnecessary token usage.
4. Convert YAML outputs into downstream gamedata artifacts:
   - `uv run update_gamedata.py -gamever <ver>`
5. Run C++ tests and optionally repair header mismatches:
   - `uv run run_cpp_tests.py -gamever <ver> [-fixheader]`
   - `-fixheader` triggers an agent-assisted header-fix workflow.

Analysis and automation model:
- The repository prefers deterministic preprocessors over LLM-based decompile helpers, and prefers LLM-based preprocessors over generic Agent SKILL fallback.
- Shared `-llm_*` CLI flags exist for LLM-backed workflows in `ida_analyze_bin.py`.
- Old signatures under `bin/<previous_gamever>/<module>/<symbol>.<platform>.yaml` are reused when possible.
- `vcall_finder` can export full per-reference disassembly/pseudocode, cache per-function YAML results, and aggregate final results into appended YAML streams.
- `generate_reference_yaml.py` prepares reference YAML inputs for `LLM_DECOMPILE` preprocessors.

Key repository components:
- `download_depot.py`: downloads the CS2 depot.
- `copy_depot_bin.py`: copies validated target binaries into `bin/<gamever>/...` and supports check-only validation.
- `ida_analyze_bin.py`: the main orchestration entry for MCP calls, preprocessors, SKILL execution, and YAML generation.
- `generate_reference_yaml.py`: builds reference YAML used by `LLM_DECOMPILE` preprocessors.
- `update_gamedata.py`: converts generated YAML into project-specific gamedata outputs.
- `run_cpp_tests.py`: validates generated headers against YAML and can launch agent-assisted header fixes.
- `config.yaml`: declares modules, symbols, and processing configuration.
- `ida_preprocessor_scripts/`: deterministic or LLM-assisted symbol-finding preprocessors and reference YAML files.
- `vcall_finder/`: cached per-function analysis artifacts and aggregated vcall outputs.
- `bin/`: versioned binaries and generated YAML artifacts.
- `dist/`: emitted gamedata for supported downstream projects.

Supported downstream outputs:
- CounterStrikeSharp: `dist/CounterStrikeSharp/.../gamedata.json`
- CS2Fixes: `dist/CS2Fixes/gamedata/cs2fixes.games.txt`
- swiftlys2: JSONC offsets and signatures under `dist/swiftlys2/...`
- plugify: `dist/plugify-plugin-s2sdk/assets/gamedata.jsonc`
- cs2kz-metamod: `dist/cs2kz-metamod/gamedata/cs2kz-core.games.txt`
- modsharp: multiple JSONC gamedata outputs under `dist/modsharp-public/.asset/gamedata/`
- CS2Surf/Timer: `dist/cs2surf/gamedata/cs2surf-core.games.jsonc`

Contribution and extension direction:
- The project explicitly welcomes new SKILL contributions through PRs.
- README guidance covers SKILL creation flows for vtables, regular functions, and global variables.
- Typical extension flow is: identify the symbol in IDA, create or update the relevant preprocessor/SKILL, register it in `config.yaml`, then feed the generated YAML into downstream gamedata and header validation steps.

---
title: suggested_commands
type: note
permalink: cs2-vibesignatures/suggested-commands
---

# Suggested commands

Prerequisites:
- Install or prepare `uv`, `depotdownloader`, `IDA Pro 9.0+`, `ida-pro-mcp`, `idalib` (required by `ida_analyze_bin.py`), `Clang/LLVM` (required by `run_cpp_tests.py`), and either `claude` or `codex`.

Download the CS2 depot:

```bash
uv download_depot.py
```

Copy validated game binaries into the workspace:

```bash
uv run copy_depot_bin.py -gamever <gamever> -platform all-platform
uv run copy_depot_bin.py -gamever <gamever> -platform all-platform -checkonly
```

Notes:
- Use `-checkonly` in CI or preflight scripts when you only need to verify whether all expected binaries already exist under `bin/<gamever>/...`.
- In `-checkonly` mode, the command returns `0` when all expected binaries are ready, `1` when any target is missing, and `2` for argument or configuration errors.

Analyze binaries and generate symbol YAML from `configs/<GAMEVER>.yaml`:

```bash
uv run ida_analyze_bin.py -gamever <gamever> [-oldgamever <previous_gamever>] [-configyaml configs/<gamever>.yaml] [-modules server] [-platform windows] [-agent claude|codex|"claude.cmd"|"codex.cmd"] [-maxretry 3] [-vcall_finder g_pNetworkMessages] [-llm_model gpt-5.4] [-llm_apikey <key>] [-llm_baseurl https://api.example.com/v1] [-llm_temperature 0.2] [-llm_effort medium] [-llm_fake_as codex] [-debug]
```

Notes:
- The analyzer reuses old YAML from `bin/<previous_gamever>/<module>/<symbol>.<platform>.yaml` when possible before invoking Agent SKILLs.
- Preferred automation order is: deterministic preprocessor scripts, then `LLM_DECOMPILE` preprocessors, then Agent `SKILL.md`.
- Shared LLM environment variable fallbacks are `CS2VIBE_LLM_APIKEY`, `CS2VIBE_LLM_BASEURL`, `CS2VIBE_LLM_MODEL`, `CS2VIBE_LLM_TEMPERATURE`, `CS2VIBE_LLM_EFFORT`, and `CS2VIBE_LLM_FAKE_AS`.
- LLM workflows do not read `OPENAI_API_KEY`, `OPENAI_API_BASE`, or `OPENAI_API_MODEL`.

Run `vcall_finder` for explicitly selected modules and objects:

```bash
uv run ida_analyze_bin.py -gamever <gamever> -modules networksystem -platform windows -vcall_finder g_pNetworkMessages -llm_model gpt-5.4 -llm_apikey <key> -llm_effort high -llm_fake_as codex -llm_baseurl http://127.0.0.1:8080/v1
```

`-vcall_finder` does not read object registrations from the versioned config. It requires explicit modules, rejects
`*`, and applies every requested object to every requested module.

Outputs:
- Per-function detail YAML: `vcall_finder/<gamever>/<object_name>/<module>/<platform>/...`
- Aggregated appended YAML stream: `vcall_finder/<gamever>/<object_name>.txt`

Generate a reference YAML for an `LLM_DECOMPILE` preprocessor:

```bash
uv run generate_reference_yaml.py -gamever <gamever> -module <module> -platform <platform> -func_name <func_name> -mcp_host 127.0.0.1 -mcp_port 13337
uv run generate_reference_yaml.py -gamever <gamever> -module <module> -platform <platform> -func_name <func_name> -auto_start_mcp -binary bin/<gamever>/<module>/<binary_name>
```

Reference path convention:
- `ida_preprocessor_scripts/references/<module>/<func_name>.<platform>.yaml`

Convert generated YAML into downstream gamedata:

```bash
uv run gamesymbol_candidate.py build -gamever <gamever> -bindir bin -configyaml configs/<GAMEVER>.yaml -output <candidate.yaml> -session <candidate.session.json>
uv run gamedata_candidate.py build -gamever <gamever> -build-id local-1 -snapshot <candidate.yaml> -configyaml configs/<gamever>.yaml -candidate-root <temp-root> -session <session.json> [-debug]
```

Run C++ layout validation:

```bash
uv run run_cpp_tests.py -gamever <gamever> -snapshot <candidate.yaml> [-debug]
```

Notes:
- After analysis, downstream consumers must use the same immutable candidate snapshot; they never fall back to `bin`.
- Historical replay may use `gamesymbols/<gamever>.yaml` directly instead of building a new candidate.
- Invoke the project-level `fix-cppheaders` SKILL to repair `hl2sdk_cs2` header differences.

Useful Claude Code prompts for creating preprocessors:

```text
/create-preprocessor-scripts Create "find-CCSPlayerPawn_vtable" in server.
/create-preprocessor-scripts Create "find-CItemDefuser_Spawn" in server by xref_strings "weapons/models/defuser/defuser.vmdl" "defuser_dropped", where CItemDefuser_Spawn is a vfunc of CItemDefuser_vtable.
/create-preprocessor-scripts Create "find-CBaseModelEntity_SetModel" in server by LLM_DECOMPILE with "CItemDefuser_Spawn", where CBaseModelEntity_SetModel is a regular function being called in "CItemDefuser_Spawn".
/create-preprocessor-scripts Create "find-IGameSystem_InitAllSystems" in server by xref_strings "IGameSystem::InitAllSystems", where IGameSystem_InitAllSystems is a regular func.
```

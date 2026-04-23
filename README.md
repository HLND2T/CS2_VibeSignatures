# CS2 VibeSignatures

[中文文档](README_CN.md)

This is a project mainly for generating signatures/offsets for CS2, updating HL2SDK_CS2 cpp headers via Agent SKILLS & MCP Calls.

Our goal is to update signatures/offsets/cppheaders without human involved.

Currently, all signatures/offsets from **CounterStrikeSharp** and **CS2Fixes** can be updated automatically with this project.

* Feel free to contribute your SKILLS with PR! [How to create SKILL? See here](https://github.com/hzqst/CS2_VibeSignatures/issues?q=is%3Aissue%20state%3Aclosed) -  `TODO: Add skill support for XXXXXXX` 

## Requirements

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)

2. [depotdownloader](https://github.com/steamre/depotdownloader)

3. claude / codex

4. IDA Pro 9.0+

5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)

6. [idalib](https://docs.hex-rays.com/user-guide/idalib) (mandatory for `ida_analyze_bin.py`)

7. Clang-LLVM (mandatory for `run_cpp_tests.py`)

## Overall workflow

#### 0. Install deps with uv

```bash
uv sync
```

#### 1. Download CS2 depot and copy binaries to workspace

```bash
DepotDownloader -app 730 -depot 2347771 -os all-platform -dir cs2_depot [-branch animgraph_2_beta]
DepotDownloader -app 730 -depot 2347773 -os all-platform -dir cs2_depot [-branch animgraph_2_beta]

uv run copy_depot_bin.py -gamever 14141 -platform all-platform
uv run copy_depot_bin.py -gamever 14141 -platform all-platform -checkonly
```

Use `-checkonly` in CI or preflight scripts when you only need to know whether all expected target binaries already exist under `bin/<gamever>/...`. In this mode the script only checks target paths, does not require a populated `cs2_depot`, returns `0` when all expected binaries are ready, `1` when any target is missing, and `2` for configuration or argument errors.

#### 2. Find and generate signatures for all symbols declared in `config.yaml`

 ```bash
 uv run ida_analyze_bin.py -gamever 14141 [-oldgamever=14140] [-configyaml=path/to/config.yaml] [-modules=server] [-platform=windows] [-agent=claude/codex/"claude.cmd"/"codex.cmd"] [-maxretry=3] [-vcall_finder=g_pNetworkMessages|*] [-llm_model=gpt-4o] [-llm_apikey=your-key] [-llm_baseurl=https://api.example.com/v1] [-llm_temperature=0.2] [-llm_effort=medium] [-llm_fake_as=codex] [-debug]
 ```

* Old signatures from `bin/{previous_gamever}/{module}/{symbol}.{platform}.yaml` will be used to find symbols in current version of game binaries directly through mcp call before actually running Agent SKILL(s). No token will be consumed in this case.

* `-agent="claude.cmd"` is for claude cli installed from Windows npm

* `-vcall_finder=g_pNetworkMessages` filters by an object declared in the module-level `vcall_finder` config; `-vcall_finder=*` processes every declared object from `config.yaml`.

* When `-vcall_finder` is enabled, the script exports full disassembly and pseudocode for each referencing function into `vcall_finder/{gamever}/{object_name}/{module}/{platform}/`, then runs LLM aggregation after all module/platform IDA work finishes; if a detail YAML already has a top-level `found_vcall`, that function skips the LLM call and reuses the cached result directly.

* After a successful LLM response, the script immediately writes back `found_vcall: [...]` or `found_vcall: []` to the corresponding detail YAML so reruns can skip that function's LLM call.

* `vcall_finder/{gamever}/{object_name}.txt` is now an appended YAML document stream; each record directly contains `insn_va`, `insn_disasm`, and `vfunc_offset` without a nested `found_vcall:` wrapper.

* Shared LLM CLI parameters:
  - `-llm_apikey`: required when an LLM-backed workflow is enabled, including `vcall_finder` aggregation and `LLM_DECOMPILE`
  - `-llm_baseurl`: optional custom compatible base URL (required when `-llm_fake_as=codex`)
  - `-llm_model`: optional, defaults to `gpt-4o`
  - `-llm_temperature`: optional; sent only when explicitly set
  - `-llm_effort`: optional; defaults to `medium`; supports `none|minimal|low|medium|high|xhigh`
  - `-llm_fake_as`: optional; `codex` switches to direct `/v1/responses` SSE transport
  - Env fallbacks: `CS2VIBE_LLM_APIKEY`, `CS2VIBE_LLM_BASEURL`, `CS2VIBE_LLM_MODEL`, `CS2VIBE_LLM_TEMPERATURE`, `CS2VIBE_LLM_EFFORT`, `CS2VIBE_LLM_FAKE_AS`
  - LLM workflows do not read `OPENAI_API_KEY`, `OPENAI_API_BASE`, or `OPENAI_API_MODEL`

```bash
uv run ida_analyze_bin.py -gamever=14141 -modules=networksystem -platform=windows -vcall_finder=g_pNetworkMessages -llm_model=gpt-5.4 -llm_apikey=your-key -llm_effort=high -llm_fake_as=codex -llm_baseurl=http://127.0.0.1:8080/v1
```

Example outputs:

- `vcall_finder/14141/g_pNetworkMessages/networksystem/windows/sub_140123450.yaml`
- `vcall_finder/14141/g_pNetworkMessages.txt`

* IDA preprocessor environment:
  - `CS2VIBE_STRING_MIN_LENGTH`: controls the minimum string length used by IDA preprocessor string enumeration logic only
  - Default: `4`
  - Empty, non-integer, or values `<1` fall back to `4`
  - This is not an LLM parameter

#### 2.5 Prepare reference YAML for `LLM_DECOMPILE`

Reference YAML path:

- `ida_preprocessor_scripts/references/<module>/<func_name>.<platform>.yaml`

Preparation steps:

1. Confirm the target function already has a current-version YAML with `func_va`, or can be resolved in IDA by symbol name/alias from `config.yaml`.
2. Run standalone CLI:

```bash
uv run generate_reference_yaml.py -gamever 14141 -module engine -platform windows -func_name CNetworkGameClient_RecordEntityBandwidth -mcp_host 127.0.0.1 -mcp_port 13337
```

Auto-start `idalib-mcp` example:

```bash
uv run generate_reference_yaml.py -gamever 14141 -module engine -platform windows -func_name CNetworkGameClient_RecordEntityBandwidth -auto_start_mcp -binary bin/14141/engine/engine2.dll
```

3. Check generated YAML:
   - `func_va` is credible
   - `disasm_code` is non-empty and matches target function semantics
   - `procedure` matches expected semantics when available (it can be an empty string when Hex-Rays is unavailable)
   - `func_name` only confirms the output file targets your requested canonical name; it does not prove address resolution correctness
4. Wire it in target `find-*.py` `LLM_DECOMPILE`:
   - Generated file path in repository:
     - `ida_preprocessor_scripts/references/<module>/<func_name>.<platform>.yaml`
   - If `LLM_DECOMPILE` uses relative path, write:
     - `references/<module>/<func_name>.<platform>.yaml`
   - Example tuple:
     - `("CNetworkMessages_FindNetworkGroup", "prompt/call_llm_decompile.md", "references/engine/CNetworkGameClient_RecordEntityBandwidth.windows.yaml")`
   - `LLM_DECOMPILE` uses the same shared `ida_analyze_bin.py` `-llm_*` flags: `-llm_model`, `-llm_apikey`, `-llm_baseurl`, `-llm_temperature`, `-llm_effort`, `-llm_fake_as`

#### 3. Convert yaml(s) to gamedata json / txt

```bash
uv run update_gamedata.py -gamever 14141 [-debug]
```

#### 4. Run cpp tests and check if cpp headers mismatch from yaml(s)

```bash
uv run run_cpp_tests.py -gamever 14141 [-debug] [-fixheader] [-agent=claude/codex/"claude.cmd"/"codex.cmd"] 
```

* When with `-fixheader`, an agent will be initiated to fix the mismatches in cpp headers.

### Currently supported gamedata

[CounterStrikeSharp](https://github.com/roflmuffin/CounterStrikeSharp)

`dist/CounterStrikeSharp/config/addons/counterstrikesharp/gamedata/gamedata.json`

 - 2 skipped symbols.

 - `GameEventManager`: not used anymore by CSS.
 - `CEntityResourceManifest_AddResource`: barely changes on game update.

[CS2Fixes](https://github.com/Source2ZE/CS2Fixes) 

`dist/CS2Fixes/gamedata/cs2fixes.games.txt`

 - `CCSPlayerPawn_GetMaxSpeed` skipped because it is not a thing in `server.dll`

[swiftlys2](https://github.com/swiftly-solution/swiftlys2) 

`dist/swiftlys2/plugin_files/gamedata/cs2/core/offsets.jsonc` 

`dist/swiftlys2/plugin_files/gamedata/cs2/core/signatures.jsonc`

[plugify](https://github.com/untrustedmodders/plugify-plugin-s2sdk) 

`dist/plugify-plugin-s2sdk/assets/gamedata.jsonc`

[cs2kz-metamod](https://github.com/KZGlobalTeam/cs2kz-metamod) 

`dist/cs2kz-metamod/gamedata/cs2kz-core.games.txt`

[modsharp](https://github.com/Kxnrl/modsharp-public) 

`dist/modsharp-public/.asset/gamedata/core.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/engine.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/EntityEnhancement.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/log.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/server.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/tier0.games.jsonc`

[CS2Surf/Timer](https://github.com/CS2Surf-CN/Timer) 

`dist/cs2surf/gamedata/cs2surf-core.games.jsonc` 
 
## How to create SKILL for vtable

`CCSPlayerPawn` for example.

Claude Code:

```
/create-preprocessor-scripts Create "find-CCSPlayerPawn_vtable" in server.
```

## How to create SKILL for regular function

### `CItemDefuser_Spawn` and `CBaseModelEntity_SetModel` for example

#### 1.Look for desired symbols in IDA 

  - Search string "weapons/models/defuser/defuser.vmdl" in IDA, look for code snippet with following pattern in xrefs to the string:

```c
    v2 = a2;
    v3 = (__int64)a1;
    sub_180XXXXXX(a1, (__int64)"weapons/models/defuser/defuser.vmdl"); //This is CBaseModelEntity_SetModel, rename it to CBaseModelEntity_SetModel
    sub_180YYYYYY(v3, v2);
    v4 = (_DWORD *)sub_180ZZZZZZ(&unk_181AAAAAA, 0xFFFFFFFFi64);
    if ( !v4 )
      v4 = *(_DWORD **)(qword_181BBBBBB + 8);
    if ( *v4 == 1 )
    {
      v5 = (__int64 *)(*(__int64 (__fastcall **)(__int64, const char *, _QWORD, _QWORD))(*(_QWORD *)qword_181CCCCCC + 48i64))(
                        qword_181CCCCCC,
                        "defuser_dropped",
                        0i64,
                        0i64);
```

The function with this code snippet is `CItemDefuser_Spawn`

#### 2. Create preprocessor script and update `config.yaml`

Claude Code:

```
/create-preprocessor-scripts Create "find-CItemDefuser_Spawn" in server by xref_strings "weapons/models/defuser/defuser.vmdl" "defuser_dropped", where CItemDefuser_Spawn is a vfunc of CItemDefuser_vtable.
```

Claude Code:

```
/create-preprocessor-scripts Create "find-CBaseModelEntity_SetModel" in server by LLM_DECOMPILE with "CItemDefuser_Spawn", where CBaseModelEntity_SetModel is a regular function being called in "CItemDefuser_Spawn".
```

## How to create SKILL for global variable

### `IGameSystem_InitAllSystems_pFirst` for example

#### 1. Look for desired symbols in IDA

  - Search string "IGameSystem::InitAllSystems" in IDA, search xrefs for the string. the function with xref to the string is `IGameSystem_InitAllSystems`. 
  
  - Rename it to `IGameSystem_InitAllSystems` if not renamed yet.
 
  - Look for code pattern at very beginning of IGameSystem_InitAllSystems: "( i = qword_XXXXXX; i; i = *(_QWORD *)(i + 8) )"
 
  - Rename `qword_XXXXXX` previously found to `IGameSystem_InitAllSystems_pFirst` if it was not renamed yet.

#### 2. Create preprocessor script and update `config.yaml`

Claude Code:

```
/create-preprocessor-scripts Create "find-IGameSystem_InitAllSystems" in server by xref_strings "IGameSystem::InitAllSystems", where IGameSystem_InitAllSystems is a regular func.
```

Claude Code:

```
/create-preprocessor-scripts Create "find-IGameSystem_InitAllSystems_pFirst" in server by LLM_DECOMPILE with "IGameSystem_InitAllSystems", where IGameSystem_InitAllSystems_pFirst is a global variable being used in "IGameSystem_InitAllSystems".
```

## How to create SKILL for struct offset

### `CGameResourceService_m_pEntitySystem` for example.

#### 1. Look for desired symbols in IDA

  - Search string "CGameResourceService::BuildResourceManifest(start)" in IDA, search xrefs for the string. 

  - The xref should point to a function - this is `CGameResourceService_BuildResourceManifest`. rename it to `CGameResourceService_BuildResourceManifest` if not renamed yet.

#### 2. Create preprocessor script and update `config.yaml`

Claude Code:

```
/create-preprocessor-scripts Create "find-CGameResourceService_BuildResourceManifest" in engine by xref_strings "CGameResourceService::BuildResourceManifest(start)" , where CGameResourceService_BuildResourceManifest is a vfunc of CGameResourceService_vtable.
```

```
/create-preprocessor-scripts Create "find-CGameResourceService_m_pEntitySystem" in engine by LLM_DECOMPILE with "CGameResourceService_BuildResourceManifest", where CGameResourceService_m_pEntitySystem is a struct offset.
```


## How to create SKILL for patch

* A patch SKILL locates a specific instruction inside a known function and generates replacement bytes to change its behavior at runtime (e.g., force/skip a branch, NOP a call). The target function should already have a corresponding find-SKILL output available (typically via `expected_input`).

* Always make sure you have ida-pro-mcp server running.

* For human contributor: You should write new initial prompts when looking for new symbols, **DO NOT** COPY-PASTE the initial prompts from README!!!

`CCSPlayer_MovementServices_FullWalkMove_SpeedClamp` for example — patching the velocity clamping `jbe` to an unconditional `jmp` inside `CCSPlayer_MovementServices_FullWalkMove`.

#### 1. Look for desired symbols in IDA

  - Decompile CCSPlayer_MovementServices_FullWalkMove and look for code pattern - whatever a float > A square of whatever a float:

```c
  v20 = (float)((float)(v16 * v16) + (float)(v19 * v19)) + (float)(v17 * v17);
  if ( v20 > (float)(v18 * v18) )
  {
    ...velocity clamping logic...
  }
```

  - Disassemble around the comparison to find the exact conditional jump instruction.

  - Disassemble around the comparison address to find the comiss + jbe instruction pair.

```
  Expected assembly pattern:
    addss   xmm2, xmm1          ; v20 = sum of squares
    comiss  xmm2, xmm0          ; compare v20 vs v18*v18
    jbe     loc_XXXXXXXX         ; skip clamp block if v20 <= v18*v18
```

  - Determine the patch bytes based on the instruction encoding.

```
  * Near `jbe` (`0F 86 rel32` — 6 bytes) → `E9 <new_rel32> 90` (unconditional `jmp` + `nop`)
  * Short `jbe` (`76 rel8` — 2 bytes) → `EB rel8` (unconditional `jmp short`)
```

#### 2. Create preprocessor script and update `config.yaml`

Follow the steps in [`.claude/skills/create-preprocessor-scripts/SKILL.md`](.claude/skills/create-preprocessor-scripts/SKILL.md) to create the preprocessor script and update `config.yaml`.

## Troubleshooting

### error: could not create 'ida.egg-info': access denied

Mitigation: You should run `python py-activate-idalib.py` under `C:\Program Files\IDA Professional 9.0\idalib\python` with **administrator** privilege.

### Could not find idalib64.dll in .........

Mitigation: Try `set IDADIR=C:\Program Files\IDA Professional 9.0` or add `IDADIR=C:\Program Files\IDA Professional 9.0` to your system environment.

## Jenkins workflow references

```bash
@echo Download latest game binaries

uv run download_bin.py -gamever %CS2_GAMEVER%
```

```bash
@echo Analyze game binaries

uv run ida_analyze_bin.py -gamever %CS2_GAMEVER% -agent="claude.cmd" -platform %CS2_PLATFORM% -debug
```

```bash
@echo Update gamedata with generated yamls

uv run update_gamedata.py -gamever %CS2_GAMEVER% -debug
```

```bash
@echo Find mismatches in CS2SDK headers and fix them

uv run run_cpp_tests.py -gamever %CS2_GAMEVER% -debug -fixheader -agent="claude.cmd"
```

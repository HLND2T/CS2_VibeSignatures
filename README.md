# CS2 VibeSignatures

[中文文档](README_CN.md)

This is a project mainly for generating signatures/offsets for CS2, updating HL2SDK_CS2 cpp headers via Agent SKILLS & MCP Calls.

Our goal is to update signatures/offsets/cppheaders without human involved.

Currently, all signatures/offsets from **CounterStrikeSharp** and **CS2Fixes** can be updated automatically with this project.

* Feel free to contribute your SKILLS with PR! [How to create SKILL? See here](https://github.com/hzqst/CS2_VibeSignatures/issues?q=is%3Aissue%20state%3Aclosed) -  `TODO: Add skill support for XXXXXXX` 

## Requirements

1. Install [uv](https://docs.astral.sh/uv/getting-started/installation/)

2. `uv sync`

3. claude / codex

4. IDA Pro 9.0+

5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)

6. [idalib](https://docs.hex-rays.com/user-guide/idalib) (mandatory for `ida_analyze_bin.py`)

7. Clang-LLVM (mandatory for `run_cpp_tests.py`)

## Overall workflow

#### 1. Download CS2 binaries

```bash
uv run python download_bin.py -gamever 14135
```

#### 2. Find and generate signatures for all symbols declared in `config.yaml`

 ```bash
 uv run python ida_analyze_bin.py -gamever=14135 [-configyaml=path/to/config.yaml] [-modules=server] [-platform=windows] [-agent=claude/codex] [-maxretry=3] [-debug]
 ```

* Old signatures from `bin/{previous_gamever}/{module}/{symbol}.{platform}.yaml` will be used to find symbols in current version of game binaries directly through mcp call before actually running Agent SKILL(s). No token will be consumed in this case.

#### 3. Convert yaml(s) to gamedata json / txt

```bash
uv run python update_gamedata.py -gamever 14135 [-debug]
```

#### 4. Run cpp tests and check if cpp headers mismatch from yaml(s)

```bash
uv run python run_cpp_tests.py -gamever 14135 [-debug] [-fixheader] [-agent=claude/codex]
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

 - 1 skipped symbol.

 - `CCSPlayerPawn_GetMaxSpeed` because it is not a thing in `server.dll`

[swiftlys2](https://github.com/swiftly-solution/swiftlys2) 

`dist/swiftlys2/plugin_files/gamedata/cs2/core/offsets.jsonc` 

`dist/swiftlys2/plugin_files/gamedata/cs2/core/signatures.jsonc`

 - 44 skipped symbols.

[plugify](https://github.com/untrustedmodders/plugify-plugin-s2sdk) 

`dist/plugify-plugin-s2sdk/assets/gamedata.jsonc`

 - 14 skipped symbols.
 
[cs2kz-metamod](https://github.com/Source2ZE/CS2Fixes) 

`dist/cs2kz-metamod/gamedata/cs2kz-core.games.txt`

 - 42 skipped symbols.
 
[modsharp](https://github.com/Kxnrl/modsharp-public) 

`dist/modsharp-public/.asset/gamedata/core.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/engine.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/EntityEnhancement.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/log.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/server.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/tier0.games.jsonc`

 - 230 skipped symbols.
 
[CS2Surf/Timer](https://github.com/CS2Surf-CN/Timer) 

`dist/cs2surf/gamedata/cs2surf-core.games.jsonc` 

 - 26 skipped symbols.
 
## How to create SKILL for vtable

`CCSPlayerPawn` for example.

#### 1. Create preprocessor script

 - Create `ida_preprocessor_scripts/find-CCSPlayerPawn_vtable.py`

 - **ALWAYS** check existing preprocessor scripts with `TARGET_CLASS_NAMES` for references.

 - no LLM needed when finding vtable. everything done in the preprocessor script.

#### 2. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` and `expected_input` (optional) explicitly declared.

```yaml
      - name: find-CCSPlayerPawn_vtable
        expected_output:
          - CCSPlayerPawn_vtable.{platform}.yaml
```

#### 3. Add the new symbol to `config.yaml`, under `symbols`.

```yaml
      - name: CCSPlayerPawn_vtable
        category: vtable
```

## How to create SKILL for regular function

* Always make sure you have ida-pro-mcp server running.

* For human contributor: You should write new initial prompts when looking for new symbols, **DO NOT** COPY-PASTE the initial prompts from README!!!

`CBaseModelEntity_SetModel` for example

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

#### 2. Create SKILL

  - Create project-level skill `find-CBaseModelEntity_SetModel` in **ENGLISH** according to what we did in IDA.
  
  - The SKILL should generate `CBaseModelEntity_SetModel.{platform}.yaml`, with `func_sig`.

  - The SKILL should be working with both `server.dll` and `libserver.so`.
  
  - DO NOT pack skill.
  
  - **ALWAYS** check existing SKILLs with `/write-func-as-yaml` invocation for references.

#### 3. Create preprocessor script

  - Create `ida_preprocessor_scripts/find-CBaseModelEntity_SetModel.py`

  - **ALWAYS** check existing preprocessor scripts with `TARGET_FUNCTION_NAMES` for references.

#### 4. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` and `expected_input` (optional) explicitly declared.

```yaml
      - name: find-CBaseModelEntity_SetModel
        expected_output:
          - CBaseModelEntity_SetModel.{platform}.yaml
```

5. Add the new symbol to `config.yaml`, under `symbols`.

```yaml
      - name: CBaseModelEntity_SetModel
        catagoty: func
        alias:
          - CBaseModelEntity::SetModel
```

## How to create SKILL for virtual function

* Always make sure you have ida-pro-mcp server running.

* For human contributor: You should write new initial prompts when looking for new symbols, **DO NOT** COPY-PASTE the initial prompts from README!!!

`CBasePlayerController_Respawn` for example

#### 1. Look for desired symbols in IDA

  - Search string "GMR_BeginRound" in IDA and look for a function with reference to it, decompile the function who reference "GMR_BeginRound" and look for code pattern in the decompiled function:

```c
      do
      {
        //.......
        if ( v31 )
        {
          if ( (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v31 + 3352LL))(v31) )
          {
            (*(void (__fastcall **)(__int64))(*(_QWORD *)v33 + 3368LL))(v33);
            if ( v36 )
            {
              sub_1801C86D0(v36);
              sub_18039EA00(v36, 32LL);
            }
          }
          else if ( v36 && *(_BYTE *)(v30 + 836) == 3 || *(_BYTE *)(v30 + 836) == 2 )
          {
            sub_1809F9670(v36);
            (*(void (__fastcall **)(__int64))(*(_QWORD *)v30 + 2176LL))(v30); // 2176LL is vfunc_offset for CBasePlayerController_Respawn
          }
        }
        ++v28;
      }
      while ( v28 != v29 );
```

#### 2. Create SKILL

  - Create project-level skill `find-CBasePlayerController_Respawn` in **ENGLISH**.
  
  - The SKILL should generate `CBasePlayerController_Respawn.{platform}.yaml`, with `func_sig`. (or `vfunc_sig` if `CBasePlayerController_Respawn` is too short or too generic).

  - The SKILL should be working with both `server.dll` and `libserver.so`.

  - DO NOT pack skill.
  
  - **ALWAYS** check existing SKILLs with `/write-vfunc-as-yaml` invocation for references.

#### 3. Create preprocessor script

  - Create `ida_preprocessor_scripts/find-CCSPlayerController_Respawn.py`

  - **ALWAYS** check existing preprocessor scripts with `TARGET_FUNCTION_NAMES` for references.

#### 4. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` and `expected_input` (optional) explicitly declared.

```yaml
      - name: find-CBasePlayerController_Respawn
        expected_output:
          - CBasePlayerController_Respawn.{platform}.yaml
        expected_input:
          - CBasePlayerController_vtable.{platform}.yaml
```

#### 5. Add the new symbol to `config.yaml`, under `symbols`.

```yaml
      - name: CBasePlayerController_Respawn
        category: vfunc
        alias:
          - CBasePlayerController::Respawn
```

## How to create SKILL for global variable

* Always make sure you have ida-pro-mcp server running.

* For human contributor: You should write new initial prompts when looking for new symbols, **DO NOT** COPY-PASTE the initial prompts from README!!!

`IGameSystem_InitAllSystems` AND `IGameSystem_InitAllSystems_pFirst` for example

#### 1. Look for desired symbols in IDA

  - Search string "IGameSystem::InitAllSystems" in IDA, search xrefs for the string. the function with xref to the string is `IGameSystem_InitAllSystems`. 
  
  - Rename it to `IGameSystem_InitAllSystems` if not renamed yet.
 
  - Look for code pattern at very beginning of IGameSystem_InitAllSystems: "( i = qword_XXXXXX; i; i = *(_QWORD *)(i + 8) )"
 
  - Rename `qword_XXXXXX` previously found to `IGameSystem_InitAllSystems_pFirst` if it was not renamed yet.

#### 2. Create SKILL

  - Create project-level skill `find-IGameSystem_InitAllSystems-AND-IGameSystem_InitAllSystems_pFirst` in **ENGLISH**.
  
  - The SKILL should generate `IGameSystem_InitAllSystems.{platform}.yaml`, with `func_sig`.

  - The SKILL should generate `IGameSystem_InitAllSystems_pFirst.{platform}.yaml`, with `gv_sig`.

  - DO NOT pack skill.
  
  - The SKILL should be working with both `server.dll` and `libserver.so`.
  
  - **ALWAYS** check existing SKILLs with `/write-func-as-yaml` and `/write-globalvar-as-yaml` invocation for references.
 
#### 3. Create preprocessor script

  - Create `ida_preprocessor_scripts/find-IGameSystem_InitAllSystems-AND-IGameSystem_InitAllSystems_pFirst.py`

  - **ALWAYS** check existing preprocessor scripts with `TARGET_FUNCTION_NAMES` and `TARGET_GLOBALVAR_NAMES` for references.

#### 4. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` and `expected_input` (optional) explicitly declared.

```yaml
      - name: find-IGameSystem_InitAllSystems-AND-IGameSystem_InitAllSystems_pFirst
        expected_output:
          - IGameSystem_InitAllSystems.{platform}.yaml
          - IGameSystem_InitAllSystems_pFirst.{platform}.yaml
```

#### 5. Add the new symbols to `config.yaml`, under `symbols`.

```yaml
      - name: IGameSystem_InitAllSystems
        category: func
        alias:
          - IGameSystem::InitAllSystems

      - name: IGameSystem_InitAllSystems_pFirst
        category: gv
        alias:
          - IGameSystem::InitAllSystems::pFirst
```

## How to create SKILL for struct offset

* Always make sure you have ida-pro-mcp server running.

* For human contributor: You should write new initial prompts when looking for new symbols, **DO NOT** COPY-PASTE the initial prompts from README!!!

`CGameResourceService_BuildResourceManifest` AND `CGameResourceService_m_pEntitySystem` for example.

#### 1. Look for desired symbols in IDA

  - Search string "CGameResourceService::BuildResourceManifest(start)" in IDA, search xrefs for the string. 

  - The xref should point to a function - this is `CGameResourceService_BuildResourceManifest`. rename it to `CGameResourceService_BuildResourceManifest` if not renamed yet.

#### 2. Create SKILL

  - Create project-level skill `find-CGameResourceService_BuildResourceManifest-AND-CGameResourceService_m_pEntitySystem` in **ENGLISH**. 
  
  - The SKILL should generate `CGameResourceService_BuildResourceManifest.{platform}.yaml`, with `func_sig`.

  - The SKILL should generate `CGameResourceService_m_pEntitySystem.{platform}.yaml`, with `offset` and `offset_sig`.

  - DO NOT pack skill.
  
  - The SKILL should be working with both `server.dll` and `libserver.so`.
  
  - **ALWAYS** check existing SKILLs with `/write-structoffset-as-yaml` invocation for references.

#### 3. Create preprocessor script

 - Create `ida_preprocessor_scripts/find-CGameResourceService_BuildResourceManifest-AND-CGameResourceService_m_pEntitySystem.py`

  - **ALWAYS** check existing preprocessor scripts with `TARGET_FUNCTION_NAMES` and `TARGET_STRUCT_MEMBER_NAMES` for references.

#### 4. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` and `expected_input` (optional) explicitly declared.

```yaml
      - name: find-CGameResourceService_BuildResourceManifest-AND-CGameResourceService_m_pEntitySystem
        expected_output:
          - CGameResourceService_BuildResourceManifest.{platform}.yaml
          - CGameResourceService_m_pEntitySystem.{platform}.yaml
```

#### 5. Add the new symbols to `config.yaml`, under `symbols`.

```yaml
      - name: CGameResourceService_BuildResourceManifest
        category: func
        alias:
          - CGameResourceService::BuildResourceManifest
          - BuildResourceManifest

      - name: CGameResourceService
        category: struct

      - name: CGameResourceService_m_pEntitySystem
        category: structmember
        struct: CGameResourceService
        member: m_pEntitySystem
        alias:
          - GameEntitySystem

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

#### 2. Create SKILL

 - Create project-level skill `find-CCSPlayer_MovementServices_FullWalkMove_SpeedClamp` in **ENGLISH**.

 - The SKILL should generate `CCSPlayer_MovementServices_FullWalkMove.{platform}.yaml`, with `patch_sig` and `patch_bytes`.

 - DO NOT pack skill.
 
 - The SKILL should be working with both `server.dll` and `libserver.so`.
 
 - **ALWAYS** check existing SKILL with `/write-patch-as-yaml` invocation for references.

#### 3. Create preprocessor script.

 - Create `ida_preprocessor_scripts/find-CCSPlayer_MovementServices_FullWalkMove_SpeedClamp.py`

  - **ALWAYS** check existing preprocessor scripts with `TARGET_PATCH_NAMES` for references.

#### 4. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` and `expected_input` (optional) explicitly declared.

```yaml
      - name: find-CCSPlayer_MovementServices_FullWalkMove_SpeedClamp
        expected_output:
          - CCSPlayer_MovementServices_FullWalkMove_SpeedClamp.{platform}.yaml
        expected_input:
          - CCSPlayer_MovementServices_FullWalkMove.{platform}.yaml
```

#### 5. Add the new symbol to `config.yaml`, under `symbols`.

```yaml
      - name: CCSPlayer_MovementServices_FullWalkMove_SpeedClamp
        category: patch
        alias:
          - ServerMovementUnlock
```

## Troubleshooting

### Cannot load IDA library file {name}, Please make sure you are using IDA 

This is because the official idapro package is not compatible with IDA 9.0

Mitigation: Overwrite `Python3**/Lib/site-packages/idapro/__init__.py` with `CS2_VibeSignatures/patched-py/Lib/site-packages/idapro/__init__.py`.

### error: could not create 'ida.egg-info': access denied

Mitigation: You should run `uv pip install --python .\python.exe .` and `.\python.exe py-activate-idalib.py` under `C:\Program Files\IDA Professional 9.0\idalib\python` with **administrator** privilege.

### Could not find idalib64.dll in .........

Mitigation: Try `set IDADIR=C:\Program Files\IDA Professional 9.0` or add `IDADIR=C:\Program Files\IDA Professional 9.0` to your system environment.

## Jenkins workflow references

```bash
@echo Download latest game binaries

uv run python download_bin.py -gamever %CS2_GAMEVER%
```

```bash
@echo Analyze game binaries

uv run python ida_analyze_bin.py -gamever %CS2_GAMEVER% -agent="claude.cmd" -platform %CS2_PLATFORM% -debug
```

```bash
@echo Update gamedata with generated yamls

uv run python update_gamedata.py -gamever %CS2_GAMEVER% -debug
```

```bash
@echo Find mismatches in CS2SDK headers and fix them

uv run python run_cpp_tests.py -gamever %CS2_GAMEVER% -debug -fixheader -agent="claude.cmd"
```

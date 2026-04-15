---
name: find-CBasePlayerController_SetPlayerName
description: Find and identify the CBasePlayerController_SetPlayerName function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the SetPlayerName function by searching for known string references and analyzing cross-references.
disable-model-invocation: true
---

# Find CBasePlayerController_SetPlayerName

Locate `CBasePlayerController_SetPlayerName` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

1. Search for strings `fov_desired` and `newname`:
   ```
   mcp__ida-pro-mcp__find_regex pattern="fov_desired"
   mcp__ida-pro-mcp__find_regex pattern="newname"
   ```

2. Get cross-references to both strings:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs=["<fov_desired_addr>", "<newname_addr>"]
   ```

3. Find the function that references **both** strings - this is the player info sync function `CGameRules_ClientSettingsChanged`.

4. Decompile that function and look for the call to `CBasePlayerController_SetPlayerName`:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

5. In the decompiled output, find the pattern:



   ```c
    if ( *v7 && strcmp(v7, v6) )
    {
      v9 = (__int64 *)(*(__int64 (__fastcall **)(__int64, const char *, _QWORD, _QWORD))(*(_QWORD *)qword_181EAF508
                                                                                       + 48LL))(
                        qword_181EAF508,
                        "player_changename",
                        0,
                        0);
      v10 = v9;
      if ( v9 )
      {
        v11 = *v9;
        v30 = -1073741696;
        v34 = *(void (__fastcall **)(__int64 *, int *, __int64))(v11 + 232);
        v31[0] = 0;
        v29 = 0;
        CBufferString::Insert((CBufferString *)&v29, 0, "userid", 6, 0);
        CBufferString::ToLowerFast((CBufferString *)&v29, 0);
        v12 = byte_18152DF80;
        if ( (v30 & 0x40000000) != 0 )
        {
          v13 = (char *)v31;
        }
        else
        {
          v13 = byte_18152DF80;
          if ( (v30 & 0x3FFFFFFF) != 0 )
            v13 = (char *)v31[0];
        }
        v14 = 1540483477
            * ((1540483477
              * ((unsigned __int8)v13[4]
               ^ (1540483477 * ((1540483477 * *(_DWORD *)v13) ^ ((unsigned int)(1540483477 * *(_DWORD *)v13) >> 24)))
               ^ ((unsigned __int8)v13[5] << 8)
               ^ 0x4846FFA0))
             ^ ((1540483477
               * ((unsigned __int8)v13[4]
                ^ (1540483477 * ((1540483477 * *(_DWORD *)v13) ^ ((unsigned int)(1540483477 * *(_DWORD *)v13) >> 24)))
                ^ ((unsigned __int8)v13[5] << 8)
                ^ 0x4846FFA0)) >> 13));
        CBufferString::Purge((CBufferString *)&v29, 0);
        v27 = -1;
        v26 = v14 ^ (v14 >> 15);
        v28 = "userid";
        v34(v10, &v26, a2);
        v15 = *v10;
        v30 = -1073741696;
        v34 = *(void (__fastcall **)(__int64 *, int *, __int64))(v15 + 192);
        v31[0] = 0;
        v29 = 0;
        CBufferString::Insert((CBufferString *)&v29, 0, "oldname", 7, 0);
        CBufferString::ToLowerFast((CBufferString *)&v29, 0);
        if ( (v30 & 0x40000000) != 0 )
        {
          v16 = (char *)v31;
        }
        else
        {
          v16 = byte_18152DF80;
          if ( (v30 & 0x3FFFFFFF) != 0 )
            v16 = (char *)v31[0];
        }
        v17 = 1540483477
            * ((1540483477
              * ((unsigned __int8)v16[4]
               ^ (1540483477 * ((1540483477 * *(_DWORD *)v16) ^ ((unsigned int)(1540483477 * *(_DWORD *)v16) >> 24)))
               ^ (((unsigned __int8)v16[5] ^ ((unsigned __int8)v16[6] << 8)) << 8)
               ^ 0xA418E935))
             ^ ((1540483477
               * ((unsigned __int8)v16[4]
                ^ (1540483477 * ((1540483477 * *(_DWORD *)v16) ^ ((unsigned int)(1540483477 * *(_DWORD *)v16) >> 24)))
                ^ (((unsigned __int8)v16[5] ^ ((unsigned __int8)v16[6] << 8)) << 8)
                ^ 0xA418E935)) >> 13));
        CBufferString::Purge((CBufferString *)&v29, 0);
        v27 = -1;
        v26 = v17 ^ (v17 >> 15);
        v28 = "oldname";
        v34(v10, &v26, (__int64)v8);
        v18 = *v10;
        v30 = -1073741696;
        v19 = *(void (__fastcall **)(__int64 *, int *, const char *))(v18 + 192);
        v31[0] = 0;
        v29 = 0;
        CBufferString::Insert((CBufferString *)&v29, 0, "newname", 7, 0);
        CBufferString::ToLowerFast((CBufferString *)&v29, 0);
        if ( (v30 & 0x40000000) != 0 )
        {
          v12 = (char *)v31;
        }
        else if ( (v30 & 0x3FFFFFFF) != 0 )
        {
          v12 = (char *)v31[0];
        }
        v20 = 1540483477
            * ((1540483477
              * ((unsigned __int8)v12[4]
               ^ (1540483477 * ((1540483477 * *(_DWORD *)v12) ^ ((unsigned int)(1540483477 * *(_DWORD *)v12) >> 24)))
               ^ (((unsigned __int8)v12[5] ^ ((unsigned __int8)v12[6] << 8)) << 8)
               ^ 0xA418E935))
             ^ ((1540483477
               * ((unsigned __int8)v12[4]
                ^ (1540483477 * ((1540483477 * *(_DWORD *)v12) ^ ((unsigned int)(1540483477 * *(_DWORD *)v12) >> 24)))
                ^ (((unsigned __int8)v12[5] ^ ((unsigned __int8)v12[6] << 8)) << 8)
                ^ 0xA418E935)) >> 13));
        CBufferString::Purge((CBufferString *)&v29, 0);
        v27 = -1;
        v26 = v20 ^ (v20 >> 15);
        v28 = "newname";
        v19(v10, &v26, v6);
        (*(void (__fastcall **)(__int64, __int64 *, _QWORD))(*(_QWORD *)qword_181EAF508 + 56LL))(
          qword_181EAF508,
          v10,
          0);
      }
      CBasePlayerController_SetPlayerName(a2, (__int64)v6);
   ```

6. Rename if needed:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<target_addr>", "name": "CBasePlayerController_SetPlayerName"}]}
   ```

7. Get function details for YAML:
   ```
   mcp__ida-pro-mcp__lookup_funcs queries="<target_addr>"
   ```

8. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

9. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBasePlayerController_SetPlayerName`
   - `func_addr`: The function address from step 7
   - `func_sig`: The validated signature from step 8

   Note: This is NOT a virtual function, so no vtable parameters are needed.

## Signature Pattern

The function is called after:
- Creating `CMsgPlayerInfo` message
- Firing `player_changename` event with `userid`, `oldname`, `newname` fields
- Comparing old and new player names

The surrounding function also handles `fov_desired` cvar (clamps FOV between 1-135).

## Function Characteristics

- **Type**: Regular member function (NOT virtual)
- **Parameters**: `(CBasePlayerController* this, const char* name)`
- **Behavior**:
  - Copies player name to `this + 0x510` using `V_strncpy` with max length 128
  - Calls network state change notification

## Hex Signature

| Bytes | Instruction | Description |
|-------|-------------|-------------|
| `41 B8 80 00 00 00` | `mov r8d, 80h` | 128 byte max name length (unique) |
| `48 8D 99 10 05 00 00` | `lea rbx, [rcx+510h]` | Name storage offset 0x510 (unique) |

**Final signature**: `41 B8 80 00 00 00 48 8D 99 10 05 00 00`

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBasePlayerController_SetPlayerName.windows.yaml`
- `libserver.so` → `CBasePlayerController_SetPlayerName.linux.yaml`

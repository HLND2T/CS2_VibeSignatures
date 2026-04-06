---
name: find-CNetworkMessages_SetIsForServer
description: |
  Find and identify the CNetworkMessages_SetIsForServer virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 engine2.dll or libengine2.so to locate the SetIsForServer vfunc call
  by decompiling CNetworkServerService_Init and identifying the virtual call through g_pNetworkMessages.
  Trigger: CNetworkMessages_SetIsForServer
disable-model-invocation: true
---

# Find CNetworkMessages_SetIsForServer

Locate `CNetworkMessages_SetIsForServer` vfunc call in CS2 engine2.dll or libengine2.so using IDA Pro MCP tools.

## Method

### 1. Get CNetworkServerService_Init Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetworkServerService_Init`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Decompile CNetworkServerService_Init

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Identify CNetworkMessages_SetIsForServer VFunc Offset from Code Pattern

In the decompiled output, look for the **virtual function call through `g_pNetworkMessages`** pattern at the very beginning of the function:

```c
  if ( qword_XXXXXXXX )
    sub_XXXXXXXX(0);
  v2 = *(void (__fastcall **)(__int64, _QWORD))(*(_QWORD *)g_pNetworkMessages + <VFUNC_OFFSET>);
  v3 = sub_XXXXXXXX();
  v2(g_pNetworkMessages, v3);                   // g_pNetworkMessages->SetIsForServer
  (**(void (__fastcall ***)(__int64, __int64, const char *))g_pNetworkMessages)(g_pNetworkMessages, 1, "ServerToClient");// g_pNetworkMessages->RegisterNetworkCategory
```

The `g_pNetworkMessages` is the global CNetworkMessages pointer, and `<VFUNC_OFFSET>` (e.g. `256LL` = `0x100`) is the vfunc offset of `CNetworkMessages_SetIsForServer`.

**Cross-validation**: The call to `SetIsForServer` is immediately followed by a call to `RegisterNetworkCategory` with the string `"ServerToClient"` as the third argument. This sequence is distinctive and confirms the correct virtual call.

Extract `<VFUNC_OFFSET>` from the code. Calculate the vtable index: `index = <VFUNC_OFFSET> / 8` (e.g. `256 / 8 = 32`).

### 4. Generate VFunc Offset Signature

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET>]` or `call qword ptr [rcx+<VFUNC_OFFSET>]` at the call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_SetIsForServer`, with `inst_addr` and `vfunc_offset` from this step.

### 5. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_SetIsForServer`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex (e.g. `0x100`)
- `vfunc_index`: The calculated index (e.g. `32`)

## Function Characteristics

- **Purpose**: Marks the CNetworkMessages instance as server-side, configuring it for server networking operations
- **Called from**: `CNetworkServerService_Init` — the initialization function for the network server service
- **Call context**: Called through `g_pNetworkMessages` vtable pointer immediately before `RegisterNetworkCategory("ServerToClient")`
- **Parameters**: `(this, is_server)` where `this` is the `g_pNetworkMessages` global pointer and `is_server` is the return value of a helper function

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CNetworkServerService_Init` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## Identification Pattern

The function is identified by locating the virtual call through `g_pNetworkMessages` inside `CNetworkServerService_Init`:
1. A global pointer `g_pNetworkMessages` is dereferenced to get a vtable
2. A virtual call is made at `vtable + <VFUNC_OFFSET>`
3. The call is immediately followed by `RegisterNetworkCategory` with `"ServerToClient"` argument
4. This appears at the very beginning of `CNetworkServerService_Init`

This is robust because:
- `CNetworkServerService_Init` is reliably found via its own xref strings (`"ServerToClient"`, `"Entities"`, etc.)
- The `SetIsForServer` call is the first virtual call through `g_pNetworkMessages` in the function
- The immediate sequence of `SetIsForServer` followed by `RegisterNetworkCategory("ServerToClient")` is distinctive

## Output YAML Format

The output YAML filename depends on the platform:
- `engine2.dll` -> `CNetworkMessages_SetIsForServer.windows.yaml`
- `libengine2.so` -> `CNetworkMessages_SetIsForServer.linux.yaml`

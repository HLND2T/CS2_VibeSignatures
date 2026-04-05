---
name: find-CNetworkMessages_SetNetworkSerializationContextData
description: |
  Find and identify the CNetworkMessages_SetNetworkSerializationContextData virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the SetNetworkSerializationContextData vfunc call
  by decompiling CEntitySystem_Activate and identifying the virtual call through g_pNetworkMessages.
  Trigger: CNetworkMessages_SetNetworkSerializationContextData
disable-model-invocation: true
---

# Find CNetworkMessages_SetNetworkSerializationContextData

Locate `CNetworkMessages_SetNetworkSerializationContextData` vfunc call in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

### 1. Get CEntitySystem_Activate Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CEntitySystem_Activate`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Decompile CEntitySystem_Activate

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Identify CNetworkMessages_SetNetworkSerializationContextData VFunc Offset from Code Pattern

In the decompiled output, look for the **virtual function call through `g_pNetworkMessages`** pattern near the `"EntitySystem - Class Tables"` string reference:

```c
  COM_TimestampedLog("EntitySystem - Class Tables", v9, m);
  if ( g_pNetworkMessages )
  {
    (*(void (__fastcall **)(__int64, const char *, _QWORD, __int64))(*(_QWORD *)g_pNetworkMessages + <VFUNC_OFFSET>))(
      g_pNetworkMessages,
      "string_t_table",
      *(unsigned int *)(a1 + 3012),
      a1 + 7888);
```

The `g_pNetworkMessages` is the global pointer, and `<VFUNC_OFFSET>` (e.g. `168LL` = `0xA8`) is the vfunc offset of `CNetworkMessages_SetNetworkSerializationContextData`.

Extract `<VFUNC_OFFSET>` from the call site. Calculate the vtable index: `index = <VFUNC_OFFSET> / 8` (e.g. `168 / 8 = 21`).

### 4. Generate VFunc Offset Signature

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET>]` or `call qword ptr [rcx+<VFUNC_OFFSET>]` at the call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_SetNetworkSerializationContextData`, with `inst_addr` and `vfunc_offset` from this step.

### 5. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_SetNetworkSerializationContextData`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex (e.g. `0xA8`)
- `vfunc_index`: The calculated index (e.g. `21`)

## Function Characteristics

- **Purpose**: Sets network serialization context data for entity class tables, including string table registration
- **Called from**: `CEntitySystem_Activate` — the function that activates the entity system and registers network class tables
- **Call context**: Called through `g_pNetworkMessages` vtable pointer with string table name, parameter, and entity system data
- **Parameters**: `(this, "string_t_table", string_table_param, entity_system_data)` where `this` is the `g_pNetworkMessages` global pointer

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CEntitySystem_Activate` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## Identification Pattern

The function is identified by locating the virtual call through `g_pNetworkMessages` inside `CEntitySystem_Activate`:
1. The xref string `"EntitySystem - Class Tables"` is passed to `COM_TimestampedLog`
2. A null check on `g_pNetworkMessages` follows
3. The first virtual call after the null check at `vtable + <VFUNC_OFFSET>` is `SetNetworkSerializationContextData`
4. The call passes `"string_t_table"` as the second argument

This is robust because:
- `CEntitySystem_Activate` is reliably found via xref string `"EntitySystem - Class Tables"`
- The `SetNetworkSerializationContextData` vfunc call pattern through `g_pNetworkMessages` is distinctive
- The `"string_t_table"` string argument provides cross-validation

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `CNetworkMessages_SetNetworkSerializationContextData.windows.yaml`
- `libserver.so` -> `CNetworkMessages_SetNetworkSerializationContextData.linux.yaml`

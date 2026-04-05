---
name: find-CNetworkMessages_GetLoggingChannel
description: |
  Find and identify the CNetworkMessages_GetLoggingChannel virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the GetLoggingChannel vfunc call
  by searching for the "CNetworkUtlVectorEmbedded: successfully late-resolved" log string, tracing to a
  CNetworkUtlVectorEmbedded::LateResolve template instance, and identifying the vfunc call through g_pNetworkMessages.
  Trigger: CNetworkMessages_GetLoggingChannel
disable-model-invocation: true
---

# Find CNetworkMessages_GetLoggingChannel

Locate `CNetworkMessages_GetLoggingChannel` vfunc call in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

### 1. Search for the LateResolve Log String

```
mcp__ida-pro-mcp__find_regex pattern="CNetworkUtlVectorEmbedded: successfully late-resolved"
```

This should find the string:
`"CNetworkUtlVectorEmbedded: successfully late-resolved 0x%p in entity %d:%s to %s:'%s'.\n"`

### 2. Find Cross-References to the String

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

There may be multiple xrefs because `CNetworkUtlVectorEmbedded::LateResolve` is a template function with multiple instantiations. Pick any one of them.

### 3. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": {"addr": "<function_addr>", "name": "CNetworkUtlVectorEmbedded_LateResolve"}}
```

### 4. Decompile and Locate the GetLoggingChannel VFunc Call Pattern

```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

Look for a pattern where `g_pNetworkMessages` is used to make a virtual call whose return value is passed to `LoggingSystem_IsChannelEnabled` and `LoggingSystem_Log`:

```c
        v15 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)g_pNetworkMessages + <VFUNC_OFFSET>))(g_pNetworkMessages);
        if ( (unsigned __int8)LoggingSystem_IsChannelEnabled(v15, 2LL) )
        {
          // ... prepare arguments ...
          v21 = (*(__int64 (**)(void))(*(_QWORD *)g_pNetworkMessages + <VFUNC_OFFSET>))();
          LoggingSystem_Log(
            v21,
            2LL,
            "CNetworkUtlVectorEmbedded: successfully late-resolved 0x%p in entity %d:%s to %s:'%s'.\n",
            ...);
        }
```

The `g_pNetworkMessages` is the global pointer, and `<VFUNC_OFFSET>` (e.g. `288LL` = `0x120`) is the vfunc offset of `CNetworkMessages_GetLoggingChannel`.

Key identification points:
- There are **two** identical virtual calls through `g_pNetworkMessages` with the same `<VFUNC_OFFSET>` in this block
- The first call's return value is passed to `LoggingSystem_IsChannelEnabled` as a channel handle
- The second call's return value is passed to `LoggingSystem_Log` as a channel handle
- Both calls take only `this` (the `g_pNetworkMessages` pointer) as argument

Extract `<VFUNC_OFFSET>` from either call site. Calculate the vtable index: `index = <VFUNC_OFFSET> / 8`.

### 5. Generate VFunc Offset Signature

Identify the instruction address (`inst_addr`) of either virtual call `call qword ptr [rax+<VFUNC_OFFSET>]` or `call qword ptr [rcx+<VFUNC_OFFSET>]` at the call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_GetLoggingChannel`, with `inst_addr` and `vfunc_offset` from this step.

### 6. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_GetLoggingChannel`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 5

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex (e.g. `0x120`)
- `vfunc_index`: The calculated index (e.g. `36`)

## Function Characteristics

- **Purpose**: Returns a logging channel handle used for network-related log messages
- **Called from**: `CNetworkUtlVectorEmbedded::LateResolve` template instances — functions that resolve late-bound network vector fields
- **Call context**: Called through `g_pNetworkMessages` vtable pointer, takes only `this` as argument, returns a logging channel handle
- **Parameters**: `(this)` where `this` is the `g_pNetworkMessages` global pointer
- **Return value**: A logging channel handle passed to `LoggingSystem_IsChannelEnabled` and `LoggingSystem_Log`

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CNetworkUtlVectorEmbedded::LateResolve` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## String-Based Discovery

The primary discovery method uses the LateResolve log message:

1. **Search string**: `"CNetworkUtlVectorEmbedded: successfully late-resolved 0x%p in entity %d:%s to %s:'%s'."`
2. **Xref chain**: String -> one of the `CNetworkUtlVectorEmbedded::LateResolve` template instances
3. **VFunc call**: Two identical virtual calls through `g_pNetworkMessages` with the same offset, whose return values are passed to `LoggingSystem_IsChannelEnabled` and `LoggingSystem_Log`

This is robust because:
- The `CNetworkUtlVectorEmbedded: successfully late-resolved` string is unique and stable across updates
- The dual `GetLoggingChannel` call pattern (check then log) through `g_pNetworkMessages` is distinctive
- Multiple template instances provide cross-validation with the same vfunc offset

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `CNetworkMessages_GetLoggingChannel.windows.yaml`
- `libserver.so` -> `CNetworkMessages_GetLoggingChannel.linux.yaml`

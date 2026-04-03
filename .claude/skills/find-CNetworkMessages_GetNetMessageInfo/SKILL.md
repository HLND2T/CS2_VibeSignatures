---
name: find-CNetworkMessages_GetNetMessageInfo
description: |
  Find and identify the CNetworkMessages_GetNetMessageInfo virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 networksystem.dll or libnetworksystem.so to locate the GetNetMessageInfo vfunc call
  by decompiling CNetChan_ProcessMessages and identifying the virtual call through g_pNetworkMessages.
  Trigger: CNetworkMessages_GetNetMessageInfo
disable-model-invocation: true
---

# Find CNetworkMessages_GetNetMessageInfo

Locate `CNetworkMessages_GetNetMessageInfo` vfunc call in CS2 networksystem.dll or libnetworksystem.so using IDA Pro MCP tools.

## Method

### 1. Get CNetChan_ProcessMessages Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetChan_ProcessMessages`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Decompile CNetChan_ProcessMessages

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Identify CNetworkMessages_GetNetMessageInfo VFunc Offset from Code Pattern

In the decompiled output, look for the **virtual function call through `g_pNetworkMessages`** pattern:

```c
    v30 = (*(__int64 (__fastcall **)(__int64, __int64))(*(_QWORD *)qword_XXXXXX + <VFUNC_OFFSET>))(qword_XXXXXX, v29);
    v31 = sub_XXXXXXXX(v68 + 16, (_DWORD)v10, (int)v72 + 29324, v72, v64, *(_QWORD *)(v30 + 8));
    if ( !v31 )
    {
      v32 = v29 ? (_QWORD *)(*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v29 + 16LL))(v29) : &unk_XXXXXXXX;
      if ( (unsigned __int8)LoggingSystem_IsChannelEnabled((unsigned int)dword_XXXXXXXX, 3LL) )
      {
        v33 = (__int64 (__fastcall ***)(_QWORD))v32[1];
        if ( v33 )
          v34 = (const char *)(**v33)(v33);
        else
          v34 = "unknown";
        LoggingSystem_Log(
          (unsigned int)dword_XXXXXXXX,
          3LL,
          "Error processing network message %s! Channel is closing!\n",
          v34);
      }
    }
```

The `qword_XXXXXX` is `g_pNetworkMessages`, and `<VFUNC_OFFSET>` (e.g. `96LL` = `0x60`) is the vfunc offset of `CNetworkMessages_GetNetMessageInfo`.

Extract `<VFUNC_OFFSET>` from the call site. Calculate the vtable index: `index = <VFUNC_OFFSET> / 8` (e.g. `96 / 8 = 12`).

### 4. Generate VFunc Offset Signature

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET>]` or `call qword ptr [rcx+<VFUNC_OFFSET>]` at the call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_GetNetMessageInfo`, with `inst_addr` and `vfunc_offset` from this step.

### 5. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_GetNetMessageInfo`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex (e.g. `0x60`)
- `vfunc_index`: The calculated index (e.g. `12`)

## Function Characteristics

- **Purpose**: Gets network message info (metadata) for a given message type
- **Called from**: `CNetChan_ProcessMessages` — the function that processes incoming network messages on a channel
- **Call context**: Called through `g_pNetworkMessages` vtable pointer with a message type parameter
- **Parameters**: `(this, msg_type)` where `this` is the `g_pNetworkMessages` global pointer

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CNetChan_ProcessMessages` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## Identification Pattern

The function is identified by locating the virtual call through `g_pNetworkMessages` inside `CNetChan_ProcessMessages`:
1. A global pointer `qword_XXXXXX` (`g_pNetworkMessages`) is dereferenced to get a vtable
2. A virtual call is made at `vtable + <VFUNC_OFFSET>`
3. The return value is used to get message info (the result + 8 is accessed for message name)
4. If processing fails, the error message "Error processing network message %s! Channel is closing!" is logged

This is robust because:
- `CNetChan_ProcessMessages` is reliably found via its own xref string
- The GetNetMessageInfo vfunc call pattern through `g_pNetworkMessages` is distinctive
- The nearby error log string provides cross-validation

## Output YAML Format

The output YAML filename depends on the platform:
- `networksystem.dll` -> `CNetworkMessages_GetNetMessageInfo.windows.yaml`
- `libnetworksystem.so` -> `CNetworkMessages_GetNetMessageInfo.linux.yaml`

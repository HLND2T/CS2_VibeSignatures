---
name: find-CNetworkMessages_SerializeAbstract
description: |
  Find and identify the CNetworkMessages_SerializeAbstract virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 engine2.dll or libengine2.so to locate the SerializeAbstract vfunc call
  by decompiling CDemoRecorder_ParseMessage and identifying the virtual call through g_pNetworkMessages.
  Trigger: CNetworkMessages_SerializeAbstract
disable-model-invocation: true
---

# Find CNetworkMessages_SerializeAbstract

Locate `CNetworkMessages_SerializeAbstract` vfunc call in CS2 engine2.dll or libengine2.so using IDA Pro MCP tools.

## Method

### 1. Get CDemoRecorder_ParseMessage Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CDemoRecorder_ParseMessage`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Decompile CDemoRecorder_ParseMessage

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Identify CNetworkMessages_SerializeAbstract VFunc Offset from Code Pattern

In the decompiled output, look for the **virtual function call through `g_pNetworkMessages`** pattern:

```c
    if ( !(*(unsigned __int8 (__fastcall **)(__int64, __int64, __int64, __int64))(*(_QWORD *)qword_XXXXXXX + <VFUNC_OFFSET>))(
            qword_XXXXXXX,
            v6,
            a2,
            a3)
      && (unsigned __int8)LoggingSystem_IsChannelEnabled((unsigned int)dword_YYYYYYYY, 3LL) )
    {
      LoggingSystem_Log(
        (unsigned int)dword_YYYYYYYY,
        3LL,
        "CDemoRecorder::ParseMessage: Failed to serialize message\n");
    }
```

The `qword_XXXXXXX` is `g_pNetworkMessages`, and `<VFUNC_OFFSET>` (e.g. `56LL` = `0x38`) is the vfunc offset of `CNetworkMessages_SerializeAbstract`.

Extract `<VFUNC_OFFSET>` from the call site. Calculate the vtable index: `index = <VFUNC_OFFSET> / 8` (e.g. `56 / 8 = 7`).

### 4. Generate VFunc Offset Signature

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET>]` or `call qword ptr [rcx+<VFUNC_OFFSET>]` at the call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_SerializeAbstract`, with `inst_addr` and `vfunc_offset` from this step.

### 5. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_SerializeAbstract`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex (e.g. `0x38`)
- `vfunc_index`: The calculated index (e.g. `7`)

## Function Characteristics

- **Purpose**: Serializes a network message abstractly (with message type and buffer parameters)
- **Called from**: `CDemoRecorder_ParseMessage` — the function that processes network messages for demo recording
- **Call context**: Called through `g_pNetworkMessages` vtable pointer with message type, buffer, and size parameters
- **Parameters**: `(this, msg_type, buf, size)` where `this` is the `g_pNetworkMessages` global pointer

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CDemoRecorder_ParseMessage` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## Identification Pattern

The function is identified by locating the virtual call through `g_pNetworkMessages` inside `CDemoRecorder_ParseMessage`:
1. A global pointer `qword_XXXXXXX` (`g_pNetworkMessages`) is dereferenced to get a vtable
2. A virtual call is made at `vtable + <VFUNC_OFFSET>`
3. The call passes message data and buffer parameters
4. The return value (bool) is checked — if it fails, the error message "CDemoRecorder::ParseMessage: Failed to serialize message" is logged

This is robust because:
- `CDemoRecorder_ParseMessage` is reliably found via its own xref string
- The SerializeAbstract vfunc call pattern through `g_pNetworkMessages` is distinctive
- The nearby error log string provides cross-validation

## Output YAML Format

The output YAML filename depends on the platform:
- `engine2.dll` -> `CNetworkMessages_SerializeAbstract.windows.yaml`
- `libengine2.so` -> `CNetworkMessages_SerializeAbstract.linux.yaml`

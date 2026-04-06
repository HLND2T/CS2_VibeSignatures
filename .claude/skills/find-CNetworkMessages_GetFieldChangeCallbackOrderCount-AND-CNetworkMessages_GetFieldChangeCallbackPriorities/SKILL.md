---
name: find-CNetworkMessages_GetFieldChangeCallbackOrderCount-AND-CNetworkMessages_GetFieldChangeCallbackPriorities
description: |
  Find and identify CNetworkMessages_GetFieldChangeCallbackOrderCount and CNetworkMessages_GetFieldChangeCallbackPriorities
  virtual function calls in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 networksystem.dll or
  libnetworksystem.so to locate both vfunc calls by decompiling CFlattenedSerializers_CreateFieldChangedEventQueue and
  identifying virtual calls through g_pNetworkMessages.
  Trigger: CNetworkMessages_GetFieldChangeCallbackOrderCount, CNetworkMessages_GetFieldChangeCallbackPriorities
disable-model-invocation: true
---

# Find CNetworkMessages_GetFieldChangeCallbackOrderCount and CNetworkMessages_GetFieldChangeCallbackPriorities

Locate `CNetworkMessages_GetFieldChangeCallbackOrderCount` and `CNetworkMessages_GetFieldChangeCallbackPriorities` vfunc calls in CS2 networksystem.dll or libnetworksystem.so using IDA Pro MCP tools.

## Method

### 1. Get CFlattenedSerializers_CreateFieldChangedEventQueue Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CFlattenedSerializers_CreateFieldChangedEventQueue`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Decompile CFlattenedSerializers_CreateFieldChangedEventQueue

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Identify CNetworkMessages_GetFieldChangeCallbackOrderCount VFunc Offset from Code Pattern

In the decompiled output, look for the **first virtual function call through `g_pNetworkMessages`** pattern. This is a call that takes only `g_pNetworkMessages` (this pointer) as the argument and returns a count value:

**Windows pattern:**
```c
    v7 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v6 + <VFUNC_OFFSET_A>))(v6);// g_pNetworkMessages->GetFieldChangeCallbackOrderCount
```

Where `v6` is `g_pNetworkMessages`.

**Linux pattern:**
```c
    v6 = *(__int64 (__fastcall **)())(*(_QWORD *)v5 + <VFUNC_OFFSET_A>);
    // ... may have inlined lock/unlock logic ...
    v9 = ((__int64 (__fastcall *)(__int64))v6)(v5);
```

Where `v5` is `g_pNetworkMessages`.

The `<VFUNC_OFFSET_A>` (e.g. `224LL` = `0xE0`) is the vfunc offset of `CNetworkMessages_GetFieldChangeCallbackOrderCount`.

Extract `<VFUNC_OFFSET_A>` from the call site. Calculate the vtable index: `index = <VFUNC_OFFSET_A> / 8` (e.g. `224 / 8 = 28`).

### 4. Generate VFunc Offset Signature for GetFieldChangeCallbackOrderCount

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET_A>]` or `call qword ptr [rcx+<VFUNC_OFFSET_A>]` at the call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_GetFieldChangeCallbackOrderCount`, with `inst_addr` and `vfunc_offset` from this step.

### 5. Write IDA Analysis Output as YAML for GetFieldChangeCallbackOrderCount

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_GetFieldChangeCallbackOrderCount`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET_A>` in hex (e.g. `0xE0`)
- `vfunc_index`: The calculated index (e.g. `28`)

### 6. Identify CNetworkMessages_GetFieldChangeCallbackPriorities VFunc Offset from Code Pattern

Further down in the same decompiled output, after the `GetFieldChangeCallbackOrderCount` call, look for the **second virtual function call through `g_pNetworkMessages`**. This call takes three arguments: the `g_pNetworkMessages` pointer, a count value, and a buffer pointer:

**Windows pattern:**
```c
        (*(void (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)g_pNetworkMessages
                                                         + <VFUNC_OFFSET_B>))(// g_pNetworkMessages->GetFieldChangeCallbackPriorities
          g_pNetworkMessages,
          v8,
          *(_QWORD *)(v5 + 40));
```

**Linux pattern:**
```c
  v15 = *(__int64 (__fastcall **)())(*(_QWORD *)g_pNetworkMessages + <VFUNC_OFFSET_B>);
  // ... may have inlined lock/unlock logic ...
  ((void (__fastcall *)(__int64, _QWORD, _QWORD))v15)(g_pNetworkMessages, v12, *(_QWORD *)(v3 + 40));
```

The `<VFUNC_OFFSET_B>` (e.g. `232LL` = `0xE8`) is the vfunc offset of `CNetworkMessages_GetFieldChangeCallbackPriorities`.

Extract `<VFUNC_OFFSET_B>` from the call site. Calculate the vtable index: `index = <VFUNC_OFFSET_B> / 8` (e.g. `232 / 8 = 29`).

### 7. Generate VFunc Offset Signature for GetFieldChangeCallbackPriorities

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET_B>]` or `call qword ptr [rcx+<VFUNC_OFFSET_B>]` at the call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_GetFieldChangeCallbackPriorities`, with `inst_addr` and `vfunc_offset` from this step.

### 8. Write IDA Analysis Output as YAML for GetFieldChangeCallbackPriorities

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_GetFieldChangeCallbackPriorities`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 7

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET_B>` in hex (e.g. `0xE8`)
- `vfunc_index`: The calculated index (e.g. `29`)

## Function Characteristics

### CNetworkMessages_GetFieldChangeCallbackOrderCount

- **Purpose**: Returns the number of field change callback order entries registered in the network messages system
- **Called from**: `CFlattenedSerializers_CreateFieldChangedEventQueue` — when creating a new field changed event queue, this count is used to allocate and initialize the priority tracking array
- **Call context**: Called through `g_pNetworkMessages` vtable pointer with only the this pointer
- **Parameters**: `(this)` where `this` is the `g_pNetworkMessages` global pointer
- **Return**: Integer count stored into the event queue structure and used to size the priority buffer

### CNetworkMessages_GetFieldChangeCallbackPriorities

- **Purpose**: Retrieves the field change callback priority values and copies them into the provided buffer
- **Called from**: `CFlattenedSerializers_CreateFieldChangedEventQueue` — after `GetFieldChangeCallbackOrderCount`, this fills the event queue's priority buffer
- **Call context**: Called through `g_pNetworkMessages` vtable pointer with count and buffer arguments
- **Parameters**: `(this, count, buffer_ptr)` where `this` is the `g_pNetworkMessages` global pointer, `count` is the order count from `GetFieldChangeCallbackOrderCount`, and `buffer_ptr` is the allocated priority buffer

## VTable Information

### CNetworkMessages (GetFieldChangeCallbackOrderCount)

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CFlattenedSerializers_CreateFieldChangedEventQueue` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET_A> / 8`.

### CNetworkMessages (GetFieldChangeCallbackPriorities)

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CFlattenedSerializers_CreateFieldChangedEventQueue` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET_B> / 8`.

## Identification Pattern

Both functions are identified from `CFlattenedSerializers_CreateFieldChangedEventQueue`:

1. The function allocates a `CNetworkFieldChangedEventQueue` object (232 bytes)
2. After initialization, it reads `g_pNetworkMessages` and makes a virtual call at `vtable + <VFUNC_OFFSET_A>` with only the this pointer — this is `GetFieldChangeCallbackOrderCount`
3. The return value (count) is stored in the queue structure at offset 220
4. After potential buffer resizing based on the count, a second virtual call at `vtable + <VFUNC_OFFSET_B>` is made through `g_pNetworkMessages` with `(this, count, buffer_ptr)` — this is `GetFieldChangeCallbackPriorities`
5. The two calls always appear in this sequence: first get the count, then get the priorities

This is robust because:
- `CFlattenedSerializers_CreateFieldChangedEventQueue` is reliably found via its own signature
- The `GetFieldChangeCallbackOrderCount` call is the first `g_pNetworkMessages` virtual call in the function, with a single-argument pattern
- The `GetFieldChangeCallbackPriorities` call is the second `g_pNetworkMessages` virtual call, with a three-argument pattern
- Both calls appear in a well-defined sequence with count-then-fill semantics
- The 232-byte allocation and `CNetworkFieldChangedEventQueue` vtable assignment provide additional context anchors

## Output YAML Format

The output YAML filenames depend on the platform:
- `networksystem.dll` -> `CNetworkMessages_GetFieldChangeCallbackOrderCount.windows.yaml`, `CNetworkMessages_GetFieldChangeCallbackPriorities.windows.yaml`
- `libnetworksystem.so` -> `CNetworkMessages_GetFieldChangeCallbackOrderCount.linux.yaml`, `CNetworkMessages_GetFieldChangeCallbackPriorities.linux.yaml`

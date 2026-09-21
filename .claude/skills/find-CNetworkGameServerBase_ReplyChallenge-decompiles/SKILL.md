---
name: find-CNetworkGameServerBase_ReplyChallenge-decompiles
description: |
  Agent fallback for the find-CNetworkGameServerBase_ReplyChallenge-decompiles preprocessor. Locates two virtual
  functions in CS2 engine2.dll / libengine2.so by decompiling their caller CNetworkGameServerBase_ReplyChallenge:
  CNetworkGameServerBase_GetChallengeType (a vcall on the server this-pointer) and
  INetworkSystem_GetSteamNetworkingSockets (a vcall on the g_pNetworkSystem global). Use this skill only when the
  deterministic/LLM preprocessor (ida_preprocessor_scripts/find-CNetworkGameServerBase_ReplyChallenge-decompiles.py)
  could not resolve either vfunc — for example when the LLM_DECOMPILE step failed with a transient API error.
  Trigger: CNetworkGameServerBase_GetChallengeType, INetworkSystem_GetSteamNetworkingSockets
disable-model-invocation: true
---

# Find CNetworkGameServerBase_GetChallengeType and INetworkSystem_GetSteamNetworkingSockets (Agent fallback)

Locate two virtual functions in CS2 `engine2.dll` / `libengine2.so` using IDA Pro MCP tools. This is the **Agent
fallback** for the `find-CNetworkGameServerBase_ReplyChallenge-decompiles` preprocessor: it runs only when the
preprocessor script returned failure. It reproduces the LLM_DECOMPILE step by hand — collecting the two virtual
calls made inside the single caller `CNetworkGameServerBase_ReplyChallenge`:

1. `CNetworkGameServerBase_GetChallengeType` — dispatched on the **server object** (`this`).
2. `INetworkSystem_GetSteamNetworkingSockets` — dispatched on the **`g_pNetworkSystem` global**.

Both outputs are **virtual dispatches** (`found_vcall`): each YAML records the vtable slot and a `vfunc_sig` that
pins the call instruction. There is **no concrete implementation address** — do not resolve or emit `func_va`.

## Realworld Function Reference

Read the platform-relevant reference YAML before searching in IDA. It provides concrete disassembly, decompiler
output, and the annotated call sites. Treat its addresses and offsets as reference-build values only; verify every
result against the current binary.

- Windows: `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_ReplyChallenge.windows.yaml`
- Linux: `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_ReplyChallenge.linux.yaml`

## Background — the two vcalls inside ReplyChallenge

`CNetworkGameServerBase_ReplyChallenge(this, netadr, a3)` builds an `S2C_CHALLENGE` reply packet.

- **GetChallengeType** is called very early — right after the bitbuf on the stack is initialized (a call of the form
  `sub_XXXX(&buf, storage, 512, 0xFFFFFFFF)`). It is a virtual call **on the server object itself**; its return value
  is the auth/challenge type, written into the bitbuf and logged as the `%u auth` field of
  `"Sending S2C_CHALLENGE [%u auth %d] to %s\n"`, and it drives the `type != 3` / `type == 3` branch.

  ```c
  // Linux reference (offset 0x2B0)
  v5 = (*(__int64 (__fastcall **)(__int64, _DWORD *))(*(_QWORD *)a1 + 688LL))(a1, a2);
  // Windows reference (offset 0x288)
  v6 = (*(__int64 (__fastcall **)(__int64, netadr_t *))(*(_QWORD *)a1 + 648LL))(a1, a2);
  ```

- **GetSteamNetworkingSockets** is the **last** virtual call in the function, just before the epilogue. It is
  dispatched on the **`g_pNetworkSystem` global** (an `INetworkSystem*`), and its result is immediately dereferenced
  to call slot `+0x58` (the send method) with the assembled bitbuf.

  ```c
  // Both platforms (offset 0x160)
  v32 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)g_pNetworkSystem + 352LL))(g_pNetworkSystem); // 352LL = 0x160
  return (*(__int64 (__fastcall **)(__int64, _QWORD, __int64, _QWORD, int, _QWORD))(*(_QWORD *)v32 + 88LL))(
           v32, ..., v34, ..., 5, 0);
  ```

The semantic roles above are the anchors — not the raw offsets, which change across updates.

> Do not confuse GetChallengeType with other vcalls in this function. It is the only vcall on the server `this`
> (`a1`). GetSteamNetworkingSockets is the only vcall on the `g_pNetworkSystem` global; the `+0x58` call that follows
> is a second-level dispatch on the object it returns, not on the global.

## Step 0. Skip if already produced

For each target, if `<name>.<platform>.yaml` already exists next to the binary and parses to a non-empty mapping,
**skip** that target — nothing to do. `/get-func-from-yaml` also reports existence.

## Step 1. Load and decompile the caller

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetworkGameServerBase_ReplyChallenge` to obtain its
`func_va`.

If the skill returns an error, **STOP** and report to user (this fallback cannot run without the predecessor).

Decompile it:

```
mcp__ida-pro-mcp__decompile addr="<CNetworkGameServerBase_ReplyChallenge.func_va>"
```

Confirm the `this` register (first argument — `rcx` on Windows, `rdi` on Linux).

## Step 2. Locate the two vcalls

### 2a. GetChallengeType — vcall on `this`

Find the virtual call dispatched on the server `this`:

```asm
mov     rax, [this]            ; load the object's vtable
...
call    qword ptr [rax+OFF]    ; OFF = vfunc_offset  (ref: 0x2B0 Linux / 0x288 Windows)
```

Confirm the semantic fingerprint:

1. It is the vcall on the **server object** (`this`/`a1`), not on a client / netchan pointer.
2. It appears right after the bitbuf-init call `sub_XXXX(&buf, storage, 512, 0xFFFFFFFF)`.
3. Its return value flows into the `"Sending S2C_CHALLENGE [%u auth %d] to %s\n"` log (the `%u`/`%d` auth field)
   and gates the `!= 3` branch.

Then: `vfunc_offset = OFF`, `vfunc_index = vfunc_offset / 8` (ref: `86` Linux `0x2B0`, `81` Windows `0x288`).

### 2b. GetSteamNetworkingSockets — vcall on `g_pNetworkSystem`

Find the virtual call dispatched on the `g_pNetworkSystem` global:

```asm
mov     rcx, cs:g_pNetworkSystem   ; (Windows) or  lea rax, g_pNetworkSystem (Linux)
mov     rax, [rcx]                 ; load the interface's vtable
call    qword ptr [rax+OFF]        ; OFF = vfunc_offset  (ref: 0x160 on both platforms)
```

Confirm the semantic fingerprint:

1. It is dispatched on `g_pNetworkSystem` (a global), not on `this` or a stack pointer.
2. It is the **last** vcall before the epilogue.
3. Its return value (`v32`/`rax`) is immediately dereferenced to call slot `+0x58` (`call qword ptr [rax+58h]`) with
   the assembled bitbuf.

Then: `vfunc_offset = OFF`, `vfunc_index = vfunc_offset / 8` (ref: `44` `0x160`, both platforms).

## Step 3. Generate the vfunc signatures

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` on each `call qword ptr [rax+OFF]` instruction to obtain
`vfunc_sig` (the offset bytes are fixed in the signature; `vfunc_sig_disp` is `0`).

## Step 4. Write the YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` for each target:

For `CNetworkGameServerBase_GetChallengeType`:

- `func_name`: `CNetworkGameServerBase_GetChallengeType`
- `vtable_name`: `CNetworkGameServerBase`
- `vfunc_offset`: the resolved offset (hex, e.g. `0x2B0` / `0x288`)
- `vfunc_index`: `vfunc_offset / 8`
- `vfunc_sig`: from Step 3
- `func_addr`: `None`   (no concrete implementation address for a virtual dispatch)
- `func_sig`: `None`

For `INetworkSystem_GetSteamNetworkingSockets`:

- `func_name`: `INetworkSystem_GetSteamNetworkingSockets`
- `vtable_name`: `INetworkSystem`
- `vfunc_offset`: the resolved offset (hex, e.g. `0x160`)
- `vfunc_index`: `vfunc_offset / 8`
- `vfunc_sig`: from Step 3
- `func_addr`: `None`   (no concrete implementation address for a virtual dispatch)
- `func_sig`: `None`

## Failure handling

- If the predecessor `CNetworkGameServerBase_ReplyChallenge` YAML is missing → **STOP** and report to user.
- If a vcall cannot be located → **STOP** and report exactly what could not be found, so the user can extend the
  reference. Recover the target you can find; do not block one on the other.

## Output YAML filenames

- Windows (`engine2.dll`): `CNetworkGameServerBase_GetChallengeType.windows.yaml`, `INetworkSystem_GetSteamNetworkingSockets.windows.yaml`
- Linux (`libengine2.so`): `CNetworkGameServerBase_GetChallengeType.linux.yaml`, `INetworkSystem_GetSteamNetworkingSockets.linux.yaml`

---
name: find-CNetworkGameServerBase_CheckTimeouts-decompiles
description: |
  Agent fallback for the find-CNetworkGameServerBase_CheckTimeouts-decompiles preprocessor. Locates the
  CNetworkGameServerBase_IsHLTV virtual function in CS2 engine2.dll / libengine2.so by decompiling its caller
  CNetworkGameServerBase_CheckTimeouts and reading the virtual dispatch made on the server this-pointer that
  gates the server-decided-timeout path. Use this skill only when the deterministic/LLM preprocessor
  (ida_preprocessor_scripts/find-CNetworkGameServerBase_CheckTimeouts-decompiles.py) could not resolve the
  vfunc — for example when the LLM_DECOMPILE step failed with a transient API error.
  Trigger: CNetworkGameServerBase_IsHLTV
disable-model-invocation: true
---

# Find CNetworkGameServerBase_IsHLTV (Agent fallback)

Locate the `CNetworkGameServerBase_IsHLTV` virtual function in CS2 `engine2.dll` / `libengine2.so` using IDA Pro
MCP tools. This is the **Agent fallback** for the `find-CNetworkGameServerBase_CheckTimeouts-decompiles`
preprocessor: it runs only when the preprocessor script returned failure. It reproduces the LLM_DECOMPILE step
by hand — collecting the virtual-call reference to `IsHLTV` inside its caller
`CNetworkGameServerBase_CheckTimeouts`.

The output is a **virtual dispatch** (`found_vcall`): the YAML records the vtable slot and a `vfunc_sig` that
pins the call instruction. There is **no concrete implementation address** — do not resolve or emit `func_va`.

## Realworld Function Reference

Read the platform-relevant reference YAML before searching in IDA. It provides concrete disassembly,
decompiler output, and the annotated call site. Treat its addresses and offsets as reference-build values only;
verify every result against the current binary.

- Windows: `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_CheckTimeouts.windows.yaml`
- Linux: `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_CheckTimeouts.linux.yaml`

## Background — where IsHLTV is called

`CNetworkGameServerBase_CheckTimeouts(this)` loops over connected clients. For each timed-out client it decides
how to disconnect. In that decision it makes a virtual call **on the server object itself** to test whether the
server is an HLTV/relay server:

```c
// Linux reference (offset 0x258)
if ( !(*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)a1 + 600LL))(a1)   // IsHLTV(this)
     && g_pSource2Server
     && ... )
// Windows reference (offset 0x230)
if ( !(*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)a1 + 560LL))(a1) ) // IsHLTV(this)
```

`IsHLTV` takes only `this` and returns a bool. When it returns false the routine takes the
`g_pSource2Server` "server-decided timeout" path. That semantic role — the vcall on the server object whose
negated result gates the `g_pSource2Server` branch — is the anchor, not the raw offset, which changes across
updates.

> Do not confuse it with the many other vcalls in this function. Those are dispatched on the **client**
> (`v5`/`rdi`) or the **netchan** (`v7`/`rsi`/`r15`) objects, not on the server `this` (`a1`). Only the `IsHLTV`
> call is `call qword ptr [rax+OFF]` where `rax = [a1]`.

## Step 0. Skip if already produced

If `CNetworkGameServerBase_IsHLTV.<platform>.yaml` already exists next to the binary and parses to a non-empty
mapping, **skip** — nothing to do. `/get-func-from-yaml` also reports existence.

## Step 1. Load and decompile the caller

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetworkGameServerBase_CheckTimeouts` to obtain its
`func_va`.

If the skill returns an error, **STOP** and report to user (this fallback cannot run without the predecessor).

Decompile it:

```
mcp__ida-pro-mcp__decompile addr="<CNetworkGameServerBase_CheckTimeouts.func_va>"
```

Confirm the `this` register (first argument — `rcx` on Windows, `rdi` on Linux, usually copied to `r14`/`r12`).

## Step 2. Locate the IsHLTV vcall

Find the virtual call dispatched on `this` that gates the `g_pSource2Server` path:

```asm
mov     rax, [this]            ; load the server object's vtable
mov     this-reg, this
call    qword ptr [rax+OFF]    ; OFF = vfunc_offset  (ref: 0x258 Linux / 0x230 Windows)
test    al, al
...                            ; g_pSource2Server used just after
```

Confirm the semantic fingerprint:

1. It is the vcall on the **server object** (`this`/`a1`), not on a client or netchan pointer.
2. It takes only `this` and returns a byte/bool tested immediately with `test al, al`.
3. Its (negated) result is followed by a load / use of `g_pSource2Server`.

Then:

- `vfunc_offset = OFF` (the displacement in the `call qword ptr [rax+OFF]` instruction)
- `vfunc_index = vfunc_offset / 8`  (ref: `75` Linux `0x258`, `70` Windows `0x230`)

## Step 3. Generate the vfunc signature

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` on the `call qword ptr [rax+OFF]` instruction to
obtain `vfunc_sig` (the offset bytes are fixed in the signature; `vfunc_sig_disp` is `0`).

## Step 4. Write the YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:

- `func_name`: `CNetworkGameServerBase_IsHLTV`
- `vtable_name`: `CNetworkGameServerBase`
- `vfunc_offset`: the resolved offset (hex, e.g. `0x258` / `0x230`)
- `vfunc_index`: `vfunc_offset / 8`
- `vfunc_sig`: from Step 3
- `func_addr`: `None`   (no concrete implementation address for a virtual dispatch)
- `func_sig`: `None`

## Failure handling

- If the predecessor `CNetworkGameServerBase_CheckTimeouts` YAML is missing → **STOP** and report to user.
- If the vcall cannot be located → **STOP** and report exactly what could not be found, so the user can extend
  the reference.

## Output YAML filenames

- Windows (`engine2.dll`): `CNetworkGameServerBase_IsHLTV.windows.yaml`
- Linux (`libengine2.so`): `CNetworkGameServerBase_IsHLTV.linux.yaml`

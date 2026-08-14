---
name: find-CNetworkGameServerBase_GetChallengeType
description: |
  Agent fallback for the find-CNetworkGameServerBase_GetChallengeType preprocessor. Locates the
  CNetworkGameServerBase_GetChallengeType virtual function in CS2 engine2.dll / libengine2.so by decompiling its
  caller CNetworkGameServerBase_ReplyChallenge and reading the first virtual dispatch made on the server
  this-pointer. Use this skill only when the deterministic/LLM preprocessor
  (ida_preprocessor_scripts/find-CNetworkGameServerBase_GetChallengeType.py) could not resolve the vfunc — for
  example when the LLM_DECOMPILE step failed with a transient API error.
  Trigger: CNetworkGameServerBase_GetChallengeType
disable-model-invocation: true
---

# Find CNetworkGameServerBase_GetChallengeType (Agent fallback)

Locate the `CNetworkGameServerBase_GetChallengeType` virtual function in CS2 `engine2.dll` / `libengine2.so`
using IDA Pro MCP tools. This is the **Agent fallback** for the `find-CNetworkGameServerBase_GetChallengeType`
preprocessor: it runs only when the preprocessor script returned failure. It reproduces the LLM_DECOMPILE step
by hand — collecting the virtual-call reference to `GetChallengeType` inside its caller
`CNetworkGameServerBase_ReplyChallenge`.

The output is a **virtual dispatch** (`found_vcall`): the YAML records the vtable slot and a `vfunc_sig` that
pins the call instruction. There is **no concrete implementation address** — do not resolve or emit `func_va`.

## Realworld Function Reference

Read the platform-relevant reference YAML before searching in IDA. It provides concrete disassembly,
decompiler output, and the annotated call site. Treat its addresses and offsets as reference-build values only;
verify every result against the current binary.

- Windows: `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_ReplyChallenge.windows.yaml`
- Linux: `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_ReplyChallenge.linux.yaml`

## Background — where GetChallengeType is called

`CNetworkGameServerBase_ReplyChallenge(this, netadr, a3)` builds an `S2C_CHALLENGE` reply. Very early — right
after it initializes a bitbuf on the stack (a call of the form `sub_XXXX(&buf, storage, 512, 0xFFFFFFFF)`) — it
makes a virtual call **on the server object itself** to obtain the challenge / authentication type:

```c
// Linux reference (offset 0x2B0)
v5 = (*(__int64 (__fastcall **)(__int64, _DWORD *))(*(_QWORD *)a1 + 688LL))(a1, a2);
// Windows reference (offset 0x288)
v6 = (*(__int64 (__fastcall **)(__int64, netadr_t *))(*(_QWORD *)a1 + 648LL))(a1, a2);
```

The returned value is the **auth/challenge type**. It is written into the bitbuf and later logged as the
`%u auth %d` field of `"Sending S2C_CHALLENGE [%u auth %d] to %s\n"`, and it drives the `if (type != 3)` /
`if (type == 3)` branch. That semantic role is the anchor — not the raw offset, which changes across updates.

## Step 0. Skip if already produced

If `CNetworkGameServerBase_GetChallengeType.<platform>.yaml` already exists next to the binary and parses to a
non-empty mapping, **skip** — nothing to do. `/get-func-from-yaml` also reports existence.

## Step 1. Load and decompile the caller

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetworkGameServerBase_ReplyChallenge` to obtain its
`func_va`.

If the skill returns an error, **STOP** and report to user (this fallback cannot run without the predecessor).

Decompile it:

```
mcp__ida-pro-mcp__decompile addr="<CNetworkGameServerBase_ReplyChallenge.func_va>"
```

Confirm the `this` register (first argument — `rcx` on Windows, `rdi` on Linux).

## Step 2. Locate the GetChallengeType vcall

Find the **first virtual call dispatched on `this`** in `ReplyChallenge`:

```asm
mov     rax, [this]            ; load the object's vtable
...
call    qword ptr [rax+OFF]    ; OFF = vfunc_offset  (ref: 0x2B0 Linux / 0x288 Windows)
```

Confirm the semantic fingerprint:

1. It is the vcall on the **server object** (`this`), not on a client / netchan pointer.
2. It appears right after the bitbuf-init call `sub_XXXX(&buf, storage, 512, 0xFFFFFFFF)`.
3. Its return value flows into the `"Sending S2C_CHALLENGE [%u auth %d] to %s\n"` log (the `%d`/`%u` auth field)
   and gates the `!= 3` branch.

Then:

- `vfunc_offset = OFF` (the displacement in the `call qword ptr [rax+OFF]` instruction)
- `vfunc_index = vfunc_offset / 8`  (ref: `86` Linux `0x2B0`, `81` Windows `0x288`)

## Step 3. Generate the vfunc signature

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` on the `call qword ptr [rax+OFF]` instruction to
obtain `vfunc_sig` (the offset bytes are fixed in the signature; `vfunc_sig_disp` is `0`).

## Step 4. Write the YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:

- `func_name`: `CNetworkGameServerBase_GetChallengeType`
- `vtable_name`: `CNetworkGameServerBase`
- `vfunc_offset`: the resolved offset (hex, e.g. `0x2B0` / `0x288`)
- `vfunc_index`: `vfunc_offset / 8`
- `vfunc_sig`: from Step 3
- `func_addr`: `None`   (no concrete implementation address for a virtual dispatch)
- `func_sig`: `None`

## Failure handling

- If the predecessor `CNetworkGameServerBase_ReplyChallenge` YAML is missing → **STOP** and report to user.
- If the vcall cannot be located → **STOP** and report exactly what could not be found, so the user can extend
  the reference.

## Output YAML filenames

- Windows (`engine2.dll`): `CNetworkGameServerBase_GetChallengeType.windows.yaml`
- Linux (`libengine2.so`): `CNetworkGameServerBase_GetChallengeType.linux.yaml`

---
name: find-CLoopTypeClientServer_RefreshNetworkGameState-decompiles
description: |
  Agent fallback for the find-CLoopTypeClientServer_RefreshNetworkGameState-decompiles preprocessor. Recovers the
  INetworkGameServer::Release and INetworkGameServer::AddRef virtual-call slots in CS2 engine2.dll / libengine2.so by
  decompiling CLoopTypeClientServer_RefreshNetworkGameState, following the de-inlined acquire helper when AddRef is not
  in the function body. Use only when the preprocessor failed (e.g. transient LLM error).
  Trigger: INetworkGameServer_Release, INetworkGameServer_AddRef
disable-model-invocation: true
---

# Find INetworkGameServer Release / AddRef (Agent fallback)

Both outputs are **indirect virtual calls** (`found_vcall`): record the call instruction, slot and a `vfunc_sig`.
Do not emit `func_va`.

## References (reference-build values only; verify against the current binary)

- `ida_preprocessor_scripts/references/engine/CLoopTypeClientServer_RefreshNetworkGameState.windows.yaml`
- `ida_preprocessor_scripts/references/engine/CLoopTypeClientServer_RefreshNetworkGameState.linux.yaml`
- `ida_preprocessor_scripts/references/engine/CLoopTypeClientServer_RefreshNetworkGameState_Acquire.linux.yaml`

## Step 0. Skip outputs that already exist

Skip any `<symbol>.<platform>.yaml` that already exists and parses non-empty.

## Step 1. Decompile the predecessor

`/get-func-from-yaml` with `func_name=CLoopTypeClientServer_RefreshNetworkGameState` (STOP on error), then decompile it.
Also check for `CLoopTypeClientServer_RefreshNetworkGameState_Acquire.<platform>.yaml` (optional helper).

## Step 2. INetworkGameServer_Release

The vcall on the object stored at `this+0x138` (second member, a game-server pointer), made before that member is
zeroed: `call qword ptr [rax+OFF]` with `OFF = 0x30` (index 6) in the references. The sibling vcall on `this+0x130`
(`OFF = 0x18`) is the client-side release — **do not confuse them**.

## Step 3. INetworkGameServer_AddRef

The vcall that follows `g_pNetworkServerService->[slot 0xC0/0xC8]()` storing into `this+0x138`:
`if (v) v->AddRef()` with `OFF = 0x28` (index 5). The preceding `g_pNetworkClientService` result at `this+0x130`
is AddRef'd through slot `0x10` — that is the client object, not the target.

- Windows reference: inline in `RefreshNetworkGameState`.
- Linux reference: in the de-inlined helper, as a tail dispatch (`mov rax,[rax+28h]` / `leave` / `jmp rax`). Decompile
  the Acquire helper (or the direct callee taking only `this`) if it is not in the body.

## Step 4. Signatures and YAML

`/generate-signature-for-vfuncoffset` on the instruction containing the displacement (for the Linux tail dispatch the
signature may need to cross the function boundary), then `/write-vfunc-as-yaml` with `vtable_name=INetworkGameServer`,
`func_addr=None`, `func_sig=None`, `vfunc_offset`, `vfunc_index = vfunc_offset / 8`, `vfunc_sig`.

## Failure handling

Predecessor YAML missing → STOP. If one target cannot be found, write the other and report which failed.

## Output YAML filenames

`INetworkGameServer_Release.{windows,linux}.yaml`, `INetworkGameServer_AddRef.{windows,linux}.yaml`

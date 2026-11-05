---
name: find-CLoopTypeClientServer_RefreshNetworkGameState_Acquire
description: |
  Agent fallback for the optional find-CLoopTypeClientServer_RefreshNetworkGameState_Acquire preprocessor.
  Locates the de-inlined helper that CLoopTypeClientServer_RefreshNetworkGameState calls to re-query the client/server
  network objects and AddRef the game server, in CS2 libengine2.so / engine2.dll. If the re-query is inlined into
  RefreshNetworkGameState (no such helper exists) write nothing and report that.
  Trigger: CLoopTypeClientServer_RefreshNetworkGameState_Acquire
disable-model-invocation: true
---

# Find CLoopTypeClientServer_RefreshNetworkGameState_Acquire (Agent fallback)

Optional producer: the output is **not required**. It exists only so
`find-CLoopTypeClientServer_RefreshNetworkGameState-decompiles` can decompile the helper that holds the
`INetworkGameServer::AddRef` vcall when it is de-inlined.

## Reference

- `ida_preprocessor_scripts/references/engine/CLoopTypeClientServer_RefreshNetworkGameState.{platform}.yaml`

## Steps

1. **Skip** if `CLoopTypeClientServer_RefreshNetworkGameState_Acquire.<platform>.yaml` already exists, or if both
   `INetworkGameServer_Release.<platform>.yaml` and `INetworkGameServer_AddRef.<platform>.yaml` already exist.
2. `/get-func-from-yaml` with `func_name=CLoopTypeClientServer_RefreshNetworkGameState`; if it errors, **STOP**.
   Decompile the returned `func_va`.
3. The function releases `this+0x130` (vtable slot `0x18`) and `this+0x138` (slot `0x30`, INetworkGameServer::Release),
   then re-acquires both. Look for a **direct call taking only `this`** between the release and the flag stores
   (Linux reference: one `call sub_*` right after the `this+0x138 = 0` store). That callee reads
   `g_pNetworkClientService` / `g_pNetworkServerService` (vcall slot `0xC0`/`0xC8`) and AddRefs the results.
4. If the re-query is inline (the `g_pNetworkClientService` / `g_pNetworkServerService` loads and the slot-`0x28`
   AddRef vcall are in `RefreshNetworkGameState` itself — Windows reference) there is **no helper**: write nothing
   and report "inlined, no helper".
5. Otherwise `/generate-signature-for-function` then `/write-func-as-yaml` with
   `func_name=CLoopTypeClientServer_RefreshNetworkGameState_Acquire`.

## Output YAML filenames

- `CLoopTypeClientServer_RefreshNetworkGameState_Acquire.windows.yaml` / `.linux.yaml` (only when de-inlined)

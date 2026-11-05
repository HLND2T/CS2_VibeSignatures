---
name: find-CLoopTypeClientServer_RefreshNetworkGameState
description: |
  Agent fallback for the find-CLoopTypeClientServer_RefreshNetworkGameState preprocessor. Locates the
  CLoopTypeClientServer_RefreshNetworkGameState regular function in CS2 engine2.dll / libengine2.so by decompiling
  its caller CLoopTypeClientServer_Update and finding the direct call that re-acquires the client/server game
  objects after the loop-mode switch. Use this skill only when the LLM_DECOMPILE preprocessor
  (ida_preprocessor_scripts/find-CLoopTypeClientServer_RefreshNetworkGameState.py) could not resolve the function,
  for example after a transient LLM API error.
  Trigger: CLoopTypeClientServer_RefreshNetworkGameState
disable-model-invocation: true
---

# Find CLoopTypeClientServer_RefreshNetworkGameState (Agent fallback)

Locate `CLoopTypeClientServer_RefreshNetworkGameState` in CS2 `engine2.dll` / `libengine2.so` using IDA Pro MCP
tools. This is the **Agent fallback** for the `find-CLoopTypeClientServer_RefreshNetworkGameState` preprocessor:
it runs only when the preprocessor returned failure, and reproduces its LLM_DECOMPILE step by hand.

The target is a **regular (non-virtual) function**. The output YAML carries `func_sig`, `func_va`, `func_rva`,
`func_size`.

## Realworld Function Reference

Read the platform-relevant reference YAML first. It has the disassembly, the decompiler output, and the
annotated call sites. Treat addresses as reference-build values only.

- Windows: `ida_preprocessor_scripts/references/engine/CLoopTypeClientServer_Update.windows.yaml`
- Linux: `ida_preprocessor_scripts/references/engine/CLoopTypeClientServer_Update.linux.yaml`

## Background

`CLoopTypeClientServer_Update(this, ...)` is the per-frame update of the client/server loop type. In the loop-mode
switch paths it calls `CLoopTypeClientServer_RefreshNetworkGameState(this)` with **only `this`** as argument
(`rcx` on Windows, `rdi` on Linux). The callee releases the cached client/server game objects
(`this+0x130` / `this+0x138`), re-queries them from `g_pNetworkClientService` / `g_pNetworkServerService`, calls
`AddRef` on the new ones and refreshes the `this+0x128..0x12A` availability flags.

There are **two call sites** in `Update`; both call the same function. One follows a
`g_pEngineServiceMgr`/`g_pSource2V8System` vcall run and a `sub_*` call, the other sits next to the
`mov byte ptr [..], 0` that clears a local flag. Both resolve to the same address.

## Step 0. Skip if already produced

If `CLoopTypeClientServer_RefreshNetworkGameState.<platform>.yaml` already exists beside the binary and parses
to a non-empty mapping, **skip**.

## Step 1. Decompile the caller

**ALWAYS** use SKILL `/get-func-from-yaml` with `func_name=CLoopTypeClientServer_Update` to obtain its `func_va`.
If it returns an error, **STOP** and report it.

```
mcp__ida-pro-mcp__decompile addr="<CLoopTypeClientServer_Update.func_va>"
```

## Step 2. Identify the callee

Find the direct `call sub_XXXX` that:

1. passes only `this` (the first argument of `Update`, copied to `r15` on Windows / `r15` on Linux);
2. is used twice in `Update`, both times with the same target;
3. whose body (decompile it to confirm) releases `this+0x130` via `[vtable+0x18]`, releases `this+0x138` via
   `[vtable+0x30]`, then re-queries both objects from `g_pNetworkClientService` / `g_pNetworkServerService`.

The callee's address is `func_va`. On Linux the callee is small; on Windows it is a mid-size function with the
re-query inlined. Do not confuse it with the neighbouring `sub_*` calls that also take `this` and `v299/v310`
(timing-struct) arguments.

## Step 3. Generate the signature and write the YAML

**ALWAYS** use SKILL `/generate-signature-for-function` for `func_va`, then SKILL `/write-func-as-yaml` with:

- `func_name`: `CLoopTypeClientServer_RefreshNetworkGameState`
- `func_addr`: the resolved `func_va`
- `func_sig`: from the signature step

## Failure handling

- Predecessor YAML missing → **STOP** and report.
- Callee cannot be uniquely identified → **STOP** and report what was found.

## Output YAML filenames

- Windows (`engine2.dll`): `CLoopTypeClientServer_RefreshNetworkGameState.windows.yaml`
- Linux (`libengine2.so`): `CLoopTypeClientServer_RefreshNetworkGameState.linux.yaml`

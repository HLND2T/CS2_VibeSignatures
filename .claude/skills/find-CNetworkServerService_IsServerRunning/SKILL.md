---
name: find-CNetworkServerService_IsServerRunning
description: |
  Final-guarantee fallback for the find-CNetworkServerService_IsServerRunning preprocessor.
  Recovers CNetworkServerService::IsServerRunning (a virtual function of the CNetworkServerService vtable)
  in CS2 engine2.dll / libengine2.so by decompiling its known predecessor
  CNetworkGameClientBase__ProcessNetworking and identifying the virtual call on g_pNetworkServerService.
  Use this skill only when the deterministic/LLM preprocessor
  (ida_preprocessor_scripts/find-CNetworkServerService_IsServerRunning.py) could not resolve the target.
  Trigger: CNetworkServerService_IsServerRunning
disable-model-invocation: true
---

# Find CNetworkServerService_IsServerRunning (final-guarantee fallback)

Recover the virtual function `CNetworkServerService::IsServerRunning` in CS2 `engine2.dll` /
`libengine2.so` using IDA Pro MCP tools. This is the **Agent fallback** for the
`find-CNetworkServerService_IsServerRunning` skill: it runs only when the preprocessor script returned
failure (almost always a transient LLM error, or the predecessor's call structure moved).

## Realworld Function References

Read the platform-relevant reference YAMLs before searching in IDA. They contain the annotated virtual
call site (`; 0x0E8/0x0F0 = ... = CNetworkServerService_IsServerRunning`). Treat their addresses as
reference-build values only; verify against the current binary.

- Windows baseline: `ida_preprocessor_scripts/references/engine/CNetworkGameClientBase__ProcessNetworking.windows.yaml`
- Linux baseline: `ida_preprocessor_scripts/references/engine/CNetworkGameClientBase__ProcessNetworking.linux.yaml`

## Step 1. Load and decompile the predecessor

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetworkGameClientBase__ProcessNetworking` to
obtain its `func_va`. If it returns an error, **STOP** and report to user (this fallback cannot run without
the predecessor).

Decompile it:

```
mcp__ida-pro-mcp__decompile addr="<CNetworkGameClientBase__ProcessNetworking.func_va>"
```

## Step 2. Locate the virtual call to the target

`CNetworkServerService::IsServerRunning(this)` is an indirect virtual call on the global
`g_pNetworkServerService`. Anchor by its **semantic fingerprint**, not a fixed offset:

- It is the (single) `call qword ptr [reg + <off>]` where `reg = *g_pNetworkServerService` (load the vtable
  from the global, then call through it).
- It returns a boolean (`al`) that is stored/tested to gate the per-tick client networking processing.

Reference build vtable offsets (verify, do not hardcode):

- Windows: `call qword ptr [rax+0E8h]` -> `vfunc_offset = 0xE8` (232), `vfunc_index = 29`
- Linux: `call qword ptr [rax+0F0h]` -> `vfunc_offset = 0xF0` (240), `vfunc_index = 30`

The vtable offset differs per platform; derive it from the located call instruction on the current binary.

## Step 3. Resolve the vfunc body, generate the signature, and write the YAML

1. From the resolved `vfunc_offset`, read the vtable slot of `CNetworkServerService_vtable` to obtain the
   concrete function address, and rename it to `CNetworkServerService_IsServerRunning` with
   `mcp__ida-pro-mcp__rename`.
2. **ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` for the vfunc at the resolved address/offset
   to obtain a validated `vfunc_sig`.
3. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `CNetworkServerService_IsServerRunning`
   - `vtable_name`: `CNetworkServerService`
   - `vfunc_sig`: the validated signature from step 2
   - `vfunc_offset` / `vfunc_index`: the resolved values

## Output YAML filenames

Written beside the binary by the writer skill, one file per platform:

- Windows (`engine2.dll`): `CNetworkServerService_IsServerRunning.windows.yaml`
- Linux (`libengine2.so`): `CNetworkServerService_IsServerRunning.linux.yaml`

## Failure handling

- If the predecessor `CNetworkGameClientBase__ProcessNetworking` YAML is missing → **STOP** and report to
  user.
- If the target virtual call cannot be located even after inspecting the predecessor → **STOP** and report
  so the user can extend the references.

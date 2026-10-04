---
name: find-CSource2Server_Shutdown-decompiles
description: |
  Final-guarantee fallback for the find-CSource2Server_Shutdown-decompiles preprocessor. Recovers the three
  teardown functions that CSource2Server::Shutdown calls directly — CGameEventManager_Shutdown,
  CLoopModeRegistry_UnregisterLoopModes, and CEngineServiceRegistry_UnregisterEngineServices — by decompiling
  CSource2Server_Shutdown in CS2 server.dll / libserver.so and reading its direct call targets. Use this skill
  only when the deterministic/LLM preprocessor (ida_preprocessor_scripts/find-CSource2Server_Shutdown-decompiles.py)
  could not resolve every target — for example when a previous-version func_sig no longer matches and the
  LLM_DECOMPILE step returns an empty result.
  Trigger: CGameEventManager_Shutdown, CLoopModeRegistry_UnregisterLoopModes,
  CEngineServiceRegistry_UnregisterEngineServices
disable-model-invocation: true
---

# Find CSource2Server_Shutdown-decompiles (final-guarantee fallback)

Recover the three functions that `CSource2Server::Shutdown` calls directly, in CS2 `server.dll` /
`libserver.so`, using IDA Pro MCP tools. This is the **Agent fallback** for the
`find-CSource2Server_Shutdown-decompiles` preprocessor: it runs only when the preprocessor script returned
failure. It reproduces the LLM_DECOMPILE step by hand — the three targets are ordinary **direct calls** made
from one well-known caller, so no cross-version name mapping is actually required: the caller's call graph
names them.

Every output is a **concrete function** (a `func_sig`), not a vcall. There is **no vtable** involved.

## Realworld Function References

Read the platform-relevant reference YAML before searching in IDA. It provides the concrete disassembly of
`CSource2Server_Shutdown` including the annotated call sites. Treat its addresses and offsets as
reference-build values only; verify every result against the current binary.

- Windows: `ida_preprocessor_scripts/references/server/CSource2Server_Shutdown.windows.yaml`
- Linux: `ida_preprocessor_scripts/references/server/CSource2Server_Shutdown.linux.yaml`

## Background — where the three teardown calls sit

`CSource2Server_Shutdown` is a short teardown routine. Its body is, in order:

1. shut down the game-event manager (`CGameEventManager_Shutdown`, passing the `gameeventmanager` global);
2. run a fixed sequence of four **indirect** calls through the same global object, each fetched as
   `vtable slot [reg+50h]` and each fed one freshly built argument (`sub_*` producers) — **these are not our
   targets**;
3. a contiguous run of four **direct calls**: the first two are our targets
   (`CLoopModeRegistry_UnregisterLoopModes`, then `CEngineServiceRegistry_UnregisterEngineServices`), followed
   by `ReleaseParticleEffects` and `ReleaseCSBotManager` which are **not** targets;
4. return through a tail `jmp`.

So the two requested functions in that run are its **first two** entries, sitting right after the four
`[reg+50h]` indirect dispatches and right before `ReleaseParticleEffects` / `ReleaseCSBotManager`. That
position — not the raw address — is the anchor, and it survives decompiler renames and address shifts across
updates.

Windows reference calls (platform refs, do not copy):

```
.text:0000000180CE832E   call    CLoopModeRegistry_UnregisterLoopModes
.text:0000000180CE8333   call    CEngineServiceRegistry_UnregisterEngineServices
.text:0000000180CE8338   call    ReleaseParticleEffects
.text:0000000180CE833D   call    ReleaseCSBotManager
```

`CGameEventManager_Shutdown` is the **first** meaningful call in the routine, ahead of the four indirect
dispatches, and is the only one taking the `gameeventmanager` global:

```
.text:0000000180CE82A6   mov     rcx, cs:gameeventmanager
.text:0000000180CE82AD   call    CGameEventManager_Shutdown
```

## Step 0. Skip targets already produced

Some outputs may already exist beside the binary (written by the preprocessor before it failed). For each
output, if `<name>.<platform>.yaml` already exists next to the binary and parses to a non-empty mapping,
**skip it** and spend effort only on the missing ones.

```
mcp__ida-pro-mcp__py_eval code="import idaapi, os; d=os.path.dirname(idaapi.get_input_file_path()); print('\n'.join(sorted(f for f in os.listdir(d) if f.endswith('.yaml'))))"
```

`/get-func-from-yaml` also reports existence for functions (returns an error when absent).

## Step 1. Load and decompile the predecessor

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CSource2Server_Shutdown` to obtain its `func_va`.

If the skill returns an error, **STOP** and report to user (this fallback cannot run without the predecessor).

Decompile it and read its direct calls:

```
mcp__ida-pro-mcp__decompile addr="<CSource2Server_Shutdown.func_va>"
```

Do not rely on the reference addresses. Identify each target by the semantic position described in
**Background** above.

## Step 2. Resolve the three direct calls

Locate each instruction and confirm it is a direct `call` (or a tail `jmp` — treat the same way).

### 2a. `CGameEventManager_Shutdown`

The **first** meaningful call in the routine. It is preceded by a load of the `gameeventmanager` global into
the argument register (`rcx` on Windows, `rdi` on Linux):

```c
CGameEventManager_Shutdown(&s_GameEventManager);
```

If the operand still reads `sub_XXXXXXXX`, that first call — the one fed by the `gameeventmanager` global and
made *before* the four `[reg+50h]` indirect dispatches — is this function. Rename it with
`mcp__ida-pro-mcp__rename` before generating the signature.

### 2b. `CLoopModeRegistry_UnregisterLoopModes`

The **first** call of the contiguous direct-call run described in Background (the run sitting between the
four `[reg+50h]` indirect dispatches and the `ReleaseParticleEffects` / `ReleaseCSBotManager` pair).

### 2c. `CEngineServiceRegistry_UnregisterEngineServices`

The **second** call of that same run, immediately after `CLoopModeRegistry_UnregisterLoopModes` and
immediately before `ReleaseParticleEffects`. Keep the order: `CLoopModeRegistry_UnregisterLoopModes` comes
first, `CEngineServiceRegistry_UnregisterEngineServices` second.

Confirm all three are **direct calls from `CSource2Server_Shutdown`**, not references that merely appear in a
reference block or comment. If the operand is a `j_XXXX` thunk, report the real function name `XXXX` (strip
the `j_` prefix).

## Step 3. Generate signatures and write the YAMLs

For each of the three resolved functions:

1. **ALWAYS** Use SKILL `/generate-signature-for-function` with `addr=<func_addr>` to obtain `func_sig`.
2. **ALWAYS** Use SKILL `/write-func-as-yaml` with:
   - `func_name`: the resolved symbol (e.g. `CLoopModeRegistry_UnregisterLoopModes`)
   - `func_addr`: the resolved address
   - `func_sig`: the validated signature from step 1

`CGameEventManager_Shutdown` is a tiny tail-call-style stub, so its signature may need to extend past the end
of the function into the next one. When `/generate-signature-for-function` cannot produce a unique signature
inside the function, allow the signature to cross the function boundary
(`func_sig_allow_across_function_boundary: true`) — this is the platform reference value and is expected.

Write each output beside the binary with the writer skill; do not hand-edit the YAML.

## Failure handling

- If the **predecessor** `CSource2Server_Shutdown` YAML is missing → **STOP** and report to user.
- If a target cannot be located by position even after reading the full decompilation → resolve the ones you
  can, then **STOP** and report exactly which output(s) could not be found, so the user can extend the
  references. Do not guess a `sub_*` by proximity.
- Never emit a symbol you did not confirm as a direct call from `CSource2Server_Shutdown`.

## Output YAML filenames

Written beside the binary by the writer skill, one file per symbol:

- Windows (`server.dll`): `<symbol>.windows.yaml`
- Linux (`libserver.so`): `<symbol>.linux.yaml`

e.g. `CGameEventManager_Shutdown.windows.yaml`, `CLoopModeRegistry_UnregisterLoopModes.windows.yaml`,
`CEngineServiceRegistry_UnregisterEngineServices.linux.yaml`.

## Why this is robust

- All three targets are direct calls from a single, stable caller (`CSource2Server_Shutdown`), so no
  cross-version name mapping or vtable slot is involved.
- Each target is anchored to its **position** in the caller (the first call, and the first/second of the
  contiguous post-dispatch run), which is stable even when addresses, offsets, and decompiler names change
  across updates.
- The anchor degrades gracefully when the callers' callees are unresolved `sub_*`: the semantic position and
  the neighboring `ReleaseParticleEffects` / `ReleaseCSBotManager` calls still identify the run.

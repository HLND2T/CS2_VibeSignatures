---
name: find-CNetworkGameServerBase_ServiceQueue
description: |
  Final-guarantee fallback for the find-CNetworkGameServerBase_ServiceQueue preprocessor. Recovers
  CNetworkGameServerBase_ServiceQueue in CS2 engine2.dll / libengine2.so when the LLM_DECOMPILE
  preprocessor cannot resolve the tail-call target of CNetworkGameServerBase_SpawnGroupThink. Use this
  skill only after the deterministic preprocessor returns failure.
  Trigger: CNetworkGameServerBase_ServiceQueue
disable-model-invocation: true
---

# Find CNetworkGameServerBase_ServiceQueue (final-guarantee fallback)

Recover the concrete `CNetworkGameServerBase_ServiceQueue` function in CS2 `engine2.dll` / `libengine2.so`
using IDA Pro MCP tools. This is an Agent fallback: it runs only when
`ida_preprocessor_scripts/find-CNetworkGameServerBase_ServiceQueue.py` cannot resolve the target.

## Realworld Function References

The finder's LLM_DECOMPILE reference is the predecessor `CNetworkGameServerBase_SpawnGroupThink`, whose
body ends by tail-calling `CNetworkGameServerBase_ServiceQueue`. Read the platform reference before
searching in IDA; its addresses are reference-build values and must be verified against the current binary.

- `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_SpawnGroupThink.windows.yaml`
- `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_SpawnGroupThink.linux.yaml`

## Background — what ServiceQueue is

`CNetworkGameServerBase_SpawnGroupThink(this, spawnGroupQueue)` ends by tail-calling
`CNetworkGameServerBase_ServiceQueue(this, spawnGroupQueue)`. In the reference build the tail call is the
final `jmp sub_XXXX` in the function body:

```
.text:000000000050CD71    jmp sub_50C800   ; CNetworkGameServerBase_ServiceQueue
```

`ServiceQueue` is the routine that actually services the spawn-group queue: it loops with a ~5 ms time step
(`<now> + 0.005`), walks 16-byte queue entries (`shl reg, 4`), and decrements the 16-bit pending-group
counter at queue offset `+0x16`, until the deadline passes or the queue drains. Do not confuse it with its
caller `SpawnGroupThink` — the target is the callee reached by that tail jump.

The reference artifacts are only orientation values (verify every field against the current binary):

| Platform | Reference `func_va` | Reference `func_rva` | Reference size |
|---|---:|---:|---:|
| Windows | `0x1800b6d60` | `0xb6d60` | `0x1fe` |
| Linux | `0x50c800` | `0x50c800` | `0x3d8` |

## Step 0. Skip an existing output

If `CNetworkGameServerBase_ServiceQueue.<platform>.yaml` already exists in the active artifact module
directory and parses to a non-empty mapping, skip that platform. Never derive the artifact path from `bin`.

## Step 1. Load and decompile the predecessor

1. Use SKILL `/get-func-from-yaml` with `func_name=CNetworkGameServerBase_SpawnGroupThink` to obtain its
   `func_va`. If it errors, STOP and report to user — this fallback cannot run without the predecessor.
2. Decompile it (`mcp__ida-pro-mcp__decompile` at that address).
3. Find the **final tail call**: a `jmp sub_XXXX` in the disassembly, or `return sub_XXXX(a1, v4);` in the
   pseudocode, that forwards the server object and the spawn-group queue pointer unchanged. That target is
   `CNetworkGameServerBase_ServiceQueue`.

## Step 2. Confirm the candidate

Decompile the tail-call target and confirm it matches the ServiceQueue shape:

- a `while (1)` loop gated on a timer read (a `sub_XXXX()` returning the current time, compared against a
  stored deadline of `now + 0.005`);
- 16-byte queue-entry walks (`shl reg, 4`) and a decrement of the 16-bit counter at queue offset `+0x16`.

Reject a candidate that is only a wrapper that does not itself contain the queue-servicing loop.

## Step 3. Generate the signature and write YAML

1. Use SKILL `/generate-signature-for-function` with the resolved function address. The signature must be
   generated from the current function body and pass its uniqueness checks.
2. Use SKILL `/write-func-as-yaml` with:
   - `func_name=CNetworkGameServerBase_ServiceQueue`
   - `func_addr=<resolved address>`
   - `func_rva=<resolved address minus image base>`
   - `func_size=<current function size>`
   - `func_sig=<validated signature>`

Write one output per input platform:

- `CNetworkGameServerBase_ServiceQueue.windows.yaml` beside `engine2.dll`
- `CNetworkGameServerBase_ServiceQueue.linux.yaml` beside `libengine2.so`

---
name: find-CNetworkGameServerBase_CreateFakeClient
description: |
  Final-guarantee fallback for the find-CNetworkGameServerBase_CreateFakeClient preprocessor. Recovers
  CNetworkGameServerBase_CreateFakeClient in CS2 engine2.dll / libengine2.so when the string-xref preprocessor
  cannot resolve the function. Use this skill only after the deterministic preprocessor returns failure.
  Trigger: CNetworkGameServerBase_CreateFakeClient
disable-model-invocation: true
---

# Find CNetworkGameServerBase_CreateFakeClient (final-guarantee fallback)

Recover the concrete `CNetworkGameServerBase_CreateFakeClient` function in CS2 `engine2.dll` / `libengine2.so`
using IDA Pro MCP tools. This is an Agent fallback: it runs only when
`ida_preprocessor_scripts/find-CNetworkGameServerBase_CreateFakeClient.py` cannot resolve the target.

## Realworld Function References

The finder has no dedicated predecessor reference YAML. Use these related references for the class and calling
conventions; their addresses and offsets are reference-build values and must be verified against the current
binary.

- `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_Init.windows.yaml`
- `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_Init.linux.yaml`
- `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_ConnectClient.windows.yaml`
- `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_ConnectClient.linux.yaml`

## Semantic fingerprint

`CNetworkGameServerBase_CreateFakeClient` is a member of `CNetworkGameServerBase` that creates and initializes a
fake network client. The deterministic finder anchors it with both exact string references `30000` and `rate`.
Those literals identify the rate initialization in the target or in a small helper it calls; do not identify the
function from either literal alone.

The first argument is the server object (`rcx` on Windows, usually `rdi`/`r12` on Linux). Confirm that the
candidate allocates or initializes a client and that the `30000`/`rate` values belong to that initialization path,
not to an unrelated command or diagnostic routine.

## Step 0. Skip an existing output

If `CNetworkGameServerBase_CreateFakeClient.<platform>.yaml` already exists in the active artifact module
directory and parses to a non-empty mapping, skip that platform. Never derive the artifact path from `bin`.

## Step 1. Locate the target in IDA

1. Search the current binary for the exact string literals `30000` and `rate` (including command-table or format
   string variants), then enumerate their code xrefs.
2. Decompile each function that references both anchors. Prefer the candidate whose first parameter is the
   `CNetworkGameServerBase` object and whose body creates a client, sets its connection/rate state, or calls the
   client initialization helper.
3. If the two strings occur in a helper, follow callers and callees one level in each direction until the
   containing `CNetworkGameServerBase` member is identified. The helper may be inlined or outlined on either
   platform, so use the client-construction and rate-initialization semantics rather than a fixed address.
4. Reject candidates that only register a console command, format a message, or initialize an unrelated rate.

The reference artifacts for build 14167 are only orientation values (verify every field against the current
binary):

| Platform | Reference `func_va` | Reference `func_rva` | Reference size |
|---|---:|---:|---:|
| Windows | `0x1800af840` | `0xaf840` | `0x24d` |
| Linux | `0x6968d0` | `0x6968d0` | `0x2b8` |

## Step 2. Generate the signature and write YAML

After confirming the candidate:

1. Use SKILL `/generate-signature-for-function` with the resolved function address. The signature must be
   generated from the current function body and pass its uniqueness checks.
2. Use SKILL `/write-func-as-yaml` with:
   - `func_name=CNetworkGameServerBase_CreateFakeClient`
   - `func_addr=<resolved address>`
   - `func_rva=<resolved address minus image base>`
   - `func_size=<current function size>`
   - `func_sig=<validated signature>`

Write one output per input platform:

- `CNetworkGameServerBase_CreateFakeClient.windows.yaml` beside `engine2.dll`
- `CNetworkGameServerBase_CreateFakeClient.linux.yaml` beside `libengine2.so`

## Failure handling

- If no candidate references both semantic anchors, inspect nearby callers/callees and decompiled client creation
  helpers before stopping.
- If the candidate cannot be distinguished from an unrelated rate-setting routine, stop and report the ambiguity;
  do not guess from the 14167 values.
- Never emit a Windows result while analyzing Linux or vice versa.

---
name: find-CServerSideClientBase_GetUserIDString
description: |
  Final-guarantee fallback for CServerSideClientBase_GetUserIDString when its deterministic string-xref
  preprocessor cannot resolve the function. Locate the concrete user-ID formatting helper in engine2.dll /
  libengine2.so and write the semantic artifact for the active platform.
  Trigger: CServerSideClientBase_GetUserIDString
disable-model-invocation: true
---

# Find CServerSideClientBase_GetUserIDString (Agent fallback)

Use this fallback only after `ida_preprocessor_scripts/find-CServerSideClientBase_GetUserIDString.py` fails.
The target is the `CServerSideClientBase` member that returns/formats a client's user-ID string; it is not the
nearby network-ID helper, HLTV/replay formatter, or a console command.

## Step 0. Skip an existing output

If `CServerSideClientBase_GetUserIDString.<platform>.yaml` already exists as a non-empty mapping in the active
artifact module directory, skip it. Never derive the artifact path from `bin` or write into checkout expected
artifacts while analyzing.

## Step 1. Locate the target in IDA

Search the current binary for exact string literals matching the user-ID fallback values:

- `STEAM_ID_LAN`
- `STEAM_ID_PENDING`
- `HLTV`
- `REPLAY`
- `UNKNOWN`

Enumerate code xrefs and decompile candidate functions. Prefer the function whose first argument is the
`CServerSideClientBase` object (`rcx` on Windows, normally `rdi` on Linux) and which returns or writes the
formatted user ID. The deterministic finder intentionally excludes unrelated matches such as `%.3f min`,
`for %.2f minutes`, `removeid:  couldn't find %s`, `FULLMATCH:%s %s`, and `banid 0 %s`.

Confirm the candidate's semantics: it reads the client's identity/auth state, selects a fallback such as
`STEAM_ID_LAN`, `STEAM_ID_PENDING`, `HLTV`, `REPLAY`, or `UNKNOWN`, and returns the resulting string (or a
pointer to it). Reject functions that only produce the network ID, register a command, or log a diagnostic.
The old build-14167 values are orientation only; do not copy an address without checking the current binary.

## Step 2. Generate and write the artifact

Rename the verified function with IDA MCP. Use `/generate-signature-for-function` to generate a unique
signature from the current function body, then use `/write-func-as-yaml` with:

- `func_name=CServerSideClientBase_GetUserIDString`
- verified current `func_addr`
- `func_rva` relative to the current image base
- current `func_size`
- validated `func_sig`

Write only the active platform output:

- `CServerSideClientBase_GetUserIDString.windows.yaml` beside `engine2.dll`
- `CServerSideClientBase_GetUserIDString.linux.yaml` beside `libengine2.so`

The trusted analyzer performs final canonical serialization; this skill supplies semantic fields only.

## Failure handling

- If no candidate combines the identity fallbacks with `CServerSideClientBase` receiver semantics, stop and
  report the ambiguity rather than guessing from reference addresses.
- Never emit a Windows result while analyzing Linux, or vice versa.
- If the output cannot be uniquely signed, retain only fields accepted by the analyzer's schema and report why
  the signature was omitted; do not invent a signature.

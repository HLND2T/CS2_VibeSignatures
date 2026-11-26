---
name: find-CGlobalVarsBase_realtime-AND-CGlobalVarsBase_curtime
description: Recover the Windows engine clock fields from minidump comment formatting.
disable-model-invocation: true
---

# Find CGlobalVarsBase.realtime and CGlobalVarsBase.curtime

1. Open the current `engine2.dll` IDB with IDA Pro MCP. Find the exact format string `Curtime( %f )\nRealtime( %f )\n` and follow its code xref to the call to `CMiniDumpComment::AppendFormattedComment`.
2. Trace the two varargs through their float-to-double conversions to the reads from the same globals pointer. The format argument order is curtime, then realtime. In 14201, the loads are `movss xmm3, dword ptr [rsi]` at `0x18020C214` for realtime and `movss xmm2, dword ptr [rsi+30h]` at `0x18020C21B` for curtime.
3. Confirm both accesses and use `/write-structoffset-as-yaml` to write `CGlobalVarsBase_realtime.windows.yaml` and `CGlobalVarsBase_curtime.windows.yaml` under `CS2VIBE_ARTIFACT_DIR`. Use `CGlobalVarsBase` as the struct, the respective member names, and the decoded byte widths. Use `/generate-signature-for-structoffset` for an explicit displacement. For an implicit zero displacement, emit the offset and width with no signature fields.

If multiple candidates survive or either argument cannot be traced, report the xrefs and unresolved fields.

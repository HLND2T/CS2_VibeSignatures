---
name: find-NetMessageInfo_t_m_pfnAllocate-AND-NetMessageInfo_t_m_MessageId
description: Recover the Windows networksystem allocator callback and message ID from descriptor registration.
disable-model-invocation: true
---

# Find NetMessageInfo_t.m_pfnAllocate and NetMessageInfo_t.m_MessageId

1. Open the current `networksystem.dll` IDB with IDA Pro MCP. Read `func_va` from `CNetworkMessages_FindOrCreateNetMessage.windows.yaml` in the analyzer's active artifact directory (`CS2VIBE_ARTIFACT_DIR`).
2. Identify the branch that allocates and initializes a new message descriptor. Trace the incoming allocator callback to the pointer store in that descriptor. In 14201 the incoming callback in `r8` is saved to its stack slot and reloaded for the write at `0x1800E51A8`.
3. Follow the effective message ID through registration and confirm the dword store on the same descriptor. In 14201 the store at `0x1800E52DD` uses the same ID passed to the registration helper.
4. Use `/generate-signature-for-structoffset` on each verified store and check for a unique match. Use `/write-structoffset-as-yaml` to write `NetMessageInfo_t_m_pfnAllocate.windows.yaml` and `NetMessageInfo_t_m_MessageId.windows.yaml` under the active artifact directory with the decoded offsets and widths.

If the prerequisite or either data-flow path is unresolved, report the path and candidate sites before writing any output.

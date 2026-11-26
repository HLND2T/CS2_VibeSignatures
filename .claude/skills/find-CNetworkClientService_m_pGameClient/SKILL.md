---
name: find-CNetworkClientService_m_pGameClient
description: Recover the Windows engine game-client pointer from the network client service's active-state check.
disable-model-invocation: true
---

# Find CNetworkClientService.m_pGameClient

1. Open the current `engine2.dll` IDB with IDA Pro MCP. Read `func_va` from `CNetworkClientService_IsActive.windows.yaml` in the analyzer's active artifact directory (`CS2VIBE_ARTIFACT_DIR`).
2. Follow the pointer load from the service's `this` argument through the null check and the connection-state comparison. Use the displacement of the first load, before the dereference of the game-client state. In 14201 the load is `mov rax, [rcx+0A0h]` at `0x1801D4900`. The non-null branch compares `[rax+230h]` against 6.
3. Use `/generate-signature-for-structoffset` on the pointer load and check for a unique match. The similarly shaped `IsConnected` can make the signature ambiguous within the function. Extend forward across the function boundary when needed and set `offset_sig_allow_across_function_boundary: true`. Use `/write-structoffset-as-yaml` to write `CNetworkClientService_m_pGameClient.windows.yaml` in the active artifact directory with `struct_name: CNetworkClientService`, `member_name: m_pGameClient`, the decoded offset, and the pointer load width.

If the prerequisite is missing or the pointer cannot be identified uniquely, report the path or candidate sites and leave the output unresolved.

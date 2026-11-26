---
name: find-CEntitySystem_m_EntityList-AND-CEntityIdentity_m_pInstance-AND-CEntityIdentity_m_EHandle
description: Recover the Windows client entity list and identity layout from chunk allocation and initialization.
disable-model-invocation: true
---

# Find the client entity list and identity fields

1. Open the current `client.dll` IDB with IDA Pro MCP. Read `func_va` from `CEntitySystem_ctor.windows.yaml` in the active client artifact directory (`CS2VIBE_ARTIFACT_DIR`).
2. Follow both constructor calls that pass the same embedded list address to the chunk allocator. The callee references the diagnostic beginning `ConcreteEntityList:  approaching limit, allocating entity chu` and allocates and initializes a chunk of identities. Use the constructor's `lea` displacement for `CEntitySystem.m_EntityList`. In 14201, the call at `0x1815AE2ED` uses the address formed at `0x1815AE2E9`.
3. In the callee, locate the per-identity loop. Identify the dword initialized to the invalid handle value and corroborate it with the later handle-index initialization. Identify the pointer slot cleared immediately before initializing the embedded field at the call. In 14201 the corresponding writes are at `0x1815B1190` (Handle) and `0x1815B11DE` (instance).
4. Confirm all three offsets and write `CEntitySystem_m_EntityList.windows.yaml`, `CEntityIdentity_m_pInstance.windows.yaml`, and `CEntityIdentity_m_EHandle.windows.yaml` in the active client artifact directory. Use `/generate-signature-for-structoffset` for explicit displacements and `/write-structoffset-as-yaml` for all three outputs. Omit `size` for the embedded-list address calculation. For an implicit zero displacement, emit the offset and width with no signature fields.

If the allocation path or field writes remain ambiguous, report the candidate addresses and unresolved outputs.

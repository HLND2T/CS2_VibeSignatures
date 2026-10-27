# C++ ABI reference validation

`run_cpp_tests.py` compares compiler layouts with an explicit immutable snapshot
built from `bin_artifacts/<GAMEVER>`. A name mismatch is evidence to investigate,
not proof that an SDK declaration has the wrong slot or signature.

## Interface and implementation tables

Concrete implementations can append virtual functions beyond the public
interface. Do not copy their full table length into the SDK interface or reduce
the concrete artifact's `vtable_size`, `vtable_numvfunc`, or `vtable_entries` to
make an interface test pass.

For a verified interface boundary, a `cpp_tests` entry can specify
`interface_vtable_numvfunc: <positive integer>`. The boundary must come from the
matching binary interface table, independently of the SDK/compiler output.
The comparator then:

- Requires a complete compiler layout with exactly that entry count and byte size.
- Preserves the concrete reference size and count in the report, requires both,
  checks their consistency, and rejects a concrete table shorter than the interface.
- Keeps reference ownership, module conflicts, known function names, and indices
  checked exactly. Out-of-range function references still fail.
- Rejects combining the boundary with `allow_vtable_size_mismatch`.

Without this option, the existing exact size/count comparison is unchanged.
The option requires `fdump-vtable-layouts`; zero, negative, boolean, fractional,
or string boundaries are invalid test definitions.

## 14192 corrections

The same convention applies to three `CServerSideClientBase` vfuncs. Only the
human-readable `func_name` changed; artifact paths, addresses, signatures, and
slots are unchanged, and the finders declare `OUTPUT_NAME_MAP` so regeneration
keeps the corrected names.

| Legacy key | Corrected `func_name` | Evidence in 14192 |
|---|---|---|
| `CServerSideClientBase_GetPlayerInfo` | `CServerSideClientBase_Create` | Windows `0x1800cbee0` / Linux `0x5427b0`, slot 9: clears the client, applies the SteamID and name without connecting, creates the `userinfo` `KeyValues`, sets signon to `SIGNONSTATE_CONNECTED`, and returns its slot. The real `GetPlayerInfo` is the sibling `return this + 400` accessor at slot 54. |
| `CServerSideClientBase_ProcessChangeSplitscreenUser` | `CServerSideClientBase_ProcessSplitscreenUserChanged` | Windows `0x1800cc620` / Linux `0x543530`, slot 43/45: reports `Unable to set SetActiveChannel to user in slot %d`; the SDK spells the same function `ProcessSplitscreenUserChanged`. |
| `CServerSideClientBase_SendServerInfo` | unchanged | Windows `0x1800c7030` / Linux `0x5497d0`, slot 48/52: serializes `SV_SendServerinfo->msg` and the `BuildServerInfoMessageAsync_t` message chain, so the artifact name is already correct. |

The `CServerSideClientBase_SendServerInfo` slot depends on overload placement:
the SDK deliberately gives the spawn-group collector and the server-info sender
the same name, because both compilers then emit the pair before
`SendInitialSpawnGroups`, matching the engine. Renaming only one of them moves the
server-info slot from 48 to 50 on MSVC, so the shared name is part of the ABI, not
a naming shortcut.

The client engine interface needed the same treatment once `cpp_tests` began
comparing it against `CEngineClient_vtable` through `IVEngineClient2`. Four slots
carried labels that do not match their bodies, and one Linux slot was resolved from
a sibling thunk:

| Legacy key | Corrected `func_name` | Evidence in 14192 |
|---|---|---|
| `CEngineClient_ExecuteClientCmd` / `IVEngineClient2_ExecuteClientCmd` | `CEngineClient_ServerCmd` / `IVEngineClient2_ServerCmd` | Windows `0x180075d30` / Linux `0x5096d0`, slot 50: clamps the split-screen slot to 0..3 and dispatches to the network client's `SendStringCmd`, i.e. `ServerCmd( CSplitScreenSlot, const char * )`. |
| `CEngineClient_ClientCmd_Unrestricted` | `CEngineClient_ClientCommand` | Windows `0x180075d60`, slot 51: takes the `( slot, cmd, bool, double, uint64 )` signature, tests the input time with `V_isnand`, wraps a non-NAN time in `__beginseq`/`__endseq`, and sends the `"%s\n"` text — the SDK's `ClientCommand`. |
| `CEngineClient_DumpNetStats` | `CEngineClient_PrintNetworkSummaryReport` | Windows `0x180075ca0` / Linux `0x507640`, slot 184: no arguments, 0x11 bytes, delegates to `CNetworkGameClient_PrintNetStats`. The real `DumpNetStats( void *, void ( * )( const char * ) )` sits at slot 29. |
| `IVEngineClient2_GetNetworkClient` | `IVEngineClient2_GetNetChannel` | Windows `0x180076530`, slot 41: indexes the per-split-screen channel array at `netclient + 24 * slot + 240`; the caller in `SendViolationReport` uses the result as a net channel. |

The Linux `CEngineClient_ServerCmd` slot was recorded as index 101
(`0x506eb0`) because the finder matched a byte signature against a sibling
forwarder. Both ABIs keep this override at the inherited slot 50, and the client
artifact already said 50, so the Linux entry now points at slot 50 (`0x5096d0`).
The Linux-only signature branch was removed; the shared inherit path resolves both
platforms.

### SendStringCmd finder replay (2026-10-27)

Correcting the Linux ServerCmd anchor exposed a downstream assumption in
`find-INetworkGameClient_SendStringCmd`: slot 50 at `0x5096d0` tail-jumps directly
to the helper at `0x4d47a0`, rather than dispatching virtually in its own body.
The helper loads slot `0x130` and performs a guarded `jmp rax` at `0x4d4914`.
The finder now opts into following one unique external direct tail jump when its
initial virtual-call scan is empty. Only tail dispatches in the helper are
scanned; missing or ambiguous targets still fail without writing an artifact.

Real Windows/Linux IDB replay regenerated all 10 nodes in the required dependency
chain: the engine vtable, client FireGameEvent anchor, IVEngineClient2 slot,
CEngineClient override, and INetworkGameClient slot on each platform. Both final
artifacts retain offset `0x130`, index 38; there are no downstream finder consumers
in the 14192 config. Source artifact bytes were unchanged. A candidate composed
from the replay passed the 4073-artifact contract and both native C++ ABI gates:
28 layout comparisons per platform, including 26 vtable comparisons, all with
zero differences. Python unit tests ran 1542 cases (18 skipped), and all 124
repository-contract tests passed. Regression coverage includes ambiguous/missing
tail targets and virtual slots, failed source scans, and Windows direct dispatch.

## 14191b corrections

SDK source: `HLND2T/s2sdk`, commit
`a54d726d1693ffffe59f101f480d6d76c79a7fc6`. The SDK was not modified.
The prior `HLND2T/hl2sdk` `cs2_vibe` branch was also inspected at
`81e4e3b8f271e9412a93b9d3e2277c02332e2f6c`.

The corrections retain legacy artifact paths used by configured producers,
dependencies, and gamedata lookups. Only the human-readable `func_name` or
`member_name` is corrected. Consumers must keep artifact identity (the SymbolStore
entry path) separate from the function's analyzed name. Regeneration of these
legacy keys must preserve the verified names rather than derive semantics solely
from the filename. Addresses, signatures, offsets, slots, binary locks, and full
concrete table contents remain unchanged. Earlier GAMEVER artifacts are unchanged.

The corresponding finders declare `OUTPUT_NAME_MAP` and pass it to
`preprocess_common_skill` (or the IGameSystem dispatch helper). Mapping keys stay
in output paths, dependency lookups, and LLM response identifiers; mapping values
are emitted as `func_name` or as the member part of `struct_name_member_name`.
The mapping applies after both signature reuse and fresh analysis, including
inherited slots. Existing outputs with stale semantic names are regenerated.
Function renames in IDA also use the semantic name. Agent fallback writers accept
`artifact_name` separately and must honor the same finder mapping. Historical
LLM reference labels remain compatibility identifiers for matching call sites.

### Interface boundary evidence

Linux addresses below are relative to image base zero. The address point follows
the Itanium table's offset-to-top and RTTI entries.

| Interface | Binary interface table | Address point | Interface count | Concrete count |
|---|---|---|---:|---:|
| `ISource2Server` | `_ZTV15CTier2AppSystemI14ISource2ServerLx0EE` at `0x2667760` | `0x2667770` | 103 | 104 |
| `INetworkServerService` | `_ZTV15CTier2AppSystemI21INetworkServerServiceLx0EE` at `0x9bef80` | `0x9bef90` | 52 | 53 |

For the first interface, slot 102 is pure virtual and the next word starts a new
RTTI group. The concrete `CSource2Server` table at `0x26682a8` has an additional
slot 103 before the secondary table's offset-to-top `-40`.
For the second, slot 51 is pure virtual; the concrete table at `0x9c2640` adds
slot 52 (`0x417480`) before the secondary table's offset-to-top `-56`.
The corresponding Windows interface boundaries are 103 and 51 entries.

### Function and member evidence

Names below are canonical SDK spellings of the verified function behavior.
An IDB's existing manually assigned name alone is not independent evidence.

| Legacy label | Correct label | Evidence in 14191b |
|---|---|---|
| `IsUserIDInUse` | `GetEntityTransmitBitsForClient` | engine Linux `0x529210`, Windows `0x1800a1ce0`: client-slot lookup returning a frame bitset pointer or null |
| `SetFinalSimulationTickThisFrame` | `GetServerNetworkAddress` | engine Linux `0x4098d0`, Windows `0x1801e3ca0`: constructs/returns `netadr_t`, including Windows hidden result buffer |
| `SetGameLoadStarted` | `FinishChangeLevel` | engine Linux `0x40f860`, Windows `0x1801e3d70`: completes and frees changelevel state, returns true |
| `GetServerSerializersCRC` | `GetServerSerializersMsg` | engine Linux `0x413b00`, Windows `0x1801e43d0`: returns the locked object's message pointer; actual Linux CRC computation is the preceding function at `0x413690` |
| `UnloadSpawnGroup` at slot 60 | `LoadSpawnGroup` | engine Linux `0x527380` forwards to game-server slot 19 (load); slot 59 at `0x5273d0` instead forwards to slot 20 (async unload) |
| `PreWorldUpdate` at game-server slot 59 | `PrepareSendClientUpdatesMainThread` | engine implementation `0x5217d0` has this exact profiler scope string and `networkgameserver.cpp` source filename; call site `0x414856` prepares client updates after advancing the tick |
| `ServerSimulate` | `ServerBeginSimulate` | engine RTTI contains `CNetworkGameServerBase::ServerBeginSimulate(EventServerBeginSimulate_t const&)` in the queued job type |
| `OnServerPreBeginAsyncPostTickWork` / `OnServerBeginAsyncPostTickWork` | `OnServerBeginAsyncPostTickWork` / `OnServerGameBeginAsyncPostTickWork` | server RTTI contains the exact event and handler names; `CLoopModeGame` at `0x1791860` consumes the bool payload and dispatches both slots |
| `PrintNetworkStats` | `SetTime` | networksystem `0x2dc330`: consumes double time, computes delta, updates time state |
| `GetUDPPort` at slot 35 | `GetUDPPortWithFallback` | networksystem `0x2d2f40`: sequential fallback across several port fields; slot 34 is the separate bound-port accessor |
| `EnableLoopbackBetweenSockets` | `ConnectLoopback` | networksystem `0x2e9b00`: connects two socket slots, including `Can't ConnectLoopback between socket ...` diagnostic |
| `InitNetworkSystem` | `InitSteamNetworking` | networksystem `0x2ea000`: SteamNetworking context and SDR initialization |
| `AddChangeAccessorPathPolymorphic` | `NetworkStateChangedBranch` | server slot 30 forwards through `0xa357a0` to `0xa79260`, which logs `CNetworkTransmitComponent::StateChangedBranch(...)` |
| `AssignChangeAccessorPathIdsPolymorphic` | `NetworkStateChangedRemove` | server slot 31 forwards through `0xa35190` to `0xa94700`, removing recorded changes and logging `removed change` / `removed ... offsets from array` |
| `PostDataUpdateDelta` / `PostDataUpdatePreserve` | `DispatchPostDataUpdate` / `OnDataUnchangedInPVS` | server `0x22826f0` dispatches to the latter handler (`0x2282530`), whose implementation sets the PVS data-update state flag |
| `BroadcastServerFrameTime` | `SendServerFrameTime` | server `0x19922a0` builds and sends the server-frame-time user message |
| `GetEntityReport` on `CSource2Server` | `FormatSerializerFieldValue` | server `0x19a7a30` formats serializer-field values into the supplied output field |
| `Save` on `CSource2Server` | `SaveGame` | server `0x1990f70` delegates to the entity save/restore interface |
| `SendMessages` | `TransmitUpToCheckpoint` | networksystem `0x291cd0` sends using checkpoint boundaries through `0x290c10`; slot 43 saves current boundaries and normal Transmit (`0x29d1e0`) refreshes them before using the same helper |
| `ParseMessagesDemo` | `ProcessDemoPacket` | networksystem `0x29b010` reads a packet structure and forwards its payload/metadata to demo parsing |
| `m_bEnableAutoDeletionExecution` | `m_bAutoExecuteQueuedDeletion` | server setter `0x22c3450` writes `this + 3171` (`0xc63`), matching both compiler layouts |

## Verification

Build a new candidate after metadata corrections; do not reuse the pre-correction
snapshot or mutate an existing candidate. Run the actual `run_cpp_tests.py` with
`--platform windows` using the native Windows compiler and `--platform linux`
using a native Linux compiler (WSL is supported), the same candidate, and the
same config. Keep debug logs and result JSON outside the source artifact tree.
The checks validate configured slot/name and member-offset evidence; they do not
establish every C++ function prototype or unreferenced member's ABI.

Regression tests in `tests/test_run_cpp_tests.py` cover exact/default comparisons,
verified interface boundaries, changed compiler counts, shifted known slots,
incomplete/inconsistent reference metadata, invalid definitions, and prohibition
of disabling size checks with an interface boundary.

### Generator replay (2026-10-22)

All 31 affected finder scripts now declare the semantic-name mappings. Replaying
the actual 14191b Windows/Linux IDBs into a temporary artifact root regenerated
all 61 corrected artifacts with matching names, addresses, slots, and offsets:
57 previous-metadata reuse executions and 32 fresh deterministic executions
succeeded. Two additional fresh inlined CNetChan attempts were not applicable:
these binaries retain the standalone helper, and both paired noinline finders
succeeded. Fresh LLM transport was not invoked; regression tests cover that
fallback's identifier/name separation with mocked LLM responses.

A new candidate built from the regenerated artifact root contains 4037 artifacts,
SHA-256 `1703d06d36004306a721c35dc30a73aaf385e7df57ac8b46c775671b267ceb1b`.
Both native Windows and WSL Linux runs passed all 21 configured C++ tests and
22 layout comparisons without differences or skips. Python regression ran
1811 tests: 1743 passed, 68 skipped, zero failures/errors. Formatting, Ruff,
strict artifact validation using a temporary Git index, and candidate guard
also passed. Repository artifact addresses/signatures were not replaced with
the replay's regenerated signatures; the checked-in corrections remain names only.

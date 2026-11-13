# IDA validation failures — 14197

## find-CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract  (module: networksystem, platform: windows/linux)

Failure (from `ida_analyze_bin.py -debug`):

    Start skill: find-CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract
      Preprocess: 0x1800e5a70 not in CNetworkMessages vtable entries
      Preprocess: trying func_xrefs fallback for CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract
      Preprocess: empty candidate set for string xref: CNetworkMessages::AllocateAndCopyConstructNetMessageAbstract unable to allocate
      Preprocess: failed to locate CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract
    Preprocess failed: find-CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract; falling back to AGENT SKILL
    Processing skill: find-CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract
      Falling back to: .claude\skills\find-CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract\SKILL.md
      Error: Skill file not found: .claude\skills\find-CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract\SKILL.md
      Failed

Diagnosis:

The target symbol no longer exists in 14197; this is not a locator regression.

1. The old func_sig `48 83 EC ?? 48 85 D2 75 ?? 8B 0D ?? ?? ?? ??` still matches exactly one
   function in 14197 (`0x1800e5a70`), but that function is
   `CNetworkMessages::AssociateNetMessageWithAllChannelCategories` — a decoy. It is not in the
   `CNetworkMessages` vtable, so the preprocessor correctly rejected it and fell through to the
   string-xref path.
2. The string-xref anchor `CNetworkMessages::AllocateAndCopyConstructNetMessageAbstract unable to
   allocate unknown message type!` is absent from the whole 14197 build. A full scan of every file
   under `cs2_depot/14197/` for `AllocateAndCopyConstructNetMessageAbstract`,
   `DeallocateUnserializedMessage`, and the message text returns zero hits.

Structural evidence that the virtual slot was removed rather than relocated:

- `??_7CNetworkMessages@@6B@` moved from `0x180239a48` to `0x180233a98`, and `vtable_size` shrank
  from `0x138` (39 slots) to `0x120` (36 slots). All subsequent `CNetworkMessages` slots shifted
  by -3.
- Slot 8 in 14196 was the allocation entry (`0x1800e2aa0`, with its
  `... unable to allocate unknown message type!` log line). Slot 8 in 14197 is now
  `sub_1800E4F20` (15 bytes):
  `result = &qword_18029F098; if (a2) return a2; return result;` — a trivial
  "use the supplied object, else fall back to a default" helper with no allocation and no logging.
  Its `f2 48 85 d2` + `mov rax,[rdx]; mov rcx,rdx; call [rax+20h]` body is gone.
- The matching deallocation entry is also gone: 14196 slot 9 (`0x1800e2af0`, log line
  `CNetworkMessages::DeallocateUnserializedMessage unable to deallocate unknown message type!`) has
  no counterpart in 14197, and slot 9 there is an unrelated 428-byte string-scanning helper.
- The neighboring serializers were also removed in 14197: `RegisterNetworkFieldSerializer`
  (14196 slot 10), `RegisterNetworkArrayFieldSerializer` (slot 11),
  `RegisterNetworkFieldChangeCallbackInternal` (slot 24), `RegisterFieldChangeCallbackPriority`
  (slot 29), and `ComputeOrderForPriority` (slot 34) all lost their
  `CNetworkMessages::<name>` debug strings. `Serialize` also moved (14196 slot 3 →
  14197 slot 2), so the whole block of message-allocation/registration virtuals was reworked.

Note that `s2sdk/public/networksystem/inetworkmessages.h` still declares
`AllocateAndCopyConstructNetMessageAbstract` and `DeallocateNetMessageAbstract` at vtable offsets
`0x40`/`0x48`; that header is out of date for 14197 and will need a separate s2sdk update. The
`CNetworkMessages_vtable` YAML itself generated correctly (36 slots), so this is a genuine binary
change, not a preprocessor defect.

Decision: user chose to temporarily disable this skill because it could not be resolved now.

## Quarantine summary — linux validation run (Failed: 0)

Server-side quarantine applied to `configs/14197.yaml` for the linux platform run. After the
quarantines below, `uv run ida_analyze_bin.py -gamever 14197 -configyaml configs/14197.yaml
-platform linux -debug` reports **Successful: 60, Failed: 0, Skipped: 1446**. The windows platform
is out of scope for this run.

### 1. CNetworkMessages interface vtable rework (39 -> 36 slots)

`??_7CNetworkMessages@@6B@` shrank from 39 to 36 slots and every slot after the removed block moved
by -3. These virtuals lost their debug strings and were removed from the interface entirely:

| Skill | 14196 slot | Note |
|---|---|---|
| find-CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract | 8 | replaced by a trivial 15-byte helper |
| find-CNetworkMessages_DeallocateNetMessageAbstract | 9 | removed |
| find-CNetworkMessages_RegisterNetworkFieldSerializer | 10 | moved to `NetSerializers_RegisterNetworkFieldSerializer` (free function, not in vtable) |
| find-CNetworkMessages_RegisterNetworkArrayFieldSerializer | 11 | moved to `NetSerializers_RegisterNetworkArrayFieldSerializer` (free function) |
| find-CNetworkMessages_RegisterNetworkFieldChangeCallbackInternal | 24 | moved to `NetSerializers_RegisterNetworkFieldChangeCallback` (free function) |
| find-CNetworkMessages_RegisterFieldChangeCallbackPriority | 29 | moved to `NetSerializers_RegisterFieldChangeCallbackPriority` (free function) |
| find-CNetworkMessages_ComputeOrderForPriority | 34 | moved to `NetSerializers_ComputeOrderForPriority` (free function) |

All six `NetSerializers_*` functions live in `networkserializerregistry.cpp` (verified by their
`C:\buildworker\...\networkmessages.cpp` / `networkserializerregistry.cpp` assert paths and by
`NetSerializers_<name>` assert strings). They are reachable, but the current finders require
`FUNC_VTABLE_RELATIONS = (..., "CNetworkMessages")`, which can never match a free function.

Also quarantined downstream because their producer no longer exists:
- find-CNetworkMessages_vtable-decompiles (needs RegisterNetworkFieldChangeCallbackInternal)
- find-CNetworkMessages_FindOrCreateNetMessage — the anchor string
  `CNetworkMessages::FindOrCreateNetMessage: Message %s is expected to have already been registered!`
  is absent from the whole 14197 build.

Repair: change these finders to locate the `NetSerializers_*` free functions by their new assert
strings, drop the `CNetworkMessages` vtable relation, and update the generated YAML to `category: func`.

### 2. CNetworkMessages_FindNetworkMessage (locator drift, symbol still present)

The function still exists at vtable slot 9 (`0x1800e52d0`, 428 bytes, uses `V_stricmp_fast`, twin of
slot 10 `V_stristr_fast`). The 14196 func_sig fails only because the prologue changed from
`push rsi` (`56 ...`) to `push rdi` (`57 ...`); the two `41 ?? FF FF 00 00` / `41 ?? FF 7F 00 00`
signature anchors now collide with 16 and 1 candidate respectively.

Repair: regenerate the func_sig from the current prologue, or pin the finder to `CNetworkMessages`
slot 9 (the Partial finder already resolves slot 10 successfully).

### 3. CNetworkSystem_SendNetworkStats (locator drift)

`Stack depth limit hit (%d)` still exists in 14197, but the `E0 00 00 00 04` signature anchor
matches nothing. Note that 14197 slot 25 (`0x180100810`, windows) is now
`CNetworkSystem_SetTime`, so the old slot layout must not be trusted.

Downstream quarantined: find-CNetworkSystem_SendNetworkStats-decompiles.

Repair: replace the stale signature anchor with a current one and re-derive the vtable slot.

### 4. CGameEventSystem_PostEventAbstract2 (ambiguous anchors)

The anchor `GameEvent:  Posting %s (id:%d group:'%s') from code` now has three owners in 14197:
`0x380fd0`, `0x3811e0` and `0x3814e0`, and two of them are `CGameEventSystem` vtable entries
(slots 15 and 17), so the xref intersection returns 2 candidates instead of 1.

Slot 15 (`0x3811e0`) is the correct `PostEventAbstract2`; slot 17 (`0x3814e0`) is
`PostEntityEventAbstract`. Repair: add an exclude for the sibling or disambiguate by call shape.

Downstream quarantined: find-IGameEventSystem_PostEventAbstract_Local and
find-CGameEventSystem_PostEventAbstract_Local (both consume the removed artifact).

### 5. CNetworkStringTableClient_ParseUpdate (symbol removed)

The anchor `CNetworkStringTableClient::ParseUpdate: message too large` and the whole
`CNetworkStringTableClient` name are absent from the 14197 `libengine2.so`, and the old func_sig
matches nothing. The function was removed or fully reworked.

Downstream quarantined: find-INetworkSystem_BufferToBufferDecompress and
find-CNetworkSystem_BufferToBufferDecompress.

### 6. INetworkMessages_FindNetworkMessageById (vfunc moved)

Present in 14197, but the vfunc offset moved from `0xf0` (index 30) to `0xd8` (index 27). The
`vfunc_sig FF 90 F0 00 00 00 48 8B 95 ...` therefore matches nothing, and the LLM-decompile
fallback returns an empty `found_vcall`, so the skill fails deterministically rather than flakily.
Evidence: the only `call [rax+0d8h]` followed by `mov rdx,[rbp-0a0h]` is inside `sub_4644C0` at
`0x464617`.

Repair: update the reference/vfunc offset to `0xd8` after the surrounding offsets are re-derived
from a full `INetworkMessages` re-analysis.

### 7. CNetworkSystem_RemoveNetChannel (linux anchor removed)

The `FULLMATCH:shutdown` anchor string is absent from the 14197 `libnetworksystem.so` (14196 had
one occurrence). The function may still exist at a different slot, but the configured anchors cannot
resolve it.

Downstream quarantined: find-CNetworkSystem_RemoveNetChannelByAddress.

### 8. Infrastructure: first-time analysis of very large binaries

Not a skill bug. `libclient.so` (74 MB) and `libserver.so` (42 MB) need far longer than the old
60-second `OPENED_BINARY_VERIFY_TIMEOUT` for their first full auto-analysis, so
`verify_opened_binary_via_mcp` reported `opened binary verification failed` and aborted 114 pending
items on `libclient.so`. Two changes were made:

- `OPENED_BINARY_VERIFY_TIMEOUT` 60s -> 1800s, retry interval 2s -> 5s.
- `McpConnectionError` (the "server is up but the session is not ready" case) is now retried inside
  that window instead of failing immediately.

Both large IDBs were also pre-warmed once (`libclient.so.i64`, `libserver.so.i64`) so subsequent
runs start from a cached database. New tests cover the retry and the give-up path.

### Remaining work

Every quarantine above is a real config/finder gap, not a flake. The expected repair is a finder
update plus a fresh artifact for each symbol; re-enabling a skill is a separate manual step.

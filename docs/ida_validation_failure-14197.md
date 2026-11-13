# IDA validation failures — 14197

The original quarantine evidence is retained below. All issue #1238 finder quarantines have
now been restored, except the two removed allocation/deallocation APIs retired with user
approval. The repair sections correct the original serializer and ParseUpdate removal
diagnoses and record fresh binary evidence. See the final verification section for run scope.

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

### Original quarantine status

The sections above record the original quarantine run. Repairs, corrected diagnoses, retired
APIs, and re-enabled finders are recorded below.

## Repair progress

### CNetworkMessages_FindOrCreateNetMessage — resolved on linux and windows

The function still exists in 14197. Its old diagnostic disappeared, but
`CNetworkMessages::FindOrCreateNetMessage: It is illegal to register new net messages after serialization!`
has exactly one owning function on each platform. The 14197-only preprocessor uses that diagnostic
and retains the `CNetworkMessages` vtable membership check; earlier game-version finders are unchanged.

The config now enables `find-CNetworkMessages_FindOrCreateNetMessage-14197`. Fresh source artifacts:

| Platform | Function VA | Vtable index | Vfunc offset |
|---|---|---|---|
| linux | `0x2bb280` | 20 | `0xa0` |
| windows | `0x1800e4f30` | 20 | `0xa0` |

Both addresses and slots were derived by the finder, not hardcoded in it. The isolated validation
root initially contained only the two required vtable YAML files; neither target YAML existed.
The run disabled old-version reuse and generated unique signatures from the current binaries:

```text
uv run ida_analyze_bin.py -gamever 14197 -configyaml configs/14197.yaml -platform linux,windows -modules networksystem -skill find-CNetworkMessages_FindOrCreateNetMessage-14197 -bindir <temporary-binary-root> -artifactdir <isolated-artifact-root> -oldartifactdir bin_artifacts -oldgamever none -require_warm_idb -debug
Successful: 2   Failed: 0   Skipped: 0
```

Validation used copies of the binaries and their pre-existing `.i64` databases. The original
binary workspace retained unpacked IDB files, so it was not used for this run.

After incorporating the generated artifacts, `unit` passed 1563 tests (18 skipped) and
`repository-contract` passed 124 tests. `git diff --check` also passed. This is targeted validation
of the restored finder; the remaining quarantined finders have not been re-enabled.

### AllocateAndCopyConstructNetMessageAbstract / DeallocateNetMessageAbstract — retired in 14197

Both methods were removed from `INetworkMessages` in 14197. The updated
`s2sdk/public/networksystem/inetworkmessages.h` explicitly documents their removal: allocation
uses `INetworkMessageInternal::AllocateMessage()`, copying uses `CNetMessage::CopyConstruct()`,
and freeing uses the message's virtual destructor.

Read-only IDA checks on both platforms found no strings containing
`AllocateAndCopyConstructNetMessageAbstract`, `DeallocateUnserializedMessage`, or
`DeallocateNetMessageAbstract`. The former allocation slot (index 8) now returns the supplied
record or a default record (`0x2b45d0` on linux, `0x1800e4f20` on windows); it performs no allocation.

With user approval, the two commented skill blocks and their symbol declarations were removed
from `configs/14197.yaml`. Their shared preprocessor scripts and all earlier-version configs and
artifacts remain unchanged. These entries are retired APIs, not pending finder repairs; no new
artifacts are emitted under the removed names.

Verification after retirement: 8 config parsing tests and all 124 `repository-contract` tests
passed. A fresh `find-CNetworkMessages_vtable` run on both platforms with old-version reuse
disabled reported `Successful: 2, Failed: 0, Skipped: 0`; both generated vtable YAML files matched
the tracked artifacts byte-for-byte. The removed methods themselves are not runnable validation
targets, and no pass is claimed for their retired finders.

### RegisterNetworkFieldSerializer / RegisterNetworkArrayFieldSerializer — resolved on both platforms

These virtual interfaces still exist in 14197. Their registry implementations carry the
`NetSerializers_RegisterNetworkFieldSerializer` and `NetSerializers_RegisterNetworkArrayFieldSerializer`
assert strings. The initial diagnosis that their old virtual entries had disappeared was incomplete:
the linux functions and the windows scalar serializer are wrappers, while the windows array
serializer retains the registry implementation directly inside its vtable function.

The combined 14197-only finder resolves each assert's unique owner. If that owner is in the current
`CNetworkMessages` vtable, it uses that slot; otherwise, it intersects the owner's single-call/jump
callers with the vtable. Missing or ambiguous owners/slots fail before either output is emitted.
Both slots are derived on every run, without old signature reuse or fixed indices, and fresh unique
signatures are generated for the virtual entries. The original symbol names and `category: vfunc`
are preserved; the two shared older-version finders are unchanged.

| Platform | Virtual entry | Function VA | Index | Offset |
|---|---|---|---|---|
| linux | RegisterNetworkFieldSerializer | `0x2b4af0` | 6 | `0x30` |
| windows | RegisterNetworkFieldSerializer | `0x1800e6980` | 6 | `0x30` |
| linux | RegisterNetworkArrayFieldSerializer | `0x2b4b50` | 7 | `0x38` |
| windows | RegisterNetworkArrayFieldSerializer | `0x1800e6a10` | 7 | `0x38` |

Eight focused tests cover direct implementations, wrappers, mixed inline states on both platforms,
shifted slots, nonvirtual callers, missing/ambiguous anchors and wrappers, duplicate slots, a shared
slot for both roles, missing vtable data, and signature-generation failure. The isolated IDA run used
only seeded vtable dependencies and no old-version reuse; it generated all four target artifacts:

```text
uv run ida_analyze_bin.py -gamever 14197 -configyaml configs/14197.yaml -platform linux,windows -modules networksystem -skill find-CNetworkMessages_RegisterNetworkFieldSerializer-AND-CNetworkMessages_RegisterNetworkArrayFieldSerializer-14197 -bindir <temporary-binary-root> -artifactdir <isolated-artifact-root> -oldartifactdir bin_artifacts -oldgamever none -require_warm_idb -debug
Successful: 2   Failed: 0   Skipped: 0
```

After incorporating the four generated artifacts, `unit` passed 1571 tests (18 skipped),
`repository-contract` passed 124 tests, and `git diff --check` passed.

### Registry callback methods and registration-permission accessors — resolved on both platforms

`RegisterNetworkFieldChangeCallbackInternal`, `RegisterFieldChangeCallbackPriority`, and
`ComputeOrderForPriority` also retain virtual wrappers in 14197. Their unique implementation owners
are identified by the `NetSerializers_RegisterNetworkFieldChangeCallback`,
`NetSerializers_RegisterFieldChangeCallbackPriority`, and `NetSerializers_ComputeOrderForPriority`
assert strings. The new `find-CNetworkMessages_RegistryCallbacks-14197` producer uses the same
owner/caller resolution as the serializer producer, extracted into `_network_registry_vfunc_common`.

The new `find-CNetworkMessages_vtable-decompiles-14197` consumes the freshly resolved callback.
It first checks that the callback address, index, and offset match the current vtable, then derives
the following two slots. A Hex-Rays ctree probe requires a simple setter assigning the second
argument to a byte field on `this` and a getter reading the same byte field on `this`. It checks
field widths, receiver/value arguments, pointer-arithmetic scaling, and matching offsets; it does
not rely on textual decompilation or a fixed member offset. Only then are fresh signatures emitted.

| Virtual entry | Index | Offset | Linux VA | Windows VA |
|---|---|---|---|---|
| RegisterNetworkFieldChangeCallbackInternal | 21 | `0xa8` | `0x2b4bc0` | `0x1800e6dc0` |
| RegisterFieldChangeCallbackPriority | 26 | `0xd0` | `0x2b4c00` | `0x1800e6e20` |
| ComputeOrderForPriority | 31 | `0xf8` | `0x2b4c30` | `0x1800e6fc0` |
| AllowAdditionalMessageRegistration | 22 | `0xb0` | `0x2b45a0` | `0x1800a68b0` |
| IsAdditionalMessageRegistrationAllowed | 23 | `0xb8` | `0x2b45b0` | `0x1800a68c0` |

The accessors' shared byte offset is `0x348` on linux and `0x288` on windows. All five symbols retain
their original names and `category: vfunc`; the shared older-version scripts are unchanged.

Both new producers were run in dependency order on both platforms with `-oldgamever none`,
`-require_warm_idb`, and temporary binary/artifact roots. The initial artifact root held only the
two vtable dependencies. Each run reported `Successful: 2, Failed: 0, Skipped: 0`, generating six
registry-method YAML files and four accessor YAML files. The refactored serializer producer was
also rebuilt on both platforms from a separate fresh output root: `Successful: 2, Failed: 0,
Skipped: 0`, with all four outputs matching the previously accepted artifacts byte-for-byte.

The focused CNetworkMessages tests pass 21 tests, including the destructor regressions, owner and
wrapper resolution, three-role group handling, typed and raw byte access, scaled pointers, shifted
slots, stale callback metadata, malformed/mismatched accessors, missing/folded slots, invalid probe
results, transport errors, and signature-generation failure.

After incorporating the ten new artifacts and the helper extraction, `unit` passed 1581 tests
(18 skipped), `repository-contract` passed 124 tests, and `git diff --check` passed.

### CNetworkMessages_FindNetworkMessage — resolved on both platforms

The 14197-only finder validates the current `FindNetworkMessagePartial` identity, address, index,
and offset against the vtable, then derives the preceding slot. A Hex-Rays ctree probe requires
that the target calls `V_stricmp_fast` while Partial calls `V_stristr_fast`; swapped, missing, or
mixed comparison calls fail. Symbol decoration is handled for both platform ABIs. No old signature,
fixed slot number, or the former generic `unknown`/integer-byte anchors determine the target.

| Platform | Function VA | Index | Offset |
|---|---|---|---|
| linux | `0x2b7180` | 9 | `0x48` |
| windows | `0x1800e52d0` | 9 | `0x48` |

The old finder's `func_sig_allow_across_function_boundary:true` signing policy is retained. Without
that opt-in, signature collection stopped at internal alignment padding and the linux lookup could
not be uniquely signed. The new unique prefixes are 193 bytes on linux and 132 bytes on windows,
both shorter than their owning functions, and the opt-in is recorded in the emitted payloads.
The shared slot writer now uses the central desired-field normalizer and honors this explicit
directive; callers without it retain their previous signing policy.

An isolated run with only vtable/Partial dependencies seeded, no target outputs, and old-version
reuse disabled reported `Successful: 2, Failed: 0, Skipped: 0`. The setter/getter producer was also
rebuilt on both platforms after sharing the anchor-metadata validator: `Successful: 2, Failed: 0,
Skipped: 0`, with all four outputs matching the previously accepted artifacts byte-for-byte.
The focused CNetworkMessages tests pass 28 tests, covering shifted and stale anchors, missing or
folded predecessor slots, comparator behavior and decoration, transport/signature failures, and
propagation of the explicit signature policy, alongside the preceding registry/accessor regressions.

After incorporating the two lookup artifacts and the shared helper updates, `unit` passed 1588
tests (18 skipped), `repository-contract` passed 124 tests, and `git diff --check` passed.

### SendNetworkStats and network-group interface calls — resolved on both platforms

The old `E0 00 00 00 04` anchor encoded the stats flag at `this + 0xe0`; the field is now at
`this + 0xd0` on both platforms. In addition, windows extracted the `groupnames` serializer into
`0x180108940`, called by the sender. Linux retains that serialization inside the sender.

The 14197-only sender finder uses the unique `groupnames` owner and the stack-depth diagnostic.
It accepts the owner itself, or its unique matching call/jump caller, only if a Hex-Rays probe
finds all three network-group getter calls on the same global receiver. Getter slots are derived
from the validated current `CNetworkMessages_FindNetworkGroup` slot and vtable, rather than a fixed
offset or an old `CNetworkSystem` slot. The sender remains `category: func`.

| Platform | Sender VA | Network-message receiver |
|---|---|---|
| linux | `0x2d9ee0` | `0x4e9de8` |
| windows | `0x1801030f0` | `0x18029c480` |

The new deterministic downstream producer rechecks the receiver, slot displacements, and call
arities, including the Color return ABI difference. It generates each `vfunc_sig` from its actual
virtual-call instruction and writes the three interface outputs only after all signatures succeed.
Mixed receivers, duplicate call sites, ambiguous complete getter groups, malformed probe results,
or signature failures cannot produce a successful result. No LLM or old reference payload is used.

| Interface method | Index | Offset | Linux call VA | Windows call VA |
|---|---|---|---|---|
| GetNetworkGroupCount | 12 | `0x60` | `0x2d9fba` | `0x1801031ce` |
| GetNetworkGroupName | 13 | `0x68` | `0x2da9b3` | `0x18010321d` |
| GetNetworkGroupColor | 14 | `0x70` | `0x2da9c3` | `0x180103237` |

Both producers run in the late networksystem pass after `FindNetworkGroup`. Their explicit
dependencies preserve the configuration's producer order. The two older shared scripts and their
reference YAML files remain unchanged, as do the original symbol names, categories, and aliases.

Twelve focused tests cover fused/extracted serialization, candidate ambiguity, stale or missing
layout anchors, folded getter roles, scaled/indexed vtable loads, shared receiver and argument
checks, platform arities, malformed/failed probes, and preventing partial interface outputs when
signature generation fails. All three configuration dependency tests passed.

The isolated artifact root initially contained only the two vtable and two FindNetworkGroup
dependencies. Both producers were then executed on linux and windows with old-version reuse
disabled and warm temporary binary copies. Each reported `Successful: 2, Failed: 0, Skipped: 0`,
generating the eight restored source artifacts.

After incorporating all eight artifacts, `unit` passed 1600 tests (18 skipped),
`repository-contract` passed 124 tests, and `git diff --check` passed.

### PostEventAbstract2 and local event dispatch — resolved on both platforms

The new 14197 posting finder validates the existing `PostEntityEventAbstract` artifact against
the current vtable, then excludes that sibling's slot from the posting-log owners. Exactly one
remaining virtual entry is required. The overload order differs by ABI: the target is index 15
on linux and index 16 on windows, so no shared fixed index is used.

The 14197 interface finder validates that fresh posting artifact and inspects only virtual calls
whose first argument is the posting function's `this`. The shared receiver probe's optional
`include_sites` mode reports slot-load/call instruction anchors as well as offsets. Its default
offset-list behavior is unchanged. The probe tracks function-pointer locals, so linux's guarded
devirtualization still proves that the loaded slot is actually dispatched on `this`.

A single dispatch slot is required; repeated call sites for that same slot are allowed. The
signature generator validates each proven instruction anchor until a unique `vfunc_sig` is
available. The concrete 14197 finder inherits the freshly resolved interface slot and generates
its own current function signature, with no old overload signature reuse. The older shared
event finders and their reference files are unchanged, and no LLM is used for this chain.

| Symbol | Linux VA / index | Windows VA / index |
|---|---|---|
| CGameEventSystem_PostEventAbstract2 | `0x3811e0` / 15 | `0x1802159f0` / 16 |
| IGameEventSystem_PostEventAbstract_Local | slot anchor `0x381257` / 14 | call anchor `0x180215b2f` / 14 |
| CGameEventSystem_PostEventAbstract_Local | `0x380f50` / 14 | `0x1802155a0` / 14 |

Both Local artifacts use offset `0x70`. The linux interface signature begins at the proven
vtable load; the windows interface signature begins at the direct memory-indirect call.

Ten new tests cover default probe compatibility, direct and hoisted slot anchors, repeated or
different dispatch slots, foreign receivers, unproven pointer assignments, platform-specific
overload order, sibling exclusion, stale metadata, malformed probes, and signature failure or
fallback between proven anchors. All three configuration dependency tests passed.

The three producers ran in dependency order on both platforms using temporary warm binary
copies and an isolated artifact root initially seeded with only the vtable/sibling dependencies.
Each reported `Successful: 2, Failed: 0, Skipped: 0` with old-version reuse disabled, generating
all six restored source artifacts.

After incorporating the six artifacts and the optional probe enhancement, `unit` passed 1610
tests (18 skipped), `repository-contract` passed 124 tests, and `git diff --check` passed.

### FindNetworkMessageById — resolved on both platforms

The old WriteSpawnGroups caller no longer performs this lookup. Its linux `+0xd8` call uses
another receiver, has one argument, and returns a floating-point value, so matching the new
displacement alone would identify the wrong method.

The 14197-only finder instead uses the `Network Message %d` diagnostic context. It derives
ById's slot immediately after the validated priority-registration anchor in the current
network-message vtable, and validates GetNetMessageInfo's interface metadata. A shared Hex-Rays
probe then requires both calls on the same global receiver with two arguments each, and proves
that ById's result is passed as GetInfo's second argument. Single-definition local aliases and
nested calls are supported; ambiguous definitions, mutations, escaped addresses, and cycles are
rejected. Static global arrays with constant indexes are normalized to their actual memory
slots; runtime pointer indexing is rejected.

Multiple diagnostic owners may prove the same receiver and method. The finder tries their
verified ById call instructions in address order until signature generation succeeds. Conflicting
receivers fail validation. No LLM, old signature, or WriteSpawnGroups reference is used. The
older shared finder and reference files remain unchanged.

| Platform | Diagnostic owner(s) | ById signature anchor | Index / offset |
|---|---|---|---|
| linux | `0x425d10`, `0x431010` | `0x425db3` | 27 / `0xd8` |
| windows | `0x1801d6640` | `0x1801d669a` | 27 / `0xd8` |

The global-receiver probe was extracted from the stats helper, preserving the default stats
checks. Both stats producers were rebuilt on both platforms in a fresh artifact root; each
reported `Successful: 2, Failed: 0, Skipped: 0`, and all eight outputs were byte-identical to
the existing source artifacts.

Five new tests exercise result flow, aliases, static-array receivers, rejected ambiguity and
mutations, shifted layout metadata, stale inputs, conflicting receiver contexts, output scope,
signature fallback/failure, and probe transport errors. The seventeen focused ById/stats tests
and three configuration dependency tests passed. The final ById producer ran on both platforms
with warm temporary copies, no existing target outputs, and old-version reuse disabled:
`Successful: 2, Failed: 0, Skipped: 0`. Both restored interface YAMLs have been incorporated.

After incorporating both artifacts and the shared probe extraction, `unit` passed 1615 tests
(18 skipped), `repository-contract` passed 124 tests, and `git diff --check` passed.

### ParseUpdate and buffer decompression — resolved on both platforms

The original quarantine diagnosis above was incorrect about removal: the 14197 parser and its
class-specific diagnostics are present. The old `message too large` diagnostic is gone, but the
intersection of `bogus user data size (%d bytes, max %d).` and `failed to decompress user data
for table %s`, both prefixed by `CNetworkStringTableClient::ParseUpdate:`, uniquely identifies
the parser on each platform. The 14197-only parser finder requires both diagnostics and generates
a fresh function signature without old-version reuse.

Decompression remains a CNetworkSystem vfunc at index 31 / offset `0xf8`. Its signature has
changed: instead of destination bytes, destination-size reference, source bytes, and source
length, it now receives source bytes, source length, and a growable output container (plus
`this`). The implementation validates payload limits and updates the output container. Restored
symbol artifacts describe the location; they do not update the SDK declaration. The existing
SDK declaration still describes the old parameter list and needs a separate SDK change.

The new concrete finder starts from `Net_BufferToBufferDecompress: malformed compressed data`
and requires one implementation owner and a unique current CNetworkSystem vtable entry, either
directly or through its call/jump wrapper. The existing registry helper now accepts a vtable
class for diagnostics; its previous default behavior is unchanged. The concrete finder runs in
the first networksystem pass, before the engine interface consumer.

The new interface finder validates the concrete artifact against the current vtable, then probes
the fresh ParseUpdate body for the same receiver in both the vtable load and first argument,
the current slot, and four total arguments. It requires one matching call and generates the
interface signature from that actual instruction. No old LLM reference or fixed slot is used.

| Platform | ParseUpdate VA | Concrete decompression VA | Interface call VA |
|---|---|---|---|
| linux | `0x59ca90` | `0x2d5040` | `0x59d0e8` |
| windows | `0x180107210` | `0x1801014d0` | `0x180107841` |

Six new tests cover diagnostic intersection and ambiguity, direct/wrapped entries, shifted
concrete slots, stale metadata, output scope, failed call probes, transport errors, and failed
signature generation. All six focused tests, nine existing registry tests, and three configuration
dependency tests passed. Each of the three producers reported `Successful: 2, Failed: 0,
Skipped: 0` in an isolated artifact root, with temporary warm binary copies, no existing target
outputs, and old-version reuse disabled. All six restored artifacts have been incorporated.

After incorporating all six artifacts and restoring the dependency order, `unit` passed 1621
tests (18 skipped), `repository-contract` passed 124 tests, and `git diff --check` passed.

### RemoveNetChannel and RemoveNetChannelByAddress — resolved on both platforms

The old linux `shutdown` literal is absent. Both methods still exist. Their new 14197 finders
derive a shared connection-close helper from direct five-argument calls carrying the `CloseSocket`
literal on the caller's `this`, then inspect its current vtable callers. A removal candidate
must take three arguments and call that helper on `this`. Its immediately following vtable
entry must take three arguments and call removal with the same receiver, a proven channel
value, and a constant false flag. Exactly one pair is required; no fixed slot is embedded.

The channel proof supports linux's out-of-line `(this, socket, address*)` lookup, local aliases,
and windows' inlined load from a collection field also used by the removal body. A null fallback
is allowed, but unproven assignments, cycles, mutations, escaped channel addresses, different
receivers, or a nonzero removal flag fail validation. Local address arrays are identified through
their lvar type even when the call argument has decayed to a pointer. IDA Python execution errors
are surfaced explicitly rather than treated as an empty match.

The ByAddress consumer repeats the pair proof and validates the fresh removal artifact against
the current table before generating its own signature. The config uses the versioned pair on
both platforms; the old windows interface-inheritance producer and old linux string finder
remain available to earlier configs. The new windows removal artifact is byte-identical to the
previous source artifact.

| Platform | Close helper VA | RemoveNetChannel VA / index | ByAddress VA / index |
|---|---|---|---|
| linux | `0x2e9140` | `0x2edc90` / 23 | `0x2edf30` / 24 |
| windows | `0x1800fd040` | `0x1800fda80` / 23 | `0x1800fcec0` / 24 |

Offsets are `0xb8` and `0xc0` respectively. Fourteen new tests cover helper discovery,
receiver identity, explicit and inlined lookup sources, local-array decay, null fallback,
rejected mutations/cycles/unproven assignments, ambiguous or missing pairs, folded slots,
stale artifacts, output scope, signature failure, malformed probe data, and execution errors.
All fourteen focused tests and three configuration dependency tests passed.

Both producers ran on both platforms with temporary warm binary copies, no target outputs
initially present, and old-version reuse disabled. Each reported `Successful: 2, Failed: 0,
Skipped: 0`; all four artifacts have been incorporated.

After incorporating the removal pair and restoring its configuration, `unit` passed 1635 tests
(18 skipped), `repository-contract` passed 124 tests, and `git diff --check` passed.

## Final verification of issue #1238 repairs

All 14197 quarantine blocks associated with this issue have been resolved: the two removed
allocation/deallocation APIs were retired with user approval, and the retained methods and
their downstream finders are enabled. The older ParticleTestStart quarantine referencing
14182 is unrelated and remains unchanged.

A final aggregate run used the unchanged temporary binary copies and a fresh isolated artifact
root. It seeded the existing tracked dependencies, including cross-module interface YAMLs
required by the engine scope, but omitted all 44 repair targets (22 symbols on two platforms).
This includes the previously tracked windows RemoveNetChannel artifact. Neither old-version
reuse nor an existing repair output could satisfy any of the 32 producer/platform executions.

```text
uv run ida_analyze_bin.py -gamever 14197 -configyaml configs/14197.yaml -platform linux,windows -modules engine,networksystem -bindir <temporary-binary-root> -artifactdir <fresh-aggregate-artifact-root> -oldartifactdir bin_artifacts -oldgamever none -require_warm_idb -debug
Successful: 32   Failed: 0   Skipped: 1252
```

All sixteen repaired producers ran on both platforms, in the config's actual dependency order.
The 44 rebuilt YAMLs matched the incorporated source artifacts byte-for-byte. The 1252 skipped
work items were satisfied by existing artifacts; this is not a forced rebuild of every finder
or a validation of binaries in the other modules.

Final quality gates: `unit` 1635 tests (18 skipped), `repository-contract` 124 tests,
configuration dependency checks 3 tests, and `git diff --check`: all passed. The original
unpacked IDB workspace was left untouched. Validation was completed before staging and publication.

### CI comparison-probe diagnostics follow-up

PR #1241's native Linux IDA run failed at the first exact-name lookup comparison probe in
run `43386066873`, attempt 2. The Windows worker completed all 19 selected producers, and
prospective-tree repository tests passed. Linux's later missing-output messages resulted from
the first finder aborting the worker; they do not identify additional independent failures.

The original boolean probe obscured both unresolved callee names and IDA Python errors. It now
returns bounded per-call evidence, both comparator sets, role-specific errors, IDA/Hex-Rays
versions, and the database input path/MD5. The caller surfaces MCP stderr and logs the structured
report, requiring the same exact/partial semantic checks and matching role addresses before
signature generation. It does not accept an unresolved comparison as a fallback.

The diagnostic-only patch passed twelve focused tests and isolated regeneration on both
platforms. A subsequent local `all` suite passed 1842 tests (21 skipped). These local checks
were followed by another native Linux CI run to establish the missing evidence.

Run `43395230647`, attempt 2, confirmed that the database input MD5 and IDA/Hex-Rays versions
matched locally. Its PLT functions at `0x1811f0` and `0x181300` had generic names `sub_1811F0`
and `sub_181300`, with no comparison names found and no decompiler errors. Those same addresses
retain the intended calls; the display-name-only identity check caused the false rejection.

The comparison probe now also resolves actual import identities. Direct imports and native
thunks use their bound import entries; ELF PLT entries require a bounded stub with a terminal
unconditional jump and no earlier calls or jumps. Code/GOT references must identify one import;
ambiguous bindings and arbitrary non-PLT wrappers are rejected. In particular, Source2's
`mov r11d, tag; jmp [GOT]` PLT stubs are not recognized by IDA's generic thunk resolver, so
their terminal jump is checked explicitly. The recovered symbols must still be the exact and
substring comparators respectively; no fixed comparator address or missing-name bypass is used.

Clearing the PLT names in a disposable, independently analyzed linux IDB reproduced the CI
failure with the old probe and passed with the import-backed probe. All 2848 PLT function names
were then cleared for the actual isolated linux validation run. Both platforms reported
`Successful: 2, Failed: 0, Skipped: 0`; both regenerated YAMLs remained byte-identical. The prior
CI's 22 Windows repair targets also matched the source artifacts byte-for-byte.

Seventeen focused tests pass, covering the diagnostic cases, unnamed PLT imports, direct import
and native thunk targets, ambiguous bindings, nonterminal jumps, oversized stubs, rejected
ordinary wrappers, and safe treatment of non-helper ctree expressions. The repository formatting
and diff whitespace checks pass. The PR workflow supplies the final native Linux verification.

# IDA validation failures — gamever 14182

This file records skills that were temporarily disabled because
`ida_analyze_bin.py -debug` could not resolve them for this game version. Each entry
is a to-do item: re-enable the skill in `configs/14182.yaml` once it is fixed.

## find-CBaseFilter_InputTestActivator  (module: server, platform: windows/linux)

Failure (from `ida_analyze_bin.py -debug`):

```text
  Start skill: find-CBaseFilter_InputTestActivator
    Preprocess failed: find-CBaseFilter_InputTestActivator; falling back to AGENT SKILL
    Starting agent skill: find-CBaseFilter_InputTestActivator
    Falling back to: .claude\skills\find-CBaseFilter_InputTestActivator\SKILL.md
    Error: Skill file not found: .claude\skills\find-CBaseFilter_InputTestActivator\SKILL.md
    Failed
```

Diagnosis: the skill is driven by the shared helper
`ida_preprocessor_scripts/_define_inputfunc.py`, which requires a static `.data` descriptor
whose name field points at the bare input-name string and whose `+0x10` field is a `.text`
handler pointer. In 14182 that premise no longer holds on either platform:

- windows (`server.dll`): the bare literal `TestActivator` is no longer a standalone string —
  it only survives as the tail of the schema name `CBaseFilter_API::TestActivator`
  (`0x1819329f0`). The IDA string list has no exact `TestActivator` entry, and no xref,
  absolute pointer or 32-bit RVA in `.data`/`.rdata` points at it.
- linux (`libserver.so`): the bare literal still exists (`0x913a67`, `.rodata.str1.1`) and is
  registered in the string list, but its only xref comes from `.text` code (`0x16b4809`),
  not from a `.data` descriptor. The `.data` entry pointing at the qualified name
  (`0x278d240`) has `.rodata` at `+0x10`, i.e. no `.text` handler.

The 14181 handler signatures match nothing in 14182 on either platform
(windows `48 89 5C 24 ?? 57 48 83 EC ?? 4C 8B 02` → 0 hits;
linux `55 48 89 E5 41 54 49 89 F4 53 48 89 FB 48 83 EC ?? 48 8B 07 48 8B 16` → 0 hits),
so the input-registration mechanism itself changed in this version. The helper consequently
falls through its silent `return False` paths (`_define_inputfunc.py:222-225`) and the failure
carries no diagnostics.

Impact: the same helper drives these skills, which are expected to fail in the same way once
they are reached:

- `find-CGameMoney_m_DataMap`
- `find-CGamePlayerEquip_InputTriggerForAllPlayers`
- `find-CGamePlayerEquip_InputTriggerForActivatedPlayer`
- `find-ShowHudHint`

Decision: user chose to temporarily disable this skill for 14182 and track the helper rework
in a GitHub issue rather than block the validation loop.

## find-CCSPlayerPawn_CreatePlayerPawnServices  (module: server, platform: windows/linux)

Failure (from `ida_analyze_bin.py -debug`):

```text
  Start skill: find-CCSPlayerPawn_CreatePlayerPawnServices
    Preprocess: CCSPlayerPawn_CreatePlayerPawnServices.windows.yaml func_sig matched 0 (need 1)
    Preprocess: trying func_xrefs fallback for CCSPlayerPawn_CreatePlayerPawnServices
    Preprocess: undefined func recovery skipped: no_entry
    Preprocess: vtable CCSPlayerPawn_vtable has 413 entries as candidate set
    Preprocess: exclude string xref 'CCSPlayer_BulletServices *' matched 2 function(s)
    Preprocess: excluded_string_func_addrs = ['0x18021c770', '0x1802418c0']
    Preprocess: common_funcs before excludes = []
    Preprocess: common_funcs after excludes = []
    Preprocess: xref intersection yielded 0 function(s) for CCSPlayerPawn_CreatePlayerPawnServices (need exactly 1)
    Preprocess: failed to locate CCSPlayerPawn_CreatePlayerPawnServices
    Preprocess failed: find-CCSPlayerPawn_CreatePlayerPawnServices; falling back to AGENT SKILL
    Error: Skill file not found: .claude\skills\find-CCSPlayerPawn_CreatePlayerPawnServices\SKILL.md
    Failed
```

Diagnosis: the skill locates the vfunc with `xref_strings: ["FULLMATCH:m_pBulletServices"]`
intersected with the `CCSPlayerPawn_vtable` candidate set. In 14182 that strategy is
structurally broken on windows:

- old func_sig `48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B D9 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ??`
  matches 0 locations;
- the exact string `m_pBulletServices` (`0x1817927e0`) is referenced only by `sub_18021C770`
  and `sub_1802418C0` (exactly the two functions the skill excludes via
  `exclude_strings: ["CCSPlayer_BulletServices *"]`) plus one `.data` reference — i.e. the
  target function no longer references that field name at all;
- the 14181 vtable slot (index 335, offset 0xa78) now points at `0x180ce43f0` (size `0x137`),
  whose shape does not match the 14181 function (size `0x2ff`); its neighbours include a
  0x22-byte trampoline and `nullsub_2484`, so the slot index has shifted;
- the 14181 prologue (`mov [rsp+8],rbx; mov [rsp+10h],rsi; push rdi; sub rsp,?; mov rbx,rcx; call ...`)
  is not unique in 14182 (8+ hits, capped);
- for 9 candidate pawn-service field names, no referencing function belongs to the
  `CCSPlayerPawn_vtable` entry set (they are referenced by schema/registration helpers such as
  `sub_1802418C0`, `sub_18060CB50`, `sub_180620880`).

Impact: 7 skills declare `CCSPlayerPawn_vtable.{platform}.yaml` as `expected_input`; the same
strategy failure can recur for other pawn vtable skills.

Decision: user chose to temporarily disable this skill for 14182 and track the gap in a GitHub
issue rather than block the validation loop.

## find-CGamePlayerEquip_InputTriggerForActivatedPlayer / ...ForAllPlayers  (module: server, platform: windows/linux)

Same failure class as `find-CBaseFilter_InputTestActivator` above — tracked by issue #1061.
Both skills are driven by `ida_preprocessor_scripts/_define_inputfunc.py`, whose premise (a
static `.data` descriptor holding the bare input-name string, with a `.text` handler pointer at
`+0x10`) no longer holds in 14182, so the helper returns False through its silent paths and the
failure carries no diagnostics.

Failure (from `ida_analyze_bin.py -debug`):

```text
  Start skill: find-CGamePlayerEquip_InputTriggerForActivatedPlayer
    Preprocess failed: find-CGamePlayerEquip_InputTriggerForActivatedPlayer; falling back to AGENT SKILL
    Starting agent skill: find-CGamePlayerEquip_InputTriggerForActivatedPlayer
    Falling back to: .claude\skills\find-CGamePlayerEquip_InputTriggerForActivatedPlayer\SKILL.md
    Error: Skill file not found: .claude\skills\find-CGamePlayerEquip_InputTriggerForActivatedPlayer\SKILL.md
    Failed
```

Input names involved: `TriggerForActivatedPlayer` (this skill) and `TriggerForAllPlayers`
(`find-CGamePlayerEquip_InputTriggerForAllPlayers`) — the same bare-name pattern that was
invalidated for `TestActivator`.

Decision: user approved quarantining both skills together (identical class, already tracked by
issue #1061) instead of spending another round on the same root cause.

## find-CSource2Server_OnStreamEntitiesFromFileCompleted + find-IGameSystem_OnRestoreGame  (module: server, platform: windows)

Failure (from `ida_analyze_bin.py -debug`):

```text
  Start skill: find-IGameSystem_OnRestoreGame
    Preprocess: invalid entry count from CSource2Server_OnStreamEntitiesFromFileCompleted, expected 1, got 0
    Preprocess failed: find-IGameSystem_OnRestoreGame; falling back to AGENT SKILL
    Starting agent skill: find-IGameSystem_OnRestoreGame
    Falling back to: .claude\skills\find-IGameSystem_OnRestoreGame\SKILL.md
    Error: Skill file not found: .claude\skills\find-IGameSystem_OnRestoreGame\SKILL.md
    Failed
```

Diagnosis: the two skills form one gap. `find-IGameSystem_OnRestoreGame` resolves its target
through `ida_preprocessor_scripts/_igamesystem_dispatch_common.py`, whose Windows detector
(`_build_dispatch_py_eval`, `:153-180`) reads the `func_va` of
`CSource2Server_OnStreamEntitiesFromFileCompleted.{platform}.yaml`, then looks for a
`lea rdx, <callback>` dispatcher inside that function and for `call [reg+vfunc_offset]` inside
the callback. In 14182 that anchor is a no-op, so no entry can be collected.

Root cause, measured with read-only IDA probes on `bin/14182/server/server.dll`:

- `CSource2Server_vtable2` (`0x18198f7f0`, single slot) resolves by RTTI
  (`??_R4CSource2Server@@6B@_0` at `0x181b839e0`, whose `+8` is the vtable) to entry
  `0x180dd6800`. The real bytes there are `C2 00 00` (`retn 0`); IDA names it `nullsub_3192`
  with `func_size` `0x3`. It is skipped by the main `CSource2Server_vtable`, whose index 98 is
  the next address `0x180dd6810`.
- 14178b / 14180 / 14181 all carried a real `0xd5`-byte function in this slot
  (`48 83 EC ?? 8B 0D ...`), and the 14181 body contains `lea rdx, sub_180512810` — the
  dispatch callback that `find-IGameSystem_OnRestoreGame` needs. Only 14182 turned the slot
  into a no-op, so the skill's premise no longer holds for this version.
- A probe for the fallback marker used by the same helper (`mov rax, gs:58h`, i.e. bytes
  `65 48 8B 04 25 58 00 00 00`) found **zero** matching functions in 14182 `server.dll`
  (`tls_func_count = 0`), so the de-inlined dispatcher fallback cannot be re-anchored either.

Secondary finding (fixed in this repository, not worked around here): the slot was previously
"resolved" by enabling `func_sig_allow_across_function_boundary`, which produced a meaningless
34-byte signature (`C2 ?? ??` + 13 `CC` padding bytes + the next function's prologue). The
pipeline now refuses to emit a `func_sig` when the target body is a single `jmp`/`ret`
instruction: see `DegenerateFuncSigTargetError` and `_classify_func_body_lead_bytes` in
`ida_analyze_util.py`. A script that still requires `func_sig` for such a target fast-fails with
an explicit reason in the error log.

Impact: `find-IGameSystem_OnRestoreGame` declares
`CSource2Server_OnStreamEntitiesFromFileCompleted.{platform}.yaml` as `expected_input`, so the
two skills must be disabled together to keep the dependency graph satisfiable.

Decision: user approved quarantining both skills and tracking the gap in a GitHub issue — tracked
by issue #1063.

## find-IGameSystem_OnSaveGame + find-IGameSystem_OnServerBeginAsyncPostTickWork  (module: server, platform: windows)

Same failure shape as the pair above (the `_igamesystem_dispatch_common` detector collects 0
dispatch entries from the host), but a **different mechanism**, so it is tracked separately.

Failure (from `ida_analyze_bin.py -debug`):

```text
  Start skill: find-IGameSystem_OnSaveGame
    Preprocess: invalid entry count from CEntitySaveRestoreBlockHandler_PreSave, expected 1, got 0
    Preprocess failed: find-IGameSystem_OnSaveGame; falling back to AGENT SKILL
    Error: Skill file not found: .claude\skills\find-IGameSystem_OnSaveGame\SKILL.md
    Failed
```

Diagnosis: the Windows detector uses two signals (`_build_dispatch_py_eval`):

1. primary: a `lea rdx, <callback>` inside the host, then `call [reg+vfunc_offset]` inside that
   callback;
2. de-inline fallback: the host's callees carrying the TLS marker `mov rax, gs:58h`
   (`65 48 8B 04 25 58 00 00 00`).

For both hosts below, neither signal exists in 14182, and no callee of either host performs an
indirect call at the expected slot, so the anchor cannot be recovered locally:

| skill | host (14182) | size | expected slot | measured in host |
|---|---|---|---|---|
| `IGameSystem_OnSaveGame` | `CEntitySaveRestoreBlockHandler_PreSave` (`0x180bc0f10`) | `0x17d` | `0x190` | no `lea rdx`, no `gs:58h`; the single callee has no indirect call |
| `IGameSystem_OnServerBeginAsyncPostTickWork` | `CLoopModeGame_OnServerBeginAsyncPostTickWork` (`0x180c56ad0`) | `0x209` | `0x148`/`0x150` | no `lea rdx`, no `gs:58h`; indirect calls are `0x1a8/0x18/0x80/0x10` |

Both hosts are ordinary, non-degenerate functions, so this is not the thunk/nullsub class.

Scope correction: probing the eight `find-IGameSystem_On*` skills that still lack artifacts showed
that only these two hosts lost the dispatch. The other six hosts still carry the full signal
(`lea rdx, <callback>` with the callback's slot matching the 14181 artifact) and were simply not
reached before an abort — e.g. `CLoopModeGame_OnServerAdvanceTick` (`lea rdx, 0x18052c2e0` →
`call [reg+0x118]`), `CSource2Server_PreWorldUpdate` (→ `0x110`),
`CSpawnGroupMgrGameSystem_OnSpawnGroupPrecache` (→ `0x68`),
`CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown` (→ `0x70` and `0x90`).

Impact: neither skill has a consumer — no other skill lists their outputs as `expected_input` —
so disabling them does not disturb the dependency graph. `find-IGameSystem_OnServerBeginAsyncPostTickWork`
produces two outputs (`IGameSystem_OnServerPreBeginAsyncPostTickWork` and
`IGameSystem_OnServerBeginAsyncPostTickWork`), so one entry covers both.

Decision: user approved quarantining both skills and tracking the gap in a new GitHub issue —
tracked by issue #1064 (cross-referenced with #1063).

## find-CPhysicsEntitySolver_PhysEnableEntityCollisions  (module: server, platform: windows)

Failure (from `ida_analyze_bin.py -debug`):

```text
  Start skill: find-CPhysicsEntitySolver_PhysEnableEntityCollisions
    Preprocess: CPhysicsEntitySolver_PhysEnableEntityCollisions.windows.yaml func_sig matched 0 (need 1)
    Preprocess: trying func_xrefs fallback for CPhysicsEntitySolver_PhysEnableEntityCollisions
    Preprocess: undefined func recovery skipped: no_entry
    Preprocess: vtable CPhysicsEntitySolver has 238 entries as candidate set
    Preprocess: common_funcs before excludes = []
    Preprocess: common_funcs after excludes = []
    Preprocess: xref intersection yielded 0 function(s) for CPhysicsEntitySolver_PhysEnableEntityCollisions (need exactly 1)
    Preprocess: failed to locate CPhysicsEntitySolver_PhysEnableEntityCollisions
    Preprocess failed: find-CPhysicsEntitySolver_PhysEnableEntityCollisions; falling back to AGENT SKILL
    Error: Skill file not found: .claude\skills\find-CPhysicsEntitySolver_PhysEnableEntityCollisions\SKILL.md
    Failed
```

Diagnosis: the skill anchors the vfunc through
`xref_funcs: ["PhysEnableEntityCollisions"]` — which keeps the **callers** of the named function
(`ida_analyze_util.py:7926`) — intersected with the `CPhysicsEntitySolver` vtable entry set. In
14182 that intersection is empty *before* any exclude filter, because the vfunc no longer
delegates to the free helper. Read-only IDA probe on `bin/14182/server/server.dll`:

- `PhysEnableEntityCollisions` is `0x180e87630` (`0x129`), with the same `func_sig` as 14181.
- It has 7 references: three real callers (`sub_180A17250`, `sub_180E1D560`, `sub_180EF5BD0`)
  plus four non-code references in `.rdata`/`.pdata` — exactly the four
  `undefined func recovery skipped: no_entry` lines above.
- None of the three callers is among the 238 `CPhysicsEntitySolver` vtable entries.
- 14182 vtable slot 14 is `0x180e96550` (`0x1d6`) and does **not** call the free helper; its
  callees are `sub_1813AA980`, `sub_1803EA850`, `CBaseEntity_UpdateOnRemove`.
- 14181's target was vtable slot 14 (offset `0x70`, size `0xd9`); the 14182 vtable has 238
  entries versus 14181's 236.

So the target vfunc was rewritten/inlined and no longer calls the free helper, which invalidates
the "callers of the named function ∩ target-class vtable" strategy for this version. This is the
same class as the `find-CCSPlayerPawn_CreatePlayerPawnServices` gap (issue #1062): an anchor
signal that no longer exists, not a degenerate thunk/nullsub.

Unconfirmed lead (deliberately not acted on): 14182 vtable slot 14 is the address-outlier slot of
its neighbourhood, mirroring 14181's slot 14, and grew from `0xd9` to `0x1d6` — so it may be the
same logical slot with a rewritten body. Re-anchoring on that heuristic without verification would
risk emitting a wrong function and a wrong signature, which is harder to detect than a failure.

Impact: no downstream consumer — no other skill lists this output as `expected_input` — so
disabling it is self-contained.

Decision: user approved quarantining this skill and tracking the gap in a new GitHub issue —
tracked by issue #1065 (same class as #1062).

## find-ParticleTestStart_CommandHandler-decompiles  (module: server, platform: linux)

Failure (from `ida_analyze_bin.py -debug`):

```text
    Preprocess: llm_decompile parsed response for DispatchParticleEffect BEGIN
{
  "found_vcall": [],
  "found_call": [],
  "found_funcptr": [],
  "found_gv": [],
  "found_struct_offset": []
}
    Preprocess: llm_decompile parsed response for DispatchParticleEffect END
    Preprocess: failed to locate DispatchParticleEffect
    Preprocess failed: find-ParticleTestStart_CommandHandler-decompiles; falling back to AGENT SKILL
    Error: Skill file not found: .claude\skills\find-ParticleTestStart_CommandHandler-decompiles\SKILL.md
    Failed
```

Diagnosis: the `llm_decompile` model returned a well-formed but **explicitly empty** answer
(`"schema_kind": "explicit_empty"`) for the target symbol `DispatchParticleEffect`, even though the
prompt it received literally contains the answer:

- target block disassembly: `.text:000000000158C53F  call DispatchParticleEffect`
- and `.text:000000000158C5F4  call UTIL_PlayerSlotToPlayerPawn` for the skill's second symbol.

The same skill produced both artifacts on windows (`DispatchParticleEffect.windows.yaml`,
`UTIL_PlayerSlotToPlayerPawn.windows.yaml`), so only the linux pass fails. The model's raw response
was valid YAML with all five result lists empty — this is an answer-quality failure, not a missing
prompt payload and not a signature-uniqueness problem.

Contributing hypothesis (unproven): the shared prompt `prompt/call_llm_decompile.md` documents
`found_call` only with **unresolved** callees (`insn_disasm: call sub_180999900`) and stresses
"report the true function name we asked to collect, not the sub_XXXXXXXX". The case at hand is the
opposite — the disassembly already shows the requested symbol name — which no example covers, so
the model may treat it as "nothing to report".

Not a portable name-based shortcut: neither symbol is an ELF export (the strings are absent from
`bin/14182/server/libserver.so`); the resolved names visible in the prompt come from the checked-in
reference `references/server/ParticleTestStart_CommandHandler.linux.yaml`, so resolving by name
would not work for a freshly validated game version.

Impact: neither output has a consumer — no other skill lists them as `expected_input` — so
disabling this skill is self-contained.

Decision: user approved quarantining this skill and tracking the gap in a new GitHub issue —
tracked by issue #1067.





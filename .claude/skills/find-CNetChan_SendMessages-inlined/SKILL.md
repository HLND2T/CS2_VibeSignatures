---
name: find-CNetChan_SendMessages-inlined
description: |
  Final-guarantee fallback for the find-CNetChan_SendMessages-inlined preprocessor. Recovers CNetChan::SendMessages
  (its func_va/func_rva/func_size/func_sig plus CNetChan vtable slot) in CS2 networksystem.dll / libnetworksystem.so.
  Use when the deterministic preprocessor (ida_preprocessor_scripts/find-CNetChan_SendMessages-inlined.py) could not
  locate the target, which happens when the thin wrapper is inlined away and the unique xref string
  "SendMessage reliable failed AllocateMessage (%d)." lives in the shared helper instead of the vfunc itself.
  Trigger: CNetChan_SendMessages
disable-model-invocation: true
---

# Find CNetChan_SendMessages (final-guarantee fallback)

Recover `CNetChan::SendMessages` in CS2 `networksystem.dll` / `libnetworksystem.so` using IDA Pro MCP tools.

This is the **Agent fallback** for the `find-CNetChan_SendMessages-inlined` skill. It runs only when the
preprocessor returned failure. The preprocessor's inlined path locates the target by the xref string
`"SendMessage reliable failed AllocateMessage (%d)."`, which actually lives inside the shared helper
`CNetChan_SendMessages_Internal` — so that anchor identifies the helper's callers, **two** of which exist
(`CNetChan::SendMessages` and `CNetChan::Transmit`). When the sibling `-noinline` path cannot disambiguate them,
this fallback is what resolves the real target.

## Realworld Function References

Read the platform-relevant real-world YAMLs before searching in IDA. They provide concrete disassembly and
semantic anchors for the neighbouring `CNetChan` vfuncs and document the decoy. Treat their addresses and
offsets as reference-build values only; verify every result against the current binary.

- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemo.windows.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemo.linux.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemoInternal.windows.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemoInternal.linux.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseNetMessageShowFilter.windows.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseNetMessageShowFilter.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_SendMessages.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_SendMessages.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_SendMessages_Internal.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_SendMessages_Internal.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_Transmit.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_Transmit.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_vtable.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_vtable.linux.yaml`

## Background — CNetChan::SendMessages and its two-caller trap

`CNetChan::SendMessages` is the `CNetChan` virtual that drains the channel's outbound message queue. It is a
thin wrapper: it acquires the channel's `CAtomicMutex` and then calls the standalone helper
`CNetChan_SendMessages_Internal`, which does the real work (allocating and transmitting each queued message and
logging `"SendMessage reliable failed AllocateMessage (%d)."` on failure).

All member accesses are relative to `this` (arg1: `rcx` on Windows, `rdi` on Linux). The vtable is `CNetChan`;
the function has a body, so its YAML carries **both** `func_*` fields and the vtable slot fields.

> **Decoy — this is the trap that matters.** `CNetChan::Transmit` also calls `CNetChan_SendMessages_Internal`
> (it flushes the queue as part of suppressing transmit). So `CNetChan_SendMessages_Internal` has exactly
> **two** callers, and the shared xref string cannot tell them apart. The preprocessor's `-noinline` path
> resolves this with `exclude_funcs: ["CNetChan_Transmit"]`; when that path is unavailable, you must
> disambiguate here. Use Step 2.

## Robustness principle — anchor semantically, not by signature

The old `func_sig` and the old vtable slot are *both* rebuild-fragile. Do not rely on either to find the
function. Instead:

1. Resolve the helper `CNetChan_SendMessages_Internal` (it *does* own the unique string).
2. Enumerate the helper's callers — there will be two.
3. Separate the real target from `CNetChan_Transmit` by the structural fingerprint in Step 2.
4. Only once the function is confirmed, derive the vtable slot by **matching the resolved address against the
   `CNetChan` vtable entries** — never by trusting the previous `vfunc_index`.

## Output inventory

`struct_name` is not used (this is a real vtable vfunc, not an interface indirect vcall). Addresses, offsets and
sizes are **reference values from build 14191 — verify against the binary, do not assume**.

| # | Output symbol | Kind | Windows | Linux | Writer skill |
|---|---------------|------|---------|-------|--------------|
| 1 | `CNetChan_SendMessages` | real vtable vfunc | `func_va 0x1800bf650`, `size 0xad`, vtable `CNetChan` slot `43` / `0x158` | `func_va 0x291cd0`, `size 0xcb`, vtable `CNetChan` slot `44` / `0x160` | `/write-vfunc-as-yaml` |

Platform gating: the symbol is produced on **both** platforms. The slot differs per platform (Windows 43,
Linux 44) — resolve it from the vtable, do not carry a number across platforms.

## Step 0. Skip targets already produced

If `CNetChan_SendMessages.<platform>.yaml` already exists in the **analyzer-reported artifact module
directory** and parses to a non-empty mapping, skip it — the preprocessor or an earlier fallback wrote it.
Never derive the artifact path from the binary directory; use the directory reported by the analyzer (also
readable as `CS2VIBE_ARTIFACT_DIR`).

`/get-func-from-yaml` reports existence for the function (returns an error when absent).

## Step 1. Resolve the helper and the candidate set

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetChan_SendMessages_Internal` to get its `func_va`.
If it errors, the helper has not been produced yet: resolve it first with the sibling
`find-CNetChan_SendMessages_Internal` skill (its own anchor is the same unique string), because this fallback
depends on it as `expected_input`. Do not guess.

Then enumerate the helper's callers — the candidate set for the target:

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, ida_funcs
INTERNAL = 0x290c10  # <-- CNetChan_SendMessages_Internal.func_va
seen = []
for x in idautils.XrefsTo(INTERNAL, 0):
    f = ida_funcs.get_func(x.frm)
    if f and f.start_ea not in seen:
        seen.append(f.start_ea)
for a in sorted(seen):
    print(hex(a), ida_funcs.get_func_name(a))
"""
```

On 14191 this yields exactly two entries (Windows `0x1800bf650` / `0x1800be510`; Linux `0x291cd0` / `0x29d1e0`).
If more than two appear, still apply Step 2 to each — the fingerprint, not the count, decides.

## Step 2. Disambiguate the real target from CNetChan_Transmit (do not skip)

The real `CNetChan::SendMessages` and the decoy `CNetChan::Transmit` differ structurally. Verified on 14191:

- **`CNetChan::SendMessages` is the *small* wrapper** (Windows `0xad`, Linux `0xcb` bytes). On Windows it calls
  `GetCurrentThreadId` and, only on lock contention, the imported `CAtomicMutex::AcquireLock`, then calls the
  helper; on Linux it uses an inline `lock cmpxchg [this+9008h]` spin on the same mutex and calls the helper.
- **`CNetChan::Transmit` is substantially larger** (Windows `0x1d0`, Linux `0x2de` bytes) and is the only one of
  the two that references the string `"%s:  CNetChan::Transmit( %s ) while suppressing transmit"`.

Disambiguate by **size and the mutex-acquire prologue**, not by a captured address:

1. Of the two candidates, the one that is the *thinner* wrapper — its only call reachable on the non-contended
   path is the helper, and its body is dominated by the `CAtomicMutex` acquire/release around that call — is the
   real target.
2. Positively confirm by checking that the candidate does **not** reference the
   `"while suppressing transmit"` string. A candidate that does is `CNetChan::Transmit`.

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, ida_funcs, idc
TRANSMIT_NEEDLE = "while suppressing transmit"
cands = [0x0, 0x0]  # <-- the two candidate starts from Step 1
for addr in cands:
    f = ida_funcs.get_func(addr)
    has_needle = False
    for head in idautils.Heads(f.start_ea, f.end_ea):
        for x in idautils.XrefsFrom(head, 0):
            try:
                tgt = x.to
            except Exception:
                continue
            txt = idc.get_strlit_contents(tgt) if tgt else None
            if txt and TRANSMIT_NEEDLE in txt.decode('utf-8', 'replace'):
                has_needle = True
    print(hex(addr), "size", hex(f.end_ea - f.start_ea), "transmit_string", has_needle)
"""
```

Scan the **whole function body** (`ida_funcs.Heads` over `[start_ea, end_ea)`), not just the entry
instruction — `XrefsFrom` at the entry point alone does not see string references made deeper in the body.

The real `CNetChan::SendMessages` is the candidate with a small size and `transmit_string = False`.

If **both** candidates reference the transmit string, or **neither** is a thin helper wrapper, the build has been
restructured beyond these anchors — **STOP** and report, so the references can be extended. Do not guess.

## Step 3. Assign the vtable fields

Once the function start is resolved, look it up in the `CNetChan` vtable entries:

```
mcp__ida-pro-mcp__py_eval code="""
import yaml, os, idaapi
d = os.environ.get('CS2VIBE_ARTIFACT_DIR') or os.path.dirname(idaapi.get_input_file_path())
plat = 'windows' if idaapi.get_input_file_path().endswith('.dll') else 'linux'
v = yaml.safe_load(open(os.path.join(d, 'CNetChan_vtable.%s.yaml' % plat), encoding='utf-8'))
ents = {}
for k, x in v['vtable_entries'].items():
    ents[int(k)] = int(str(x), 16)
tgt = 0x0  # <-- resolved CNetChan_SendMessages start
idx = []
for k, a in ents.items():
    if a == tgt:
        idx.append(k)
print('vtable_class', v['vtable_class'])
print('match index', idx, 'offset', [hex(i*8) for i in idx])
"""
```

Use explicit `for` loops, not comprehensions: inside `py_eval` a comprehension body cannot see the enclosing
locals (it raises `NameError`), whereas a plain loop can.

Set:

- `vtable_name = CNetChan`
- `vfunc_index = <the matching entry index>`
- `vfunc_offset = vfunc_index * 8`

If the resolved start matches **no** vtable entry, the function is not the vtable target — return to Step 2.
Do **not** emit the previous build's slot.

The legacy artifact key `CNetChan_SendMessages` identifies the checkpoint-bounded
sender `CNetChan::TransmitUpToCheckpoint`. Rename the function accordingly:

```
mcp__ida-pro-mcp__rename batch={"func":[{"addr":"<start>","name":"CNetChan_TransmitUpToCheckpoint"}]}
```

## Step 4. Generate the signature and write the YAML

1. **ALWAYS** Use SKILL `/generate-signature-for-function` with `addr=<resolved start>` to obtain a fresh,
   validated `func_sig`. (This is a real function with a body — unlike an interface indirect vcall.)
2. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `artifact_name`: `CNetChan_SendMessages`
   - `func_name`: `CNetChan_TransmitUpToCheckpoint`
   - `func_addr`: the resolved function start
   - `func_sig`: the signature from step 1
   - `vtable_name`: `CNetChan`
   - `vfunc_offset`: `vfunc_index * 8` (from Step 3)
   - `vfunc_index`: from Step 3

   If `/write-vfunc-as-yaml` cannot take both a `func_addr` and vtable fields in one call, use
   `/write-func-as-yaml` for the `func_*` fields and then add the vtable fields, matching the field set of the
   14191 ground-truth YAML (`func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`, `vtable_name`,
   `vfunc_offset`, `vfunc_index`). Do not omit the vtable fields — downstream consumers read `vfunc_index`.

Do not write a partial YAML: all eight fields above are required, and the writer must produce them for the
platform being processed only.

## Failure handling

- `CNetChan_SendMessages_Internal` YAML missing → **STOP** and report (this skill's `expected_input` is absent).
- `CNetChan_vtable.<platform>.yaml` missing → **STOP** and report.
- The helper has zero callers, or the two candidates cannot be separated by Step 2 → **STOP** and report which
  check failed. Do not guess an address.
- Never emit the symbol on the wrong platform, and never reuse a previous build's `func_va`/`vfunc_index`.

## Output YAML filenames

Written under the analyzer-reported artifact module directory, one file per platform:

- Windows (`networksystem.dll`): `CNetChan_SendMessages.windows.yaml`
- Linux (`libnetworksystem.so`): `CNetChan_SendMessages.linux.yaml`

## Why this is robust

- The helper `CNetChan_SendMessages_Internal` owns the unique `"SendMessage reliable failed AllocateMessage
  (%d)."` string, so it is always locatable; the ambiguity is confined to its two callers.
- Those callers are separated by a **structural** fingerprint (thin mutex-wrapper vs. the large Transmit body
  that owns the `"while suppressing transmit"` string), which does not depend on a struct displacement — that
  displacement shifted from `0x70` (14181) to `0x8C` (14191) and is exactly what made the original fixed-offset
  exclusion fragile.
- The vtable slot is **derived** from the resolved address, so a vtable reorder is absorbed instead of repeated.
- A fresh `func_sig` is generated from the located function, so a rewritten prologue is absorbed too.

---
name: find-CNetworkMessages_UnserializeMessageInternal
description: |
  Final-guarantee fallback for the find-CNetworkMessages_UnserializeMessageInternal preprocessor. Recovers
  CNetworkMessages::UnserializeMessageInternal (its func_va/func_rva/func_size/func_sig plus CNetworkMessages
  vtable slot) in CS2 networksystem.dll / libnetworksystem.so. Use when the deterministic preprocessor
  (ida_preprocessor_scripts/find-CNetworkMessages_UnserializeMessageInternal.py) could not locate the target
  because the stored func_sig no longer matches and its xref-string anchors ("size_exceeded_max", "netmessage")
  yield an empty candidate set.
  Trigger: CNetworkMessages_UnserializeMessageInternal
disable-model-invocation: true
---

# Find CNetworkMessages_UnserializeMessageInternal (final-guarantee fallback)

Recover `CNetworkMessages::UnserializeMessageInternal` in CS2 `networksystem.dll` / `libnetworksystem.so` using
IDA Pro MCP tools.

This is the **Agent fallback** for the `find-CNetworkMessages_UnserializeMessageInternal` skill: it runs only
when the preprocessor returned failure. The preprocessor tries to reuse the previous build's `func_sig` and
then falls back to two xref-string anchors; on a new build any of those can miss:

- the stored `func_sig` breaks when the prologue is rewritten;
- the xref-string fallback breaks when `"size_exceeded_max"` or `"netmessage"` lose their direct string xref —
  these are passed to `__MakeGlobalSymbolCaseSensitive`, a bare call whose string argument is frequently shared
  or folded so the `XrefsTo` lookup returns an empty set (this is exactly how it failed on 14189:
  `empty candidate set for string xref: size_exceeded_max`).

Your job is to locate the function by **semantic anchors that survive those changes**, then emit the YAML.

## Realworld Function References

Read the platform-relevant real-world YAMLs before searching in IDA. `CNetworkMessages::UnserializeMessageInternal`
has no dedicated reference YAML, so use the neighbouring `CNetworkMessages` finders and the ground-truth outputs
for context and for the vtable cross-check. Treat addresses, offsets and sizes as reference-build values only;
verify every result against the current binary.

- `bin_artifacts/14188b/networksystem/CNetworkMessages_UnserializeMessageInternal.windows.yaml`
- `bin_artifacts/14188b/networksystem/CNetworkMessages_UnserializeMessageInternal.linux.yaml`
- `bin_artifacts/14188b/networksystem/CNetworkMessages_vtable.windows.yaml`
- `bin_artifacts/14188b/networksystem/CNetworkMessages_vtable.linux.yaml`
- `bin_artifacts/14188b/networksystem/CNetworkMessages_SerializeInternal.windows.yaml`
- `bin_artifacts/14188b/networksystem/CNetworkMessages_SerializeMessageInternal.windows.yaml`
- `bin_artifacts/14188b/networksystem/CNetworkMessages_UnserializeFromStream.windows.yaml`
- `bin_artifacts/14188b/networksystem/CNetworkMessages_FindOrCreateNetMessage.windows.yaml`
- `bin_artifacts/14188b/networksystem/CNetworkMessages_RegisterNetworkCategory.windows.yaml`

## Background — what CNetworkMessages::UnserializeMessageInternal does

`CNetworkMessages::UnserializeMessageInternal(this, msg, stream)` is the `CNetworkMessages` virtual that reads
one net message body from a stream:

- it first obtains the message body size (`sub_1801BF610` on Windows / `sub_303E40` on Linux) and rejects a size
  that exceeds the remaining stream bit budget;
- it asks the stream/context object (`a3` vtable) for the associated message descriptor and the caller name/id;
- when the body size exceeds the per-message cap (default `1500`, or a value read from the message descriptor's
  keyvalues) and the `-netmessage_size_exceeded_max` command-line option is **not** set, it builds a small
  keyvalues block and logs a diagnostic — anchored by the four named keys `"name"`, `"id"`, `"size"`,
  `"max_size"` and the two global symbol names `"size_exceeded_max"`, `"netmessage"`;
- it then copies the body into the destination buffer (raw pointer or `g_pMemAlloc`-allocated scratch) and
  returns success/failure.

All accesses that matter for anchoring are **immediates and immediate arguments**, not `this + offset` — this is
a plain function, so it is identified by its unique constants and its vtable position, not by a struct member.

## Robustness principle — anchor on constants, not on string xrefs

Do **not** rely on the preprocessor's `func_sig` or on the `"size_exceeded_max"` / `"netmessage"` string xrefs —
both are what failed. Instead anchor on the **keyvalues key-hash immediates**, which are compiled directly into
the function and are globally unique to it (verified on 14188b, both platforms):

| Key | 32-bit immediate (hex) |
|-----|------------------------|
| `"id"` | `0x18BE5E5F` |
| `"size"` | `0x82E324C5` |
| `"max_size"` | `0x9EFBD7ED` |

Each of these three values appears **exactly once** in the whole binary, and that occurrence is inside
`CNetworkMessages::UnserializeMessageInternal`. (`"name"`'s immediate `0x70E8F456` is *not* unique — do not use
it as a primary anchor.)

The vtable slot is then **derived** from the resolved address, never carried over from the previous build.

## Output inventory

This is a real vtable vfunc with a body, so the YAML carries both `func_*` fields and the vtable slot fields.
Offsets/indices/sizes are **reference values from build 14188b — verify against the binary, do not assume**.

| # | Output symbol | Kind | Windows | Linux | Writer skill |
|---|---------------|------|---------|-------|--------------|
| 1 | `CNetworkMessages_UnserializeMessageInternal` | real vtable vfunc | `func_va 0x1800e1f60`, `size 0x2f2`, vtable `CNetworkMessages` slot `4` / `0x20` | `func_va 0x2b1b60`, `size 0x2da`, vtable `CNetworkMessages` slot `4` / `0x20` | `/write-vfunc-as-yaml` |

Platform gating: the symbol is produced on **both** platforms. The vtable slot is `4` (`0x20`) on both — but
still resolve it from the vtable rather than assuming, since the vtable can be reordered independently.

## Step 0. Skip targets already produced

If `CNetworkMessages_UnserializeMessageInternal.<platform>.yaml` already exists in the **analyzer-reported
artifact module directory** and parses to a non-empty mapping, skip it — the preprocessor or an earlier fallback
wrote it. Never derive the artifact path from the binary directory; use the directory reported by the analyzer
(also readable as `CS2VIBE_ARTIFACT_DIR`).

## Step 1. Load the CNetworkMessages vtable

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CNetworkMessages` to obtain the authoritative
`vtable_va`, `vtable_symbol` and `vtable_entries` for the current build. You need this to assign the vtable
fields in Step 3 and to cross-check the resolved address.

The `expected_input` for this skill is exactly this `CNetworkMessages_vtable.{platform}.yaml`, so it must already
exist when the fallback runs. If `/get-vtable-from-yaml` errors, **STOP** and report to user.

## Step 2. Locate the function by its unique key-hash immediates

Search the whole image for each 4-byte little-endian immediate. Any one of them is sufficient; require that at
least two agree on a single function start.

```
mcp__ida-pro-mcp__py_eval code="""
import ida_bytes, ida_funcs, idc, idaapi
vals = {"id": 0x18BE5E5F, "size": 0x82E324C5, "max_size": 0x9EFBD7ED}
lo, hi = idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea()
for name, v in vals.items():
    b = v.to_bytes(4, 'little')
    found = set(); s = lo; n = 0
    while n < 40:
        a = ida_bytes.find_bytes(b, s, hi)
        if a == idaapi.BADADDR:
            break
        f = ida_funcs.get_func(a)
        if f:
            found.add((hex(f.start_ea), idc.get_func_name(f.start_ea)))
        s = a + 1; n += 1
    print(name, hex(v), sorted(found))
"""
```

The function start returned for the three values is `CNetworkMessages_UnserializeMessageInternal`.

**Positive confirmation (optional, use when the immediates are ambiguous)**: the target is the only function that
calls `__MakeGlobalSymbolCaseSensitive` (Windows `_MakeGlobalSymbolCaseSensitive`) twice in a row with the
arguments `"size_exceeded_max"` then `"netmessage"`, immediately after building the `"name"`/`"id"`/`"size"`/
`"max_size"` keyvalues block. Confirm by scanning the candidate's own strings/calls:

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, ida_funcs
f = ida_funcs.get_func(0x0)  # <-- candidate start
strings = idautils.Strings(default_setup=False)
sm = {s.ea: str(s) for s in strings}
hits = []
for ea, txt in sm.items():
    for x in idautils.XrefsTo(ea, 0):
        if f.start_ea <= x.frm < f.end_ea:
            hits.append(txt[:40]); break
print(sorted(set(hits)))
"""
```

A correct candidate's own strings include `"max_size"` and usually `"size_exceeded_max"` / `"netmessage"`.

> Note: `"size_exceeded_max"` / `"netmessage"` may legitimately have **no** `XrefsTo` at all in some builds
> (the preprocessor hit exactly this on 14189). Their absence is **not** evidence against a candidate — that is
> why the key-hash immediates above are the primary anchor and the strings are only a confirmation aid.

## Step 3. Assign the vtable fields

Look the resolved function start up in the `CNetworkMessages` vtable entries from Step 1:

```
mcp__ida-pro-mcp__py_eval code="""
import yaml, os, idaapi
d = os.environ.get('CS2VIBE_ARTIFACT_DIR') or os.path.dirname(idaapi.get_input_file_path())
plat = 'windows' if idaapi.get_input_file_path().endswith('.dll') else 'linux'
v = yaml.safe_load(open(os.path.join(d, f'CNetworkMessages_vtable.{plat}.yaml'), encoding='utf-8'))
ents = {int(k): int(str(x), 16) for k, x in v['vtable_entries'].items()}
tgt = 0x0  # <-- resolved CNetworkMessages_UnserializeMessageInternal start
idx = [k for k, a in ents.items() if a == tgt]
print('vtable_class', v['vtable_class'])
print('match index', idx, 'offset', [hex(i * 8) for i in idx])
"""
```

Set:

- `vtable_name = CNetworkMessages`
- `vfunc_index = <the matching entry index>`
- `vfunc_offset = vfunc_index * 8`

Verified neighbours you can sanity-check against (14189 Windows): slot `0` = `CNetworkMessages_RegisterNetworkCategory`,
slot `2` = `CNetworkMessages_FindOrCreateNetMessage`, slot `5` = `CNetworkMessages_SerializeMessageInternal`,
slot `6` = `CNetworkMessages_UnserializeFromStream`, slot `8` = `CNetworkMessages_AllocateAndCopyConstructNetMessageAbstract`,
slot `11` = `CNetworkMessages_RegisterNetworkArrayFieldSerializer`, slot `24` = `CNetworkMessages_RegisterNetworkFieldChangeCallbackInternal`.
If the resolved start matches **no** vtable entry, the function is not the vtable target — return to Step 2.
Do **not** emit the previous build's slot.

Rename the function to `CNetworkMessages_UnserializeMessageInternal` if it is not already named that:

```
mcp__ida-pro-mcp__rename batch={"func":[{"addr":"<start>","name":"CNetworkMessages_UnserializeMessageInternal"}]}
```

## Step 4. Generate the signature and write the YAML

1. **ALWAYS** Use SKILL `/generate-signature-for-function` with `addr=<resolved start>` to obtain a fresh,
   validated `func_sig`. (This is a real function with a body — unlike an interface indirect vcall.)
2. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `CNetworkMessages_UnserializeMessageInternal`
   - `func_addr`: the resolved function start
   - `func_sig`: the signature from step 1
   - `vtable_name`: `CNetworkMessages`
   - `vfunc_offset`: `vfunc_index * 8` (from Step 3)
   - `vfunc_index`: from Step 3

   The YAML must contain all eight fields (`func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`,
   `vtable_name`, `vfunc_offset`, `vfunc_index`) for the platform being processed only. If `/write-vfunc-as-yaml`
   cannot take both a `func_addr` and vtable fields in one call, write the `func_*` fields with
   `/write-func-as-yaml` and then add the vtable fields.

Do not write a partial YAML, and do not carry a stale `func_va`/`vfunc_index` forward from a previous build.

## Failure handling

- `CNetworkMessages_vtable.<platform>.yaml` missing → **STOP** and report (the skill's `expected_input` is absent).
- The key-hash immediates resolve to no function, or disagree on more than one function start → **STOP** and
  report which immediate failed, so the references can be extended. Do not guess an address.
- Never emit the symbol on the wrong platform, and never reuse a previous build's `func_va`/`vfunc_index`.

## Output YAML filenames

Written under the analyzer-reported artifact module directory, one file per platform:

- Windows (`networksystem.dll`): `CNetworkMessages_UnserializeMessageInternal.windows.yaml`
- Linux (`libnetworksystem.so`): `CNetworkMessages_UnserializeMessageInternal.linux.yaml`

## Why this is robust

- The function is located by **immediate hash constants compiled into its body** — they cannot be relocated away
  by string dedup or cross-function string sharing, which is precisely the failure mode that produced the
  preprocessor's `empty candidate set for string xref: size_exceeded_max`.
- The vtable slot is **derived** from the resolved address, so a vtable reorder is absorbed instead of repeated.
- A fresh `func_sig` is generated from the located function, so a rewritten prologue is absorbed too.

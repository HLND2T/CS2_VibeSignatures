---
name: find-CNetChan_CanPacket
description: |
  Final-guarantee fallback for the find-CNetChan_CanPacket preprocessor. Recovers CNetChan::CanPacket
  (its func_va/func_rva/func_size/func_sig plus CNetChan vtable slot) in CS2 networksystem.dll /
  libnetworksystem.so.
  Use when the deterministic preprocessor (ida_preprocessor_scripts/find-CNetChan_CanPacket.py) could not
  locate the target because the stored func_sig no longer matches, the CNetChan vtable was reordered so the old
  vfunc slot no longer resolves, or the "%s: !CanPacket() - m_bSuppressingTransmit." xref string moved.
  Trigger: CNetChan_CanPacket
disable-model-invocation: true
---

# Find CNetChan_CanPacket (final-guarantee fallback)

Recover `CNetChan::CanPacket` in CS2 `networksystem.dll` / `libnetworksystem.so` using IDA Pro MCP tools.

This is the **Agent fallback** for the `find-CNetChan_CanPacket` skill: it runs only when the preprocessor
returned failure. The preprocessor tries two things and either can miss on a new build:

- reuse the previous build's `func_sig` — breaks when the prologue is rewritten;
- reuse the `"%s: !CanPacket() - m_bSuppressingTransmit."` xref string — breaks when the single call site moves
  or the string literal relocates.

Your job is to locate the function by **semantic anchors that survive those changes**, then emit the YAML.

## Realworld Function References

Read the platform-relevant real-world YAMLs before searching in IDA. They provide concrete disassembly,
decompiler output, and semantic anchors, and they document the neighbouring functions you must distinguish the
target from. Treat their addresses and offsets as reference-build values only; verify every result against the
current binary.

- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemo.windows.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemo.linux.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemoInternal.windows.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemoInternal.linux.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseNetMessageShowFilter.windows.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseNetMessageShowFilter.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_CanPacket.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_CanPacket.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_SetTimeout.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_SetTimeout.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_UpdateMessageStats.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_UpdateMessageStats.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_vtable.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_vtable.linux.yaml`

## Background — CNetChan::CanPacket and its decoys

`CNetChan::CanPacket` is the `CNetChan` virtual that reports whether the channel may send right now:

- returns false while the channel is suppressed (`m_bSuppressingTransmit`), logging
  `"%s: !CanPacket() - m_bSuppressingTransmit.\n"`;
- otherwise consults the outstanding message/byte budget and the channel's timeout state.

All member accesses are relative to `this` (the first argument — `rcx` on Windows, `rdi` on Linux). The vtable is
`CNetChan`; the function has a body, so its YAML carries **both** `func_*` fields and the vtable slot fields.

> **Decoy — this is the trap that matters.** `CanPacket` has a **small, generic prologue**
> (`55 48 89 E5 41 54 53 48 89 FB 48 83 EC ?? 80 BF ...` on Linux) that is shared with several other small
> `CNetChan` members. In particular a stale `find-CNetChan_UpdateMessageStats` anchor once matched this exact
> prologue template and mislabelled `CanPacket` as `UpdateMessageStats`, producing a duplicate artifact that
> collided at the *other* symbol's slot. The reverse confusion is equally possible here: if your prologue search
> lands on a function that references the `"UpdateMessageStats, bit counter about to roll over"` string, it is
> `UpdateMessageStats`, not `CanPacket`. Use the string anchor in Step 2, not the prologue.

## Robustness principle — anchor semantically, not by signature

The old `func_sig` and the old vtable slot are *both* rebuild-fragile — that is exactly what failed. Do not rely
on either to find the function. Instead:

1. Find the function by its **semantic fingerprint** (the `!CanPacket()` suppression log and the budget/timeout
   checks).
2. **Disambiguate against its vtable neighbours** (Step 2b) — several small `CNetChan` members share the prologue.
3. Only once the function is confirmed, derive the vtable slot by **matching the resolved address against the
   `CNetChan` vtable entries** — never by trusting the previous `vfunc_index`.

## Output inventory

`struct_name` is not used (this is a real vtable vfunc, not an interface indirect vcall). Addresses, offsets and
sizes are **reference values from build 14191 — verify against the binary, do not assume**.

| # | Output symbol | Kind | Windows | Linux | Writer skill |
|---|---------------|------|---------|-------|--------------|
| 1 | `CNetChan_CanPacket` | real vtable vfunc | `func_va 0x1800bd150`, `size 0x285`, vtable `CNetChan` slot `47` / `0x178` | `func_va 0x286b20`, `size 0x197`, vtable `CNetChan` slot `48` / `0x180` | `/write-vfunc-as-yaml` |

Platform gating: the symbol is produced on **both** platforms. Note the slot differs per platform (Windows 47,
Linux 48) — resolve it from the vtable, do not carry a number across platforms.

## Step 0. Skip targets already produced

If `CNetChan_CanPacket.<platform>.yaml` already exists in the **analyzer-reported artifact module directory** and
parses to a non-empty mapping, skip it — the preprocessor or an earlier fallback wrote it. Never derive the
artifact path from the binary directory; use the directory reported by the analyzer (also readable as
`CS2VIBE_ARTIFACT_DIR`).

## Step 1. Load the CNetChan vtable and confirm the platform

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CNetChan` to obtain the authoritative
`vtable_va`, `vtable_symbol`, and `vtable_entries` for the current build. You need this to assign the vtable
fields in Step 3; do **not** reuse the old `vfunc_offset`/`vfunc_index`.

The `expected_input` for this skill is exactly this `CNetChan_vtable.{platform}.yaml`, so it must already exist
when the fallback runs. If `/get-vtable-from-yaml` errors, **STOP** and report to user.

## Step 2. Locate CNetChan::CanPacket by its unique anchor

Use IDA string xrefs. Enumerate strings exactly as the preprocessor does (C strings, `minlen` = the
`CS2VIBE_STRING_MIN_LENGTH` in effect, 4 in CI):

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, ida_nalt, idc
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
needle = "!CanPacket() - m_bSuppressingTransmit."
for s in strings:
    if needle in str(s):
        ea = s.ea
        print('string', hex(ea), str(s)[:70])
        for xr in idautils.XrefsTo(ea, 0):
            print('   xref', hex(xr.frm), 'in', hex(idc.get_func_attr(xr.frm, idc.FUNCATTR_START)),
                  idc.get_func_name(idc.get_func_attr(xr.frm, idc.FUNCATTR_START)))
"""
```

**Anchor that is unique to the real target** — `"%s: !CanPacket() - m_bSuppressingTransmit."` is referenced by
`CNetChan::CanPacket` and by nothing else (verified on 14191, both platforms).

Resolve each xref `frm` to its containing function. The required containing function start is
`CNetChan_CanPacket`.

If the string is unavailable (e.g. logging compiled out), fall back to the **semantic fingerprint**: a boolean
virtual on `CNetChan` that (a) reads a suppression byte at `this+0x...`, and (b) is immediately adjacent in the
vtable to `UpdateMessageStats`/`IsOverflowed`. Confirm the candidate by Step 3 before emitting.

## Step 2b. Disambiguate against sibling CNetChan members (do not skip)

Several small `CNetChan` members share the generic Linux prologue
`55 48 89 E5 41 54 53 48 89 FB 48 83 EC ?? 80 BF ...`. A candidate is **not** `CanPacket` if it references the
`"UpdateMessageStats, bit counter about to roll over"` string or any `ParseMessagesDemo` string. Confirm
positively by scanning the candidate's own strings:

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, ida_funcs
f = ida_funcs.get_func(0x286b20)  # candidate
strings = idautils.Strings(default_setup=False)
hits = []
for s in strings:
    for x in idautils.XrefsTo(s.ea, 0):
        if f.start_ea <= x.frm < f.end_ea:
            hits.append((hex(x.frm), str(s)[:60])); break
for h in sorted(hits): print(h)
"""
```

The real target must contain the `!CanPacket()` suppression string. If none of the candidates do, **STOP** and
report — the build has been restructured beyond these anchors and the references need extending.

## Step 3. Assign the vtable fields

Look the resolved start up in the `CNetChan` vtable entries obtained in Step 1:

```
mcp__ida-pro-mcp__py_eval code="""
import yaml, os, idaapi
d = os.environ.get('CS2VIBE_ARTIFACT_DIR') or os.path.dirname(idaapi.get_input_file_path())
plat = 'windows' if idaapi.get_input_file_path().endswith('.dll') else 'linux'
v = yaml.safe_load(open(os.path.join(d, f'CNetChan_vtable.{plat}.yaml'), encoding='utf-8'))
ents = {int(str(x),16): int(k) for k, x in v['vtable_entries'].items()}
tgt = 0x0  # <-- resolved CNetChan_CanPacket start
print('vtable_class', v['vtable_class'])
print('match index', [k for k,a in ents.items() if a == tgt])
"""
```

Set:

- `vtable_name = CNetChan_vtable`
- `vfunc_index = <the matching entry index>`
- `vfunc_offset = vfunc_index * 8`

If the resolved start matches **no** vtable entry, the function is not the vtable target — return to Step 2b.
Do **not** emit the previous build's slot.

Rename the function to `CNetChan_CanPacket` if the database does not already name it that way:

```
mcp__ida-pro-mcp__rename batch={"func":[{"addr":"<start>","name":"CNetChan_CanPacket"}]}
```

## Step 4. Generate the signature and write the YAML

1. **ALWAYS** Use SKILL `/generate-signature-for-function` with `addr=<resolved start>` to obtain a fresh,
   validated `func_sig`.
2. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `CNetChan_CanPacket`
   - `func_addr`: the resolved function start
   - `func_sig`: the signature from step 1
   - `vtable_name`: `CNetChan_vtable`
   - `vfunc_offset`: `vfunc_index * 8` (from Step 3)
   - `vfunc_index`: from Step 3

Do not write a partial YAML: all eight fields above are required, and the writer must produce them for the
platform being processed only.

## Failure handling

- `CNetChan_vtable.<platform>.yaml` missing → **STOP** and report (the skill's `expected_input` is absent).
- The `!CanPacket()` anchor resolves to no function → **STOP** and report which anchor failed, so the references
  can be extended. Do not guess an address.
- The resolved target equals `CNetChan_UpdateMessageStats` (i.e. it references the bit-counter string) → **STOP**;
  the search has drifted onto a sibling.
- Never emit the symbol on the wrong platform, and never reuse a previous build's `func_va`/`vfunc_index`.

## Output YAML filenames

Written under the analyzer-reported artifact module directory, one file per platform:

- Windows (`networksystem.dll`): `CNetChan_CanPacket.windows.yaml`
- Linux (`libnetworksystem.so`): `CNetChan_CanPacket.linux.yaml`

## Why this is robust

- The function is located by its **`!CanPacket()` suppression string**, which its vtable neighbours do not
  reference — so the shared generic prologue cannot mislead the search.
- The vtable slot is **derived** from the resolved address, so a vtable reorder is absorbed instead of repeated.
- The cross-check against `UpdateMessageStats` prevents the exact collision that a prologue-anchored search
  previously produced between these two adjacent slots.

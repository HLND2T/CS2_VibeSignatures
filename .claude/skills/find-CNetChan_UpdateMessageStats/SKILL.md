---
name: find-CNetChan_UpdateMessageStats
description: |
  Final-guarantee fallback for the find-CNetChan_UpdateMessageStats preprocessor chain. Recovers
  CNetChan::UpdateMessageStats (its func_va/func_rva/func_size/func_sig plus CNetChan vtable slot) in CS2
  networksystem.dll / libnetworksystem.so.
  Use when the deterministic chain
  (ida_preprocessor_scripts/find-CNetChan_UpdateMessageStats-{noinline,inlined}.py with
  find-CNetChan_UpdateMessageStatsInternal.py) could not produce CNetChan_UpdateMessageStats.{platform}.yaml
  because the stored func_sig no longer matches, the CNetChan vtable was reordered so the old vfunc slot no
  longer resolves, or the
  "CNetChan::UpdateMessageStats, bit counter about to roll over with addition of %d bits, resetting to zero"
  xref string moved.
  Trigger: CNetChan_UpdateMessageStats
disable-model-invocation: true
---

# Find CNetChan_UpdateMessageStats (final-guarantee fallback)

Recover `CNetChan::UpdateMessageStats` in CS2 `networksystem.dll` / `libnetworksystem.so` using IDA Pro MCP tools.

This is the **Agent fallback** for the `find-CNetChan_UpdateMessageStats` chain. The chain emits the symbol from
either the **de-inlined** path (`find-CNetChan_UpdateMessageStats-noinline`, taken when the compiler kept a
standalone wrapper) or the **inlined** path (`find-CNetChan_UpdateMessageStats-inlined`, taken when the body was
folded into the caller and only `find-CNetChan_UpdateMessageStatsInternal` produced the helper). Any of these can
miss on a new build:

- reuse the previous build's `func_sig` — breaks when the prologue is rewritten;
- reuse the previous `vfunc_sig` / vtable slot — breaks when the `CNetChan` vtable is reordered;
- reuse the `"CNetChan::UpdateMessageStats, bit counter about to roll over ..."` xref string — breaks when the
  single call site moves or the literal relocates.

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
- `bin_artifacts/14191/networksystem/CNetChan_UpdateMessageStats.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_UpdateMessageStats.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_UpdateMessageStatsInternal.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_UpdateMessageStatsInternal.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_CanPacket.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_CanPacket.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_SetTimeout.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_SetTimeout.linux.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_vtable.windows.yaml`
- `bin_artifacts/14191/networksystem/CNetChan_vtable.linux.yaml`

## Background — CNetChan::UpdateMessageStats and its decoys

`CNetChan::UpdateMessageStats` is the `CNetChan` virtual that adds a message-group bit count to the channel's
running totals:

- logs
  `"CNetChan::UpdateMessageStats, bit counter about to roll over with addition of %d bits, resetting to zero\n"`
  and resets the counter when the running bit counter would overflow;
- forwards the actual accumulate step through the `CNetworkSystem`/`ILoopMode` indirect call reachable from
  `qword_4F2FB8` (Windows: `qword_...`), i.e. the body ends in an indirect virtual dispatch.

All member accesses are relative to `this` (the first argument — `rcx` on Windows, `rdi` on Linux). The vtable is
`CNetChan`; the function has a body, so its YAML carries **both** `func_*` fields and the vtable slot fields.

> **Decoy — this is the trap that matters, and it is a *cross-symbol* one.** On Linux the compiler emits
> `UpdateMessageStats` as a **thin wrapper** (`sub_287AB0` on 14191: `cmp/jle`, one `jmp` into the real body
> `sub_287380`) whose own prologue does **not** resemble the `UpdateMessageStats` body. The real body
> (`sub_287380`) is the function that references the diagnostic string. A naive prologue-signature search
> (`55 48 89 E5 41 54 53 48 89 FB 48 83 EC 10 80 BF ?? ?? ?? ?? ??`) matches **`CNetChan_CanPacket`**
> (`sub_286B20`) instead — that generic frame template is shared by many small `CNetChan` members. Selecting
> CanPacket writes a wrong address into slot 46 and collides with the real CanPacket product at slot 48. Anchor
> on the string, never on a generic prologue.

## Robustness principle — anchor semantically, not by signature

The old `func_sig` and the old vtable slot are *both* rebuild-fragile — that is exactly what failed. Do not rely
on either to find the function. Instead:

1. Find the function by its **semantic fingerprint** (the diagnostic string below, the roll-over reset logic,
   the indirect dispatch through the network-system singleton).
2. **Disambiguate against the sibling `CNetChan_CanPacket`** (Step 2b) — they are distinct functions with
   adjacent vtable slots and, on some builds, a shared generic prologue.
3. Only once the function is confirmed, derive the vtable slot by **matching the resolved address against the
   `CNetChan` vtable entries** — never by trusting the previous `vfunc_index`.

## Output inventory

`struct_name` is not used (this is a real vtable vfunc, not an interface indirect vcall). Addresses, offsets and
sizes are **reference values from build 14191 — verify against the binary, do not assume**.

| # | Output symbol | Kind | Windows | Linux | Writer skill |
|---|---------------|------|---------|-------|--------------|
| 1 | `CNetChan_UpdateMessageStats` | real vtable vfunc | `func_va 0x1800c6260`, `size 0x172`, vtable `CNetChan` slot `45` / `0x168` | `func_va 0x287ab0`, `size 0x19`, vtable `CNetChan` slot `46` / `0x170` | `/write-vfunc-as-yaml` |

Platform gating: the symbol is produced on **both** platforms. Note the slot differs per platform (Windows 45,
Linux 46) **and the Linux function is a thin wrapper, so its `size` is far smaller than the inner body** — resolve
it from the vtable, do not carry a number across platforms.

## Step 0. Skip targets already produced

If `CNetChan_UpdateMessageStats.<platform>.yaml` already exists in the **analyzer-reported artifact module
directory** and parses to a non-empty mapping, skip it — the preprocessor or an earlier fallback wrote it.
Never derive the artifact path from the binary directory; use the directory reported by the analyzer (also
readable as `CS2VIBE_ARTIFACT_DIR`).

## Step 1. Load the CNetChan vtable and confirm the platform

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CNetChan` to obtain the authoritative
`vtable_va`, `vtable_symbol`, and `vtable_entries` for the current build. You need this to assign the vtable
fields in Step 3; do **not** reuse the old `vfunc_offset`/`vfunc_index`.

The `expected_input` for this skill is exactly this `CNetChan_vtable.{platform}.yaml`, so it must already exist
when the fallback runs. If `/get-vtable-from-yaml` errors, **STOP** and report to user.

## Step 2. Locate the diagnostic string and its enclosing function

Use IDA string xrefs. Enumerate strings exactly as the preprocessor does (C strings, `minlen` = the
`CS2VIBE_STRING_MIN_LENGTH` in effect, 4 in CI):

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, ida_nalt, idc
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
needle = "CNetChan::UpdateMessageStats, bit counter about to roll over"
for s in strings:
    if needle in str(s):
        ea = s.ea
        print('string', hex(ea), str(s)[:70])
        for xr in idautils.XrefsTo(ea, 0):
            print('   xref', hex(xr.frm), 'in', hex(idc.get_func_attr(xr.frm, idc.FUNCATTR_START)),
                  idc.get_func_name(idc.get_func_attr(xr.frm, idc.FUNCATTR_START)))
"""
```

That reference encloses the **real body** (`CNetChan_UpdateMessageStatsInternal`). On Linux this is a *different*
function from the vtable target; on Windows the two coincide (the body is emitted standalone and is itself the
vtable slot).

## Step 2b. Resolve the vtable target — walk callers, then confirm against the vtable

The string-referencing function is the *body*. The **vtable target** is the entry whose slot points at it,
directly or through a thin wrapper:

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, idc, ida_bytes, yaml, os, idaapi
d = os.environ.get('CS2VIBE_ARTIFACT_DIR') or os.path.dirname(idaapi.get_input_file_path())
plat = 'windows' if idaapi.get_input_file_path().endswith('.dll') else 'linux'
v = yaml.safe_load(open(os.path.join(d, f'CNetChan_vtable.{plat}.yaml'), encoding='utf-8'))
ents = {int(str(x),16): int(k) for k, x in v['vtable_entries'].items()}   # addr -> index
body = 0x0  # <-- function found in Step 2
for cand in [body] + [idc.get_func_attr(x.frm, idc.FUNCATTR_START) for x in idautils.XrefsTo(body, 0)]:
    print(hex(cand), idc.get_func_name(cand), '-> vtable index', ents.get(cand))
"""
```

Pick the candidate that **is a `CNetChan` vtable entry**. On Linux that is the thin wrapper, not the body.

**Deliberately avoid** `CNetChan` vtable neighbours that share a generic prologue, in particular
`CNetChan_CanPacket`. A candidate that resolves to the same address as `CNetChan_CanPacket.<platform>.yaml`
(or to the `"!CanPacket() - m_bSuppressingTransmit."` string's function) is **wrong** — return to Step 2.

## Step 3. Assign the vtable fields

From the matching entry: `vtable_name = CNetChan_vtable`, `vfunc_index = <entry index>`,
`vfunc_offset = vfunc_index * 8`. On 14191 that is Windows index 45 / offset `0x168` and Linux index 46 /
offset `0x170`.

If the resolved target matches **no** vtable entry, the function is not the vtable target — return to Step 2b.
Do **not** emit the previous build's slot.

Rename the function to `CNetChan_UpdateMessageStats` if the database does not already name it that way:

```
mcp__ida-pro-mcp__rename batch={"func":[{"addr":"<target>","name":"CNetChan_UpdateMessageStats"}]}
```

## Step 4. Generate the signature and write the YAML

1. **ALWAYS** Use SKILL `/generate-signature-for-function` with `addr=<resolved target>` to obtain a fresh,
   validated `func_sig`. On Linux this signature covers the **wrapper**, so keep it short — do not stretch it to
   reach the body.
2. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with `func_name=CNetChan_UpdateMessageStats`,
   `func_addr=<resolved target>`, the `func_sig` from step 1, `vtable_name=CNetChan_vtable`, and the
   `vfunc_offset`/`vfunc_index` from Step 3.

Do not write a partial YAML: all eight fields (`func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`,
`vtable_name`, `vfunc_offset`, `vfunc_index`) are required, and the writer must produce them for the platform
being processed only.

> Writing the helper: if both the de-inlined and inlined paths are exercised, the `CNetChan_UpdateMessageStats*`
> artifacts must stay mutually consistent — the Internal helper is a distinct symbol with its own (body) address,
> never a re-labelled `CanPacket`.

## Failure handling

- `CNetChan_vtable.<platform>.yaml` missing → **STOP** and report (the skill's `expected_input` is absent).
- The diagnostic string resolves to no function → **STOP** and report which anchor failed, so the references can
  be extended. Do not guess an address.
- The resolved target equals `CNetChan_CanPacket` → **STOP**; the prologue-anchored search has drifted again.
- Never emit the symbol on the wrong platform, and never reuse a previous build's `func_va`/`vfunc_index`.

## Output YAML filenames

Written under the analyzer-reported artifact module directory, one file per platform:

- Windows (`networksystem.dll`): `CNetChan_UpdateMessageStats.windows.yaml`
- Linux (`libnetworksystem.so`): `CNetChan_UpdateMessageStats.linux.yaml`

## Why this is robust

- The function is located by its **diagnostic string**, which `CNetChan_CanPacket` does not reference — so the
  shared generic prologue cannot mislead the search.
- The vtable slot is **derived** from the resolved address, so a vtable reorder is absorbed instead of repeated.
- The Linux wrapper-vs-body distinction is handled explicitly, so a `size`/`sig` mismatch between platforms is
  expected rather than a failure signal.

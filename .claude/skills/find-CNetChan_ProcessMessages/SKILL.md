---
name: find-CNetChan_ProcessMessages
description: |
  Final-guarantee fallback for the find-CNetChan_ProcessMessages preprocessor. Recovers CNetChan::ProcessMessages
  (its func_va/func_rva/func_size/func_sig plus CNetChan vtable slot) in CS2 networksystem.dll / libnetworksystem.so.
  Use when the deterministic preprocessor (ida_preprocessor_scripts/find-CNetChan_ProcessMessages.py) could not
  locate the target because the stored func_sig no longer matches, the CNetChan vtable was reordered so the old
  vfunc slot no longer resolves, and the "NetChan %s ProcessMessages has taken more than ..." xref string yields
  an empty candidate set.
  Trigger: CNetChan_ProcessMessages
disable-model-invocation: true
---

# Find CNetChan_ProcessMessages (final-guarantee fallback)

Recover `CNetChan::ProcessMessages` in CS2 `networksystem.dll` / `libnetworksystem.so` using IDA Pro MCP tools.

This is the **Agent fallback** for the `find-CNetChan_ProcessMessages` skill: it runs only when the preprocessor
returned failure. The preprocessor tries three things and any one of them can miss on a new build:

- reuse the previous build's `func_sig` — breaks when the prologue is rewritten;
- reuse the previous `vfunc_sig` / vtable slot — breaks when `CNetChan`'s vtable is reordered;
- reuse the `"NetChan %s ProcessMessages has taken more than %dms to process %d messages."` xref string — breaks
  when the single call site moves or the string literal relocates.

Your job is to locate the function by **semantic anchors that survive those changes**, then emit the YAML.

## Realworld Function References

Read the platform-relevant real-world YAMLs before searching in IDA. They provide concrete disassembly,
decompiler output, and semantic anchors, and they document the neighboring functions you must distinguish the
target from. Treat their addresses and offsets as reference-build values only; verify every result against the
current binary.

- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemo.windows.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemo.linux.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemoInternal.windows.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseMessagesDemoInternal.linux.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseNetMessageShowFilter.windows.yaml`
- `ida_preprocessor_scripts/references/networksystem/CNetChan_ParseNetMessageShowFilter.linux.yaml`
- `vcall_finder/14141b/g_pNetworkMessages/networksystem/windows/CNetChan_ProcessMessages.yaml`
- `vcall_finder/14141b/g_pNetworkMessages/networksystem/linux/CNetChan_ProcessMessages.yaml`
- `bin_artifacts/14188b/networksystem/CNetChan_ProcessMessages.windows.yaml`
- `bin_artifacts/14188b/networksystem/CNetChan_ProcessMessages.linux.yaml`
- `bin_artifacts/14188b/networksystem/CNetChan_vtable.windows.yaml`
- `bin_artifacts/14188b/networksystem/CNetChan_vtable.linux.yaml`
- `bin_artifacts/14188b/networksystem/CNetChan_ParseMessagesDemo.windows.yaml`
- `bin_artifacts/14188b/networksystem/CNetChan_ParseMessagesDemo.linux.yaml`

## Background — CNetChan::ProcessMessages and its decoys

`CNetChan::ProcessMessages` is the `CNetChan` virtual that drains the incoming net message queue for one channel:

- loops over queued messages, dispatching each by type and logging `"Error processing network message %s! Channel
  is closing!\n"` when the channel is closing;
- enforces the per-frame queue limit, logging
  `"Too many incoming messages on channel (%s) %d remain queued, limit per-frame is %d."` and the sibling
  `"Too many queued messages on channel (%s) %d queued, limit is %d.\n"`;
- runs a watchdog: when processing takes too long it calls `CNetworkSystem_RemoveNetChannel` and logs
  `"[%s] DISCONNECTING. ProcessMessages has taken more than %dms to process %d messages. (Current message type:
  '%s')\n"` and `"NetChan %s ProcessMessages has taken more than %dms to process %d messages. (Current message
  type: '%s')\n"`.

All member accesses are relative to `this` (the first argument — `rcx` on Windows, `rdi` on Linux). The vtable is
`CNetChan`; the function has a body, so its YAML carries **both** `func_*` fields and the vtable slot fields.

> **Decoy — this is the trap that matters.** The watchdog block is **duplicated**: `CNetChan::ProcessMessages`
> also contains the inlined body of its `lambda_1` (`CNetChan::ProcessMessages::<lambda_1>::operator ()`), and on
> Windows that inlined copy lives in a **separate helper function** that references the *same* watchdog strings.
> On 14188b that helper is `sub_1800C1910` (Windows) and it is **not** in the `CNetChan` vtable. Both the real
> target and the lambda reference `"NetChan %s ProcessMessages has taken more than ..."`, `"[%s] DISCONNECTING.
> ProcessMessages has taken more than ..."`, and the `netchan.cpp` / `lambda_1` assert strings. Selecting the
> wrong one writes a helper's address into a vtable slot. Use the disambiguator in Step 2.

## Robustness principle — anchor semantically, not by signature

The old `func_sig` and the old vtable slot are *both* rebuild-fragile — that is exactly what failed. Do not
rely on either to find the function. Instead:

1. Find the function by its **semantic fingerprint** (the logging strings below, the `CNetworkSystem_RemoveNetChannel`
   call, the per-frame queue-limit constants).
2. **Disambiguate against the lambda helper** (Step 2) using the strings that are unique to the real target.
3. Only once the function is confirmed, derive the vtable slot by **matching the resolved address against the
   `CNetChan` vtable entries** — never by trusting the previous `vfunc_index`.

## Output inventory

`struct_name` is not used (this is a real vtable vfunc, not an interface indirect vcall). Addresses, offsets and
sizes are **reference values from build 14188b — verify against the binary, do not assume**.

| # | Output symbol | Kind | Windows | Linux | Writer skill |
|---|---------------|------|---------|-------|--------------|
| 1 | `CNetChan_ProcessMessages` | real vtable vfunc | `func_va 0x1800c0eb0`, `size 0xa52`, vtable `CNetChan` slot `72` / `0x240` | `func_va 0x2982a0`, `size 0xf09`, vtable `CNetChan` slot `73` / `0x248` | `/write-vfunc-as-yaml` |

Platform gating: the symbol is produced on **both** platforms. Note the slot differs per platform (Windows 72,
Linux 73) — resolve it from the vtable, do not carry a number across platforms.

## Step 0. Skip targets already produced

If `CNetChan_ProcessMessages.<platform>.yaml` already exists in the **analyzer-reported artifact module
directory** and parses to a non-empty mapping, skip it — the preprocessor or an earlier fallback wrote it.
Never derive the artifact path from the binary directory; use the directory reported by the analyzer (also
readable as `CS2VIBE_ARTIFACT_DIR`).

`/get-func-from-yaml` reports existence for the function (returns an error when absent).

## Step 1. Load the CNetChan vtable and confirm the platform

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CNetChan` to obtain the authoritative
`vtable_va`, `vtable_symbol`, and `vtable_entries` for the current build. You need this to assign the vtable
fields in Step 3; do **not** reuse the old `vfunc_offset`/`vfunc_index`.

The `expected_input` for this skill is exactly this `CNetChan_vtable.{platform}.yaml`, so it must already exist
when the fallback runs. If `/get-vtable-from-yaml` errors, **STOP** and report to user.

## Step 2. Locate CNetChan::ProcessMessages by its unique anchors

Use IDA string xrefs. Enumerate strings exactly as the preprocessor does (C strings, `minlen` = the
`CS2VIBE_STRING_MIN_LENGTH` in effect, 4 in CI):

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, ida_nalt
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
str_map = {s.ea: str(s) for s in strings}
for needle in ["Error processing network message %s! Channel is closing!",
               "Too many incoming messages on channel (%s)"]:
    for ea, txt in str_map.items():
        if needle in txt:
            print(needle[:40], hex(ea), [hex(x.frm) for x in idautils.XrefsTo(ea, 0)])
            break
"""
```

**Anchors that are unique to the real target** — these two strings are referenced by `CNetChan::ProcessMessages`
and by nothing else (verified on 14188b, both platforms):

- `"Error processing network message %s! Channel is closing!\n"`
- `"Too many incoming messages on channel (%s) %d remain queued, limit per-frame is %d."`

Resolve each xref `frm` to its containing function (that function start is the candidate). The candidate must
appear for **both** anchors; they must agree on a single function start. That start is
`CNetChan_ProcessMessages`.

**Deliberately avoid** the watchdog strings `"NetChan %s ProcessMessages has taken more than ..."` and
`"[%s] DISCONNECTING. ProcessMessages has taken more than ..."` as the *primary* anchor — they are the ones the
preprocessor already failed on, and the lambda helper references them too.

## Step 2b. Disambiguate against the lambda helper (do not skip)

If, and only if, the unique anchors above are unavailable or disagree, fall back to the watchdog strings and
then **separate the real target from the inlined lambda** using these rules (verified on 14188b Windows):

- The **real target** is the function that references **both** `"Error processing network message %s! Channel is
  closing!"` and `"Too many incoming messages on channel (%s) %d remain queued, limit per-frame is %d."`
  (`CNetChan_ProcessMessages` @ `0x1800c0eb0`).
- The **lambda helper** (`sub_1800C1910` on 14188b) references the `netchan.cpp`,
  `CNetChan::ProcessMessages::<lambda_1>::operator ()`, `"false"` and `"Disconnecting netchan because of
  excessive CPU usage /+/ ..."` strings but **neither** of the two unique anchors above.
- Confirm positively by scanning the candidate's **own strings**:

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, ida_funcs
f = ida_funcs.get_func(0x1800c0eb0)  # candidate
strings = idautils.Strings(default_setup=False)
str_map = {s.ea: str(s) for s in strings}
hits = []
for sea, txt in str_map.items():
    for x in idautils.XrefsTo(sea, 0):
        if f.start_ea <= x.frm < f.end_ea:
            hits.append((hex(x.frm), txt[:60])); break
for h in sorted(hits): print(h)
"""
```

- The real target additionally calls **`CNetworkSystem_RemoveNetChannel`** in the watchdog path. A candidate
  that never calls it is the lambda helper, not the target.

If both a candidate and a lambda helper are returned, prefer the one containing the queue-limit strings **and**
the `CNetworkSystem_RemoveNetChannel` call. If only the lambda helper is returned, **STOP** and report — the
build has been restructured beyond these anchors and the references need extending.

## Step 3. Assign the vtable fields

Once the function start is resolved, look it up in the `CNetChan` vtable entries obtained in Step 1:

```
mcp__ida-pro-mcp__py_eval code="""
import yaml, os, idaapi
d = os.environ.get('CS2VIBE_ARTIFACT_DIR') or os.path.dirname(idaapi.get_input_file_path())
plat = 'windows' if idaapi.get_input_file_path().endswith('.dll') else 'linux'
v = yaml.safe_load(open(os.path.join(d, f'CNetChan_vtable.{plat}.yaml'), encoding='utf-8'))
ents = {int(k): int(str(x), 16) for k, x in v['vtable_entries'].items()}
tgt = 0x0  # <-- resolved CNetChan_ProcessMessages start
idx = [k for k, a in ents.items() if a == tgt]
print('vtable_class', v['vtable_class'])
print('match index', idx, 'offset', [hex(i*8) for i in idx])
"""
```

Set:

- `vtable_name = CNetChan`
- `vfunc_index = <the matching entry index>`
- `vfunc_offset = vfunc_index * 8`

If the resolved start matches **no** vtable entry, the function is not the vtable target — return to Step 2b.
Do **not** emit the previous build's slot.

Rename the function to `CNetChan_ProcessMessages` if the database does not already name it that way:

```
mcp__ida-pro-mcp__rename batch={"func":[{"addr":"<start>","name":"CNetChan_ProcessMessages"}]}
```

## Step 4. Generate the signature and write the YAML

1. **ALWAYS** Use SKILL `/generate-signature-for-function` with `addr=<resolved start>` to obtain a fresh,
   validated `func_sig`. (This is a real function with a body — unlike an interface indirect vcall.)
2. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `CNetChan_ProcessMessages`
   - `func_addr`: the resolved function start
   - `func_sig`: the signature from step 1
   - `vtable_name`: `CNetChan`
   - `vfunc_offset`: `vfunc_index * 8` (from Step 3)
   - `vfunc_index`: from Step 3

   If `/write-vfunc-as-yaml` cannot take both a `func_addr` and vtable fields in one call, use
   `/write-func-as-yaml` for the `func_*` fields and then add the vtable fields, matching the field set of the
   14188b ground-truth YAML (`func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`, `vtable_name`,
   `vfunc_offset`, `vfunc_index`). Do not omit the vtable fields — downstream consumers read `vfunc_index`.

Do not write a partial YAML: all eight fields above are required, and the writer must produce them for the
platform being processed only.

## Failure handling

- `CNetChan_vtable.<platform>.yaml` missing → **STOP** and report (the skill's `expected_input` is absent).
- The unique anchors resolve to no function, or only the lambda helper resolves → **STOP** and report which
  anchor failed, so the references can be extended. Do not guess an address.
- Never emit the symbol on the wrong platform, and never reuse a previous build's `func_va`/`vfunc_index`.

## Output YAML filenames

Written under the analyzer-reported artifact module directory, one file per platform:

- Windows (`networksystem.dll`): `CNetChan_ProcessMessages.windows.yaml`
- Linux (`libnetworksystem.so`): `CNetChan_ProcessMessages.linux.yaml`

## Why this is robust

- The function is located by its **queue-limit logging strings**, which the lambda helper does not reference —
  so the duplication that makes the watchdog strings ambiguous cannot mislead the search.
- The vtable slot is **derived** from the resolved address, so a vtable reorder (the failure mode that defeats
  the preprocessor's `vfunc_sig` path) is absorbed instead of repeated.
- A fresh `func_sig` is generated from the located function, so a rewritten prologue (the failure mode that
  defeats the preprocessor's `func_sig` path) is absorbed too.

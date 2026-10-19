---
name: find-CNetworkStringTableContainer_RemoveAllTables
description: |
  Final-guarantee fallback for the find-CNetworkStringTableContainer_RemoveAllTables preprocessor. Recovers
  CNetworkStringTableContainer::RemoveAllTables in CS2 engine2.dll / libengine2.so by anchoring on its debug
  string and intersecting the hits with the CNetworkStringTableContainer vtable, so both the inlined and the
  de-inlined build shapes are covered. Use when the deterministic preprocessor
  (ida_preprocessor_scripts/find-CNetworkStringTableContainer_RemoveAllTables.py) cannot resolve the vfunc
  because the string gained extra call sites or the body moved across the inline boundary.
  Trigger: CNetworkStringTableContainer_RemoveAllTables, CNetworkStringTableContainer::RemoveAllTables
disable-model-invocation: true
---

# Find CNetworkStringTableContainer_RemoveAllTables (final-guarantee fallback)

Recover `CNetworkStringTableContainer::RemoveAllTables` in CS2 `engine2.dll` / `libengine2.so` using IDA Pro
MCP tools. This is the Agent fallback: it runs only when the preprocessor returned failure.

## Realworld Function References

Read the platform-relevant source-owned artifacts before searching in IDA. Treat every address, offset, and
index below as a reference-build value; verify each one against the current binary.

- `bin_artifacts/14191/engine/CNetworkStringTableContainer_vtable.windows.yaml`
- `bin_artifacts/14191/engine/CNetworkStringTableContainer_vtable.linux.yaml`
- `bin_artifacts/14191/engine/CNetworkStringTableContainer_RemoveAllTables.windows.yaml`
- `bin_artifacts/14191/engine/CNetworkStringTableContainer_RemoveAllTables.linux.yaml`
- `ida_preprocessor_scripts/references/engine/CNetworkStringTableContainer_WriteBaselines.windows.yaml`
- `ida_preprocessor_scripts/references/engine/CNetworkStringTableContainer_WriteBaselines.linux.yaml`

The `WriteBaselines` references are sibling methods on the same class; they help confirm you are inside
`CNetworkStringTableContainer` and not in a look-alike container.

## Background — what RemoveAllTables does

`RemoveAllTables` walks the container's table array, releases every live `INetworkStringTable` through its
deleting destructor (slot 0 called with argument `1`), then zeroes the count and frees the array through
`g_pMemAlloc`. Under a debug log channel it first emits:

```
"%s: CNetworkStringTableContainer::RemoveAllTables:  removing %d tables\n"
```

The `%s` is `INetworkStringTableContainer::GetName()`, a trailing accessor that returns the string stored at
`this + 0x28` (`"SV"` on the server container, `"CL"` on the client one). Do not confuse that accessor with the
target — it is a different vtable slot and contains no table-walking loop.

## Robustness principle — anchor on the string, disambiguate with the vtable

The debug string is the stable semantic anchor, but it is **not** unique: call sites get inlined into unrelated
functions over time (on 14191 the Windows build has four string xrefs — the vfunc itself plus
`SV_InstallHLTVStringTableMirrors` and two static initializers). Never accept a "single xref" answer and never
accept the first hit.

The discriminator is the vtable: intersect the string-xref candidate set with
`CNetworkStringTableContainer_vtable`'s entries. Exactly one candidate must survive. This works whether the body
is inlined into the vfunc (14191) or de-inlined behind a string-owning helper (14181), because either way the
vtable slot points at a function that contains — or immediately reaches — the logging call.

## Output inventory

| # | Output symbol | Kind | Windows | Linux | Writer skill |
|---|---------------|------|---------|-------|--------------|
| 1 | `CNetworkStringTableContainer_RemoveAllTables` | real vtable vfunc | index 13 / offset `0x68` | index 14 / offset `0x70` | `/write-vfunc-as-yaml` |
| 2 | `CNetworkStringTableContainer_vtable` | vtable | `expected_input`, not produced here | `expected_input`, not produced here | — |

Platform gating: the target is produced on both platforms. Offsets/indices above are **reference values from
build 14191 — derive them from the current binary, do not assume**.

## Step 0. Skip an existing output

If `CNetworkStringTableContainer_RemoveAllTables.<platform>.yaml` already exists in the active artifact module
directory and parses to a non-empty mapping, skip that platform. Never derive the artifact path from the binary
directory; use the directory reported by the analyzer (also readable as `CS2VIBE_ARTIFACT_DIR`).

## Step 1. Load the container vtable

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CNetworkStringTableContainer` to obtain the
authoritative `vtable_va`, `vtable_size`, `vtable_numvfunc`, and `vtable_entries` for the current build. This
`CNetworkStringTableContainer_vtable.{platform}.yaml` is this skill's `expected_input`, so it must already exist
when the fallback runs. If `/get-vtable-from-yaml` errors, **STOP** and report to the user.

## Step 2. Collect the string-xref candidates

Enumerate C strings and resolve every xref to its containing function. Keep the full set — do not stop at the
first hit:

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, ida_nalt, idc, ida_funcs
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
needle = "CNetworkStringTableContainer::RemoveAllTables:  removing %d tables"
cands = set()
for s in strings:
    if needle in str(s):
        print('string', hex(s.ea), str(s)[:80])
        for xr in idautils.XrefsTo(s.ea, 0):
            f = ida_funcs.get_func(xr.frm)
            if f:
                cands.add(f.start_ea)
                print('   xref', hex(xr.frm), 'in', hex(f.start_ea), idc.get_func_name(f.start_ea))
print('CANDIDATES', [hex(a) for a in sorted(cands)])
"""
```

If the string is missing entirely (logging compiled out on this build), **STOP** and report — the anchor set
must be extended; do not guess an address.

## Step 3. Intersect with the vtable entries

Keep only candidates that are entries of `CNetworkStringTableContainer_vtable`:

```
mcp__ida-pro-mcp__py_eval code="""
import yaml, os, idaapi
d = os.environ.get('CS2VIBE_ARTIFACT_DIR') or os.path.dirname(idaapi.get_input_file_path())
plat = 'windows' if idaapi.get_input_file_path().endswith('.dll') else 'linux'
v = yaml.safe_load(open(os.path.join(d, f'CNetworkStringTableContainer_vtable.{plat}.yaml'), encoding='utf-8'))
entries = {int(str(a), 16): int(k) for k, a in v['vtable_entries'].items()}
cands = {0x0, 0x0}  # <-- paste CANDIDATES from Step 2
print('vtable_numvfunc', v['vtable_numvfunc'])
for c in sorted(cands):
    print(hex(c), '-> vtable index', entries.get(c, 'NOT IN VTABLE'))
"""
```

Exactly one candidate must map to an index. Set:

- `vtable_name = CNetworkStringTableContainer_vtable` — the artifact stem, matching what the
  preprocessor and the tracked `bin_artifacts` YAML use. Do **not** write the bare class name here.
- `vfunc_index = <the matching entry index>`
- `vfunc_offset = vfunc_index * 8`

If zero candidates match, the body is de-inlined behind a helper. Enumerate the functions each candidate calls,
decompile them, and look for the one that returns its first argument (`this`) and performs the table-freeing
loop; then re-run the vtable intersection on that callee. If more than one candidate matches, or the callee
search is ambiguous, **STOP** and report which candidates survived — do not pick one by position.

On reference build 14191 this yields Windows index 13 / offset `0x68` and Linux index 14 / offset `0x70`.

## Step 4. Confirm the candidate is the table-walking vfunc

Decompile the resolved function and confirm both markers:

- a `LoggingSystem_Log` (or equivalent) call passing the `removing %d tables` format;
- a loop over the table array that calls the deleting destructor of each element (`(**elem)(elem, 1)`) and then
  zeroes the count and frees the array.

Reject a candidate that only logs or only frees — it is a sibling method or a stale call site.

Rename the function if the database does not already name it that way:

```
mcp__ida-pro-mcp__rename batch={"func":[{"addr":"<start>","name":"CNetworkStringTableContainer_RemoveAllTables"}]}
```

## Step 5. Generate the signature and write the YAML

1. **ALWAYS** Use SKILL `/generate-signature-for-function` with `addr=<resolved start>` to obtain a fresh,
   validated `func_sig`.
2. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `CNetworkStringTableContainer_RemoveAllTables`
   - `func_addr`: the resolved function start
   - `func_sig`: the signature from step 1
   - `vtable_name`: `CNetworkStringTableContainer_vtable`
   - `vfunc_offset`: `vfunc_index * 8` (from Step 3)
   - `vfunc_index`: from Step 3

Do not write a partial YAML: `func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`, `vtable_name`,
`vfunc_offset`, and `vfunc_index` are all required. Emit only the platform currently being processed.

The `vtable_name` value must be the artifact stem `CNetworkStringTableContainer_vtable`, not the bare class name —
the preprocessor emits that stem and `bin_artifact_contract.py` compares the artifact byte-for-byte against the
canonical form.

## Failure handling

- `CNetworkStringTableContainer_vtable.<platform>.yaml` missing → **STOP** and report (the skill's
  `expected_input` is absent).
- The `removing %d tables` string resolves to no function → **STOP** and report which anchor failed.
- More than one candidate survives the vtable intersection → **STOP** and report the survivors.
- Never emit the symbol on the wrong platform, and never reuse a previous build's `func_va`/`vfunc_index`.

## Output YAML filenames

Written under the analyzer-reported artifact module directory, one file per platform:

- Windows (`engine2.dll`): `CNetworkStringTableContainer_RemoveAllTables.windows.yaml`
- Linux (`libengine2.so`): `CNetworkStringTableContainer_RemoveAllTables.linux.yaml`

## Why this is robust

- The function is anchored by a **class-specific debug string**, then disambiguated by the **vtable entry set**,
  so the extra inline call sites that break a "unique string xref" search cannot mislead it.
- The vtable slot is **derived** from the resolved address, so a vtable reorder is absorbed instead of repeated.
- Following the de-inline boundary covers the case where the string-owning body moves into a helper that
  receives `this` as its first argument.

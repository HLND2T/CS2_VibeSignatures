---
name: find-CEntitySystem_m_entityNames
description: |
  Final-guarantee fallback for the find-CEntitySystem_m_entityNames preprocessor. Recovers
  CEntitySystem::m_entityNames in CS2 server.dll / libserver.so by decompiling
  CEntitySystem_AddEntityToNameMap and recognizing its ordered-map/RB-tree lookup whether the lookup helper is
  emitted as a separate function or inlined into the predecessor. Use when
  ida_preprocessor_scripts/find-CEntitySystem_m_entityNames.py cannot resolve the member because the
  LLM_DECOMPILE reference shape moved across the inline boundary.
  Trigger: CEntitySystem_m_entityNames
disable-model-invocation: true
---

# Find CEntitySystem_m_entityNames (final-guarantee fallback)

Recover `CEntitySystem::m_entityNames` in CS2 `server.dll` / `libserver.so` using IDA Pro MCP tools. This is
the Agent fallback for `find-CEntitySystem_m_entityNames`; it runs only after the preprocessor fails. Produce
the missing struct-offset YAML even when the anonymous ordered-map lookup helper was inlined into
`CEntitySystem_AddEntityToNameMap` and the expected `sub_*(this + off + 8, this + off, &key)` call no longer
exists.

## Realworld Function References

Read the platform-relevant YAML before searching in IDA. Treat every address and offset as a reference-build
value only and verify it against the current binary.

- `ida_preprocessor_scripts/references/server/CEntitySystem_AddEntityToNameMap.windows.yaml`
- `ida_preprocessor_scripts/references/server/CEntitySystem_AddEntityToNameMap.linux.yaml`

The Linux reference includes both the historical lookup helper pseudocode and the predecessor pseudocode. Its
`a1 + 2800` annotation identifies the map base (`0xAF0`); `0xAF8` identifies its `m_Elements` storage subobject.
Never copy a reference displacement without checking the current function.

## Background and semantic fingerprint

`CEntitySystem_AddEntityToNameMap(this, identity)` reads the entity-name key from `identity + 0x18`, returns
when it is null, looks the key up in `this->m_entityNames`, and either appends the entity handle to an existing
`CEntityNameList` or allocates a new 32-byte list and inserts it into the ordered map.

Identify this map operation by the whole fingerprint, not by an anonymous helper name:

- the key comes from `identity + 0x18`;
- RB-tree node indices use `0xFFFF` as the null sentinel;
- nodes are 24 bytes and compare their key field against the entity-name key;
- the duplicate path calls `_UtlRBTree_FailedInsertDuplicate` or references the assertion text
  `Found existing value when inserting into tree`;
- the new-value path allocates 32 bytes for the `CEntityNameList` and inserts the entity handle into it.

The first argument is the owning `CEntitySystem *`: `rcx` on Windows and `rdi` on Linux, commonly copied to a
callee-saved register such as `rbx` or `r12`. Confirm every candidate displacement is relative to that pointer.

## Robustness principle: accept both compiler shapes

Do not search for the literal name `sub_1E59BD0`; anonymous names and function boundaries change per build.

1. Decompile `CEntitySystem_AddEntityToNameMap` and first look for a separate ordered-map/RB-tree lookup call.
   Historical Linux builds pass values equivalent to `this + off + 8`, `this + off`, and `&key`. Windows may
   materialize `this + off`, then pass `this + off + 8` plus a small context object containing the base and key.
2. If that call is absent, assume the helper was inlined. Locate the direct RB-tree traversal using the
   semantic fingerprint above. The usual container field cluster is:
   - node count at `this + off + 8`;
   - allocation/capacity flags at `this + off + 0xA`;
   - node-storage pointer at `this + off + 0x10`;
   - root index at `this + off + 0x18`;
   - nearby free-list/tree bookkeeping at `this + off + 0x1A` and `this + off + 0x1C`.
3. Infer one common `off` from at least three of those accesses and verify it against the insertion path. Prefer
   a direct `lea reg, [this + off]` that feeds tree insertion/bookkeeping. On Linux 14168, for example, the
   inlined traversal accesses `this + 0xB08`, `this + 0xAFA`, and `this + 0xB00`, then materializes
   `this + 0xAF8`; the field cluster implies map base `off = 0xAF0`, while the materialized pointer is the storage subobject.
4. If the predecessor calls a plausible lookup helper instead, decompile it and follow the arguments. Recover
   `off` from the caller's `this`-relative expressions; helper-local offsets are offsets within the map, not
   within `CEntitySystem`.

Reject candidates that do not participate in the entity-name-key lookup and subsequent existing/new
`CEntityNameList` branches.

## Output inventory

Offsets are ground-truth reference values from build 14168 and must be re-derived for the current binary.

| Output symbol | Kind | Windows | Linux | Writer skill |
|---------------|------|---------|-------|--------------|
| `CEntitySystem_m_entityNames` | struct member | `0xAF0` | `0xAF0` | `/write-structoffset-as-yaml` |

Platform gating: emit this output on both Windows and Linux. `struct_name` is `CEntitySystem`, `member_name`
is `m_entityNames`, and the map size is `32`.

## Step 0. Skip an existing output

Determine the current platform from the input binary. If `CEntitySystem_m_entityNames.<platform>.yaml` already
exists beside it and parses to a non-empty mapping, skip the target because the preprocessor or an earlier run
already produced it. List YAMLs with:

```
mcp__ida-pro-mcp__py_eval code="import idaapi, os; d=os.path.dirname(idaapi.get_input_file_path()); print('\n'.join(sorted(f for f in os.listdir(d) if f.endswith('.yaml'))))"
```

## Step 1. Load and decompile the predecessor

**ALWAYS** Use SKILL `/get-func-from-yaml` with
`func_name=CEntitySystem_AddEntityToNameMap` to obtain `func_va`. If it errors, **STOP** and report the missing
prerequisite.

Then decompile and, when needed, disassemble the function:

```
mcp__ida-pro-mcp__decompile addr="<CEntitySystem_AddEntityToNameMap.func_va>"
mcp__ida-pro-mcp__disasm addr="<CEntitySystem_AddEntityToNameMap.func_va>"
```

Track the `this` register and apply the separate-helper/inlined-helper procedure above. Do not fail merely
because no three-argument lookup call appears.

## Step 2. Generate the signature and write YAML

Prefer an instruction that directly contains `off`, such as `lea reg, [this + off]`, in the verified map
lookup/insertion block.

1. **ALWAYS** Use SKILL `/generate-signature-for-structoffset` with the instruction address and the resolved
   `struct_offset=off`. The target instruction must keep the full displacement fixed and
   `offset_sig_disp=0`.
2. **ALWAYS** Use SKILL `/write-structoffset-as-yaml` with:
   - `struct_name=CEntitySystem`
   - `member_name=m_entityNames`
   - `offset=<resolved off>`
   - `size=8`
   - `offset_sig=<generated struct_sig>`
   - `offset_sig_disp=0`

If the current compiler never materializes `this + off` directly and only accesses `off + 2`, `off + 8`, or
`off + 0x10`, still write the verified base `offset` with `size=8`; set `offset_sig=None` and
`offset_sig_disp=None` rather than generating a signature for the wrong subfield displacement.

## Failure handling

- Missing `CEntitySystem_AddEntityToNameMap.<platform>.yaml` -> **STOP** and report the prerequisite.
- Fewer than three coherent container-field accesses and no trustworthy separate-helper call -> **STOP** and
  report the unresolved member; do not guess from the 14168 reference value.
- A non-unique offset signature -> try another direct `this + off` instruction, then write offset-only if the
  member is otherwise proven.
- Never emit a Windows result while analyzing Linux or a Linux result while analyzing Windows.

## Output YAML filename

Write beside the binary as `CEntitySystem_m_entityNames.windows.yaml` for `server.dll` or
`CEntitySystem_m_entityNames.linux.yaml` for `libserver.so`.

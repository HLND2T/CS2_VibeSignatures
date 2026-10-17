---
name: find-RegisterSchemaTypeOverride_CEntityHandle
description: Locate the CEntityHandle to ehandle schema type registration thunk in CS2 server.dll or libserver.so using IDA Pro MCP, including warm IDBs with undefined functions and stale signatures. Use when the corresponding finder preprocessor fails or this symbol is requested directly.
disable-model-invocation: true
---

# Find RegisterSchemaTypeOverride_CEntityHandle

Find the **regular registration thunk** that passes the schema type name
`CEntityHandle` and its network alias `ehandle` to the network messages interface.
The virtual registration method it calls is a separate symbol.

## Realworld Function References

Read the reference for the active platform before identifying the function:

- Windows: `ida_preprocessor_scripts/references/server/RegisterSchemaTypeOverride_CEntityHandle.windows.yaml`
- Linux: `ida_preprocessor_scripts/references/server/RegisterSchemaTypeOverride_CEntityHandle.linux.yaml`

These are semantic examples from an older build. Addresses, byte patterns,
argument count, CRC constants, registers, and virtual offsets can change. Some
builds omit the CRC argument entirely. Do not require the old `0x110` slot.

## Session and output contract

Read `.claude/skills/generate-signature-for-function/references/mcp-ida-session.md`
(relative to the repository root). Follow its shared session rules:
call `idb_list`, reuse the assigned server database, and pass its `database` id
to subsequent calls. Open a database only if the target is absent. Never use
`open_file`, switch to another module, or close a session owned by the runner.
Save and close with `save=True` any session you open yourself.

The active input determines the platform. Write exactly one artifact:

| Input | Required output |
| --- | --- |
| `server.dll` | `RegisterSchemaTypeOverride_CEntityHandle.windows.yaml` |
| `libserver.so` | `RegisterSchemaTypeOverride_CEntityHandle.linux.yaml` |

Use `CS2VIBE_ARTIFACT_DIR` as the output directory when set. Otherwise use the
repository's `bin_artifacts/<GAMEVER>/server/` directory, inferring GAMEVER from
the assigned binary path. Never write symbol YAML into `bin/` or cache storage.

Before analysis, parse the expected output if it exists. Skip only when it is
a nonempty mapping with the exact `func_name`, positive `func_size`, valid
`func_va`/`func_rva`, and a nonempty unique `func_sig` matching the current
function entry. If validator feedback requests a repair, repair it even if the
file exists. An empty, malformed, or stale file is unfinished work.

## Locate and verify the thunk

1. Search for the exact strings `CEntityHandle` and `ehandle`. Keep all string
   occurrences and their raw xrefs, including those outside known functions.
   `idautils.Strings(default_setup=False)` preserves the current string list;
   do not silently reset its configuration. Inspect raw string bytes when the
   list does not contain the expected literal.
2. Inspect the instructions around their xrefs. Find the small code sequence
   that supplies **both exact strings to the same virtual call or tail jump**,
   loading the interface receiver from a global pointer and then its vtable.
   Windows typically passes the receiver in RCX and the type name in RDX;
   Linux typically uses RDI and RSI. Derive the remaining arguments from the
   current instructions rather than the old prototype.
3. Exclude constructors, logging code, reflection metadata, and larger
   registration setup functions. A neighboring thunk can also pass `ehandle`
   but register `CHandle`; it is not the target. A string substring match or
   an identical indirect-jump sequence alone is insufficient evidence.
4. Read the full candidate through its return/tail jump. Verify the receiver,
   exact type/alias pair, and call arguments before assigning the name. If
   several candidates remain semantically indistinguishable, stop with a
   `<skill_error>` describing the ambiguity; do not guess.

## Recover undefined code conservatively

A warm IDB may have decoded instructions and string xrefs without a function.
An empty function-xref search therefore does not prove the target is absent.

- From a raw string xref, walk instruction heads backward within the same
  executable segment. Inspect incoming code references to the candidate entry.
  A `lea` in a static initializer can take the address of the registration
  thunk without calling it directly.
- If that initializer is also undefined, inspect `.preinit_array`,
  `.init_array`, or `.fini_array`. A pointer-sized, aligned, in-bounds entry
  whose stored value equals the code entry is evidence for defining it. An
  arbitrary data pointer alone is insufficient.
- Define only an evidenced entry outside existing functions. Use `define_func`
  or `ida_funcs.add_func`, then verify `get_func(raw_xref).start_ea` equals that
  entry and the function covers the complete registration sequence. Never
  delete, split, or expand unrelated existing functions to force a match.
- Inspect tool errors and actual boundaries if definition fails. Keep the
  evidence and report an error if safe recovery cannot be established.

**MCP Python scope:** `py_eval` can execute with distinct globals and persistent
locals. Use ordinary loops for code that reads newly assigned loop variables;
avoid comprehensions or nested helpers capturing such variables. On Python
3.11, `get_operand_value(xref.frm, i)` inside a comprehension can read an old
global `xref`, even while the outer loop is visiting a different reference.
Build a fresh local result on every call; never rely on earlier `result` values.

## Generate and write the artifact

1. Rename the verified function `RegisterSchemaTypeOverride_CEntityHandle`.
2. Use `/generate-signature-for-function` at the verified entry, and validate
   that the pattern has exactly one match in the active module at that entry.
   Similar adjacent thunks can have the same fully wildcarded instruction
   shape. If so, retain the minimum operand bytes needed to distinguish them,
   keeping instruction boundaries and rechecking uniqueness. Never copy the
   signature or address from another version, or extend into unrelated code
   to manufacture a unique prefix.
3. Use `/write-func-as-yaml` with the verified address, exact function name,
   and validated signature. Ensure it writes to the output directory above.
   Produce these regular-function fields:

   ```yaml
   func_name: RegisterSchemaTypeOverride_CEntityHandle
   func_va: '<current entry VA>'
   func_rva: '<entry VA minus current image base>'
   func_size: '<current function size>'
   func_sig: '<validated unique signature>'
   ```

4. Reopen the YAML, verify all five fields against the active database, and
   recheck its signature. Do not add `vfunc_index`, `vfunc_offset`, or a virtual
   method address: the downstream `find-INetworkMessages_RegisterSchemaTypeOverride`
   consumes this thunk separately to determine the virtual slot.
5. Report the exact artifact path, function address, and the semantic and
   signature checks performed. Report unrecoverable failures with
   `<skill_error>reason</skill_error>` instead of claiming success.

# Undefined Function Xref Recovery Design

## Context

`preprocess_func_xrefs_via_mcp` resolves functions by intersecting candidate
sets collected from string xrefs, direct address xrefs, signature matches, and
optional vtable entries. The current `_collect_xref_func_*` helpers only keep
addresses for which IDA already returns `idaapi.get_func(...)`.

This fails when IDA has valid code and xrefs but has not created a function for
the target block. One observed case is
`CSteamworksGameStats_OnReceivedSessionID` in Linux `libclient.so`: the string
`Steamworks Stats: %s Received %s session id: %llu` is referenced from code
inside `loc_12B0AA0`, but IDA did not mark `loc_12B0AA0` as a function. A
separate `lea rax, loc_12B0AA0` proves that the block has an explicit code-entry
reference and should be recoverable automatically.

## Goal

Add a conservative, reusable recovery layer so all `_collect_xref_func_*`
helpers can recover function starts for code addresses that are not yet covered
by an IDA function.

The fix must apply to:

- `_collect_xref_func_starts_for_string`
- `_collect_xref_func_starts_for_ea`
- `_collect_xref_func_starts_for_signature`

## Non-Goals

- Do not add special-case logic for `CSteamworksGameStats_OnReceivedSessionID`.
- Do not define a function solely because the current matched address is not
  covered by an existing function.
- Do not perform aggressive function discovery across large ranges.
- Do not change `preprocess_func_xrefs_via_mcp` intersection semantics.

## Approach

Use a shared normalization helper that maps an arbitrary code address to a
function start:

1. If `idaapi.get_func(addr)` already exists, return that function start.
2. If the address is not in a function, conservatively recover the function that
   should cover it.
3. After recovery, query `idaapi.get_func(original_addr)` again.
4. Return a function start only when the original address is actually covered by
   the newly defined function.

The recovery path scans upward from the original address by at most `0x200`
bytes. For each probed address, it checks whether that address is explicitly
referenced as a code entry by an instruction inside an existing valid IDA
function. The referencing instruction's mnemonic must be one of:

- `call`
- `jmp`
- `lea`

Only one unique candidate entry is allowed. If there are zero candidates,
multiple candidates, invalid code, or a collision with an already defined
different function, recovery fails conservatively.

## Helper Design

Add a small constant:

```python
UNDEFINED_FUNC_RECOVERY_BACKTRACK_LIMIT = 0x200
```

Add a helper equivalent to:

```python
async def _normalize_func_start_for_code_addr(session, code_addr, debug=False):
    ...
```

Responsibilities:

- Run IDA-side logic through `py_eval` to inspect the address and discover a
  unique recoverable function-entry candidate.
- When recovery is needed and a unique entry exists, call MCP
  `define_func` with that entry address.
- Re-run IDA-side verification against the original code address.
- Return an integer function start or `None`.

The helper should not expose IDA-specific intermediate details to callers. The
collector helpers should only decide whether to add the returned function start
to their result set.

## Collector Integration

`_collect_xref_func_starts_for_string` should collect each string-reference
instruction address, then pass each `xref.frm` through the shared normalization
helper.

`_collect_xref_func_starts_for_ea` should do the same for each address-reference
instruction address.

`_collect_xref_func_starts_for_signature` should pass each byte-pattern match
address through the same helper.

Each collector keeps its existing return contract:

- `set[int]` on successful collection
- `None` only for collection/tool failure paths where that was already the
  caller-visible behavior
- empty set when no valid function candidates survive

## Conservative Safety Rules

The recovery helper must follow these rules:

- Never treat the original matched address as a function entry unless the upward
  scan independently proves it is the unique `call`/`jmp`/`lea` entry candidate.
- Stop after scanning `0x200` bytes upward.
- If upward scanning reaches an address already belonging to another function,
  abandon recovery.
- Accept only `call`, `jmp`, and `lea` references.
- Require the referencing instruction to be inside an existing valid IDA
  function.
- Require the referenced operand target to equal the probed entry candidate.
- Require exactly one unique entry candidate before calling `define_func`.
- After `define_func`, verify that the original address is covered by the
  recovered function.

## Error Handling and Debug Output

Tool failures must not crash the preprocessor. If `py_eval` or `define_func`
fails, the helper returns `None` for that address. With `debug=True`, it should
print concise recovery diagnostics, such as:

- no recoverable entry candidate
- multiple recoverable entry candidates
- recovery collided with an existing function
- `define_func` failed
- recovered function does not cover the original address

## Testing Plan

Add targeted tests in `tests/test_ida_analyze_util.py`.

The tests should verify:

- Existing function addresses still return their current function start.
- Undefined addresses with one unique upward `call`/`jmp`/`lea` entry candidate
  call `define_func` and return the recovered function start.
- Undefined addresses with multiple entry candidates do not call `define_func`.
- Undefined addresses that hit another function while scanning upward do not call
  `define_func`.
- References from instructions not covered by an existing valid IDA function are
  ignored and do not create recovery candidates.
- The generated IDA-side logic contains the `0x200` backtrack limit and the
  `call`/`jmp`/`lea` mnemonic filter.
- All three `_collect_xref_func_*` helpers pass their raw code addresses through
  the shared normalization helper.

## Acceptance Criteria

- `CSteamworksGameStats_OnReceivedSessionID` can be found through the existing
  `FUNC_XREFS` string when IDA leaves the containing code block undefined but a
  unique `call`/`jmp`/`lea` entry reference exists from an instruction inside an
  existing valid IDA function.
- String, direct-address, and signature xref collectors all share the same
  recovery behavior.
- No collector creates tail functions by defining a function at an arbitrary
  matched address.
- Recovery is skipped whenever the conservative uniqueness or boundary checks
  fail.

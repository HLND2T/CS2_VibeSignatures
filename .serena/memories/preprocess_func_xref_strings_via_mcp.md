# preprocess_func_xref_strings_via_mcp

## Overview
`preprocess_func_xref_strings_via_mcp` locates a function by searching for known string literals in the binary and resolving cross-references to them. It intersects the sets of functions referencing each string to find the unique target, then auto-generates a `func_sig` via `preprocess_gen_func_sig_via_mcp`.

## Responsibilities
- For each provided xref string, use MCP `py_eval` to search IDA's string list for exact matches and collect all code xrefs.
- Resolve the owning function of each xref via `idaapi.get_func()`.
- Intersect the function sets across all strings; require exactly one common function.
- Generate a shortest-unique `func_sig` for the resolved function via `preprocess_gen_func_sig_via_mcp`.
- Return standard function YAML data (`func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`).

## Files Involved (no line numbers)
- ida_analyze_util.py
- ida_preprocessor_scripts/*.py (callers)

## Architecture
1. **Input validation**: require non-empty `xref_strings` list.
2. **String search loop**: for each string in `xref_strings`:
   - Build a `py_eval` script that iterates `idautils.Strings()`, matches the exact string, collects `XrefsTo` code references, and resolves owning functions.
   - Parse the returned list of function start addresses (hex strings).
   - If no functions reference the string, fail immediately.
3. **Set intersection**: intersect all per-string function sets. Require exactly 1 common function.
4. **Signature generation**: call `preprocess_gen_func_sig_via_mcp` to produce a unique `func_sig`.
   - If sig generation fails, fall back to basic func info (func_va, func_rva, func_size) without `func_sig`.
5. **Return**: dict with `func_name`, `func_va`, `func_rva`, `func_size`, and optionally `func_sig`.

## Integration with preprocess_common_skill
- `preprocess_common_skill` accepts a new `func_xref_strings` parameter: list of `(func_name, xref_strings_list)` tuples.
- For func targets, `preprocess_func_sig_via_mcp` is tried first (reusing old signatures). If it fails and the func has an entry in `func_xref_strings`, the xref-string fallback is attempted.
- Functions that appear only in `func_xref_strings` (not in `func_names`) are also processed automatically.

## Dependencies
- Internal: `parse_mcp_result`, `preprocess_gen_func_sig_via_mcp`
- MCP tools: `py_eval`
- IDA Python APIs (via py_eval): `idautils.Strings`, `idautils.XrefsTo`, `idaapi.get_func`

## Notes
- String matching is exact (not substring).
- Uniqueness is strict: if 0 or 2+ functions reference all strings, the lookup fails.
- The py_eval script safely escapes backslash and double-quote characters in search strings.
- When `func_sig` generation fails, the function still returns basic metadata (without `func_sig`) so the YAML can still be written, but downstream consumers may need to re-generate the signature later.

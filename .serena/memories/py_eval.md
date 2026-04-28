# py_eval

## Overview
IDA MCP `py_eval` executes dynamically generated Python scripts using a dual-namespace model similar to `exec(code, exec_globals, exec_locals)`. Functions defined in the generated script perform global lookup against `exec_globals`, and do not automatically see top-level constants, imported modules, or helper names written into `exec_locals`.

## Repeated Pitfall
- If a `py_eval` script defines top-level constants or imports first, then defines helper functions, and the helpers reference those names, runtime execution can raise `NameError`.
- Typical error: `NameError: name 'SINGLE_MNEMS' is not defined`, even when `SINGLE_MNEMS` was already defined before the function in the script text.
- This problem does not affect only constants; it also affects `FLOAT_EPSILON`, `DOUBLE_EPSILON`, `MEM_OP_TYPES`, imported module names, and other helpers.

## Correct Pattern
- After defining all top-level constants, imports, and helper functions, insert the following before actually calling helpers or entering the main logic:

```python
globals().update(locals())
```

- Recommended position: after the last helper definition and before `out = {}` / the main loop / the main execution logic.
- Do not patch only the currently missing name; this is a systemic issue caused by the `exec(..., globals, locals)` scope model.

## Verification
- Add test assertions for every newly introduced large `py_eval` generated script to verify that the generated code contains `globals().update(locals())`.
- For regressions related to float-xref filtering, the current targeted commands are:

```bash
python -m unittest tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_filter_func_addrs_by_float_xrefs_keeps_xref_matches_and_excludes_hits
python -m unittest tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport tests.test_ida_preprocessor_scripts.TestFindCcsPlayerMovementServicesProcessMovement
```

## Related Files
- `ida_analyze_util.py` - generates `py_eval` scripts in multiple places; any new helper/constant additions must follow this bridging pattern.
- `tests/test_ida_analyze_util.py` - should cover whether generated scripts contain `globals().update(locals())`.

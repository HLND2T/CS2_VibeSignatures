---
title: binsync_force_push_manifest
type: note
permalink: cs2-vibesignatures/binsync-force-push-manifest
---

# BinSync push manifest + fork-only force_push_all

## Purpose
`push_binsync_symbols.py` + `headless_force_push.py` push IDA symbols to per-binary BinSync Git remotes (best-effort, CI step `binsync-push` in `build-on-self-runner.yml`). Originally `headless_force_push.py` did a `collect_artifacts` dump of **every** function/global/type/segment in the IDB — for engine2.dll that was 789 functions + 394 comments, and ~16k artifacts for big modules (scenesystem = 37k), making the step take minutes and bloating remotes with auto-named (`sub_*`/`unknown_libname_*`/`HandlerRoutine`) junk and IDA auto-comments (`Microsoft VisualC v7/14 64bit runtime`, `Trap to Debugger`, stack-var arg names).

## Fix: manifest-driven selective push
- `push_binsync_symbols.collect_manifest_symbols(root, gamever, config)` walks `configs/{gamever}.yaml` `modules[].symbols[]`, keeps only `category` in {`func`,`vfunc`,`gv`}, and reads the target address from the generated `{symbol}.{platform}.yaml` — `func_rva` for funcs/vfuncs, `gv_rva` for globals. These are already in BinSync's lifted/RVA form (Windows rva = va - 0x180000000; Linux rva == va). Output: `{"module/platform": {"functions":[int], "globals":[int]}}`.
- Per binary, it writes a temp JSON manifest and invokes `headless_force_push.py <bin> --push --artifacts-file <manifest>`.
- `headless_force_push.py` gained `--artifacts-file`; when set it calls `controller.force_push_all(func_addrs, global_addrs, [], [], use_decompilation=...)` — i.e. **empty types and segments**.
- Symbols whose YAML has no `func_rva`/`gv_rva` are skipped. This is correct and expected: 55 engine Windows `vfunc`-category symbols are vtable-slot-only (only `vfunc_sig` + `vfunc_index`, e.g. `ISource2GameClients_ClientSettingsChanged`) and cannot be pushed as standalone functions.
- Real 14174 counts: 1839 functions + 733 globals across 16 binaries (vs. full-dump).

## Windows lift bias (CRITICAL: declib first-segment base != PE image base)
YAML `*_rva` = `va - image_base` (0x180000000 for these PEs; 0 for ELF). But declib's `binary_base_addr` = `get_first_segment_base()` = **lowest-address IDA segment VA** — for a PE that's `.text` at `image_base + first_section_rva` (0x1000), NOT the image base. So declib's lifted function/global key = `va - (image_base + 0x1000)` = `rva - 0x1000` on Windows, while on Linux (ELF loads at vaddr 0) key == `rva`. **The manifest MUST send `rva - first_section_rva` on Windows** or BinSync's `_collect_force_push_functions`/`_collect_force_push_globals` silently skip almost everything (engine2.dll went from 256 → 14 funcs, 115 → 8 globals; networksystem.dll 27 → 0). Fix lives in `push_binsync_symbols.py`: `_pe_first_section_rva()` parses the PE section table, `_first_segment_lift_bias(binary_path)` returns 0x1000/0 for PE/ELF, and `collect_manifest_symbols` subtracts the bias from each YAML `*_rva`. A handful of funcs matched pre-fix because their IDB `start_ea` had been offset +0x1000 (IDB shows `sub_1800A0ED0` for YAML va `0x18009fed0`), coincidentally canceling the bias.

## Fork-only API (critical gotcha)
`BSController.force_push_all(func_addrs, global_addrs, type_names, segment_names, use_decompilation)` **only exists in the HLND2T/binsync fork** (commit e229614 "Add force_push_all single-commit helper"), NOT in upstream `binsync/binsync` nor PyPI `binsync==5.15.3`. Upstream/pypi only have `force_push_functions`, `force_push_global_vars`, `force_push_types`, `force_push_segments` (each its own commit). `force_push_all` collects funcs + their contained comments (via `_force_push_function_comments`) + globals + types + segments into ONE commit. The self-hosted runner's standalone `python` interpreter (the `--python` passed to `push_binsync_symbols.py`) MUST have the HLND2T fork installed from source (see `docs/en/requirements.md`), or `force_push_all` raises AttributeError.

## Comments: no user/auto flag available
The `Comment` artifact (declib 4.5.0) has only `addr/comment/func_addr/decompiled` — `decompiled` tracks the IDA comment *slot* (hexrays user cmt vs disasm/function-header cmt), NOT whether the text is user-authored vs IDA-auto. Auto-comments (`Microsoft VisualC ... runtime`, `switch jump`, stack-var names from decompiler) are mixed with real ones in `deci.comments`, so the current manifest approach still pushes auto-comments for the selected functions. Truly filtering IDA-auto comments is not possible through this API; it would need IDA-side classification. The big win already comes from (a) dropping types+segments and (b) pushing only declared functions rather than the whole IDB.

## Involved files
- `push_binsync_symbols.py` — `collect_manifest_symbols`, `_pe_first_section_rva`, `_first_segment_lift_bias`, `build_manifest`, per-binary `--artifacts-file` invocation.
- `headless_force_push.py` — `force_push_selected`, `load_manifest`, `--artifacts-file`.
- `init_gamebin.py` — `iter_configured_binaries` yields `(module_name, platform, binary_path)`; `configured_binary_paths` now delegates to it.
- `tests/test_push_binsync_symbols.py` (registered in `run_test_suite.py` UNIT_MODULES).

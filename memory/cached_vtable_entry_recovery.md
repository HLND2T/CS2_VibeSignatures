---
title: cached_vtable_entry_recovery
type: note
permalink: cs2-vibesignatures/cached-vtable-entry-recovery
---

# Cached vtable entry recovery

## Trigger
Inherited getters report `failed to query function info`, or caller/vtable intersections are empty despite valid current vtable YAMLs. Issues #1176–#1183 and #1186–#1192 share this symptom on 14192.

## Root cause and constraints
The vtable producer defines IDA functions while resolving entries. Reusing its YAML skips those IDB side effects. A vtable entry can therefore contain valid executable instructions while `get_func(entry)` returns None. Missing func_sig on a short inherited getter is intentional and is not evidence that the function was removed. Address deduplication in candidate sets also does not measure vtable length.

## Correct approach
`ida_analyze_util._recover_vtable_entries_via_mcp` checks each cached entry against the live 64-bit vtable pointer, executable segment and code flags. It defines only code owned by no function, verifies the exact recovered entry and leaves existing functions untouched. Inherited-slot lookup retries metadata; xref lookup recomputes the candidate intersection once. Do not infer semantic identity from a previous version's slot alone.

## Verification
`tests/test_vtable_entry_recovery.py` executes the remote Python against IDA stubs, covering stale pointers, data/non-executable addresses, existing function interiors, definition failure and both consuming resolver paths. Real-MCP replays with empty old-signature maps cover the affected Windows/Linux finders. The detailed 14192 evidence is in `docs/ida_validation_failure-14192.md`.

## Scope
Cached vtable artifacts in inherited-vfunc and xref/vtable preprocessors. This recovery neither changes tracked vtable bytes nor deletes or splits IDA functions.

## Agent fallback pointer
For the 16 affected targets from issues #1176–#1192 (excluding the dependency-only #1184), matching `.claude/skills/find-<target>/SKILL.md` files provide semantic IDA recovery, platform/output inventories and safe cached-vtable boundary handling; use `-skip_pp -oldgamever none` with an external artifact root to validate this path. The two `-inlined` skill names retain their suffix while their output symbols omit it.

Agent-only verification must remove each selected output immediately before its isolated run and require positive preprocessing-skip, Agent-start and success log markers. Exit code zero alone may mean the existing output was skipped; keep deletion confined to the checkout-external scratch artifact root. All 30 applicable 14192 platform/target combinations passed and reproduced the source-owned YAML bytes; see the detailed evidence document above.

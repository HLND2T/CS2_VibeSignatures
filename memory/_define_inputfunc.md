---
title: _define_inputfunc
type: note
permalink: cs2-vibesignatures/define-inputfunc
---

# _define_inputfunc

## Overview
`ida_preprocessor_scripts/_define_inputfunc.py` locates entity-input handlers from a static `.data`
descriptor: exact-match the name string in the IDA string list, take its `.data` xref as the
descriptor start, read the qword at `handler_ptr_offset`, require it in `.text`, then generate
`func_sig`. Entry: `preprocess_define_inputfunc_skill(target_name, input_name, handler_ptr_offset, ...)`.

## Descriptor layouts
- Legacy `DEFINE_INPUTFUNC` (<= 14181): name = bare input name (`TestActivator`), handler at `+0x10`
  (`DEFINE_INPUTFUNC_HANDLER_PTR_OFFSET`). Handler ABI `(CBaseEntity*, InputData_t&)`.
- `_API` input registration (>= 14182): name = qualified schema name (`CBaseFilter_API::TestActivator`),
  handler at `+0x48` (`API_INPUT_HANDLER_PTR_OFFSET`). Layout: `+0x00` qualified name, `+0x08` display
  name, `+0x10` empty string, `+0x18/+0x20` parameter-type callbacks, `+0x38` flags `0x200010100`,
  `+0x48` handler.
- The `_API` handler is a new-ABI wrapper `(?, ?, ?, ctx, args)`: activator from `ctx+0x10`, entity
  resolved from `args+8`. Never publish it under a legacy symbol name — downstream hooks use the old
  prototype. Emit a new `<Class>_API_<Input>` symbol instead (precedent: `ShowHudHint` ->
  `CEnvHudHint_API_ShowHudHint`).
- On windows the legacy input body is often inlined into the `_API` wrapper, so "legacy inner body"
  retargeting is not generally possible.

## Consumers
- `_API` (the only active layout): `find-CBaseFilter_API_TestActivator`,
  `find-CGamePlayerEquip_API_TriggerForAllPlayers`, `find-CGamePlayerEquip_API_TriggerForActivatedPlayer`.
- Legacy layout consumers are gone from 14182+: the three legacy `find-C*_Input*` scripts were rewritten
  to `preprocess_common_skill` + `xref_signatures` on the body each `_API` wrapper forwards to, because
  CS2Fixes hooks the legacy body rather than the wrapper. `find-ShowHudHint` (legacy helper consumer)
  has been disabled since 14168.
- `find-CGameMoney_m_DataMap` only reuses the normalization/`_call_py_eval_json` utilities; it is not a
  handler consumer.

## Notes
- Every failure path prints a `Preprocess:` reason under `-debug` (issue #1061). Keep new early returns
  diagnosable; silent `return False` made the 14182 breakage cost several IDA probe rounds.
- Verification: `tests/test_define_inputfunc_preprocessor.py`, `TestDefineInputFuncContracts` in
  `tests/test_ida_preprocessor_contracts_commands.py`.

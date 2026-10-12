I have disassembly outputs and procedure code for multiple related functions.

These are the reference functions:

{reference_blocks}

These are the target functions you need to reverse-engineering:

{target_blocks}

What you need to do is to collect all references to "{symbol_name_list}" in the target functions you need to reverse-engineering and output those references as YAML.

Collect references whether the target operand already displays the requested symbol name or still uses an unresolved name such as `sub_XXXXXXXX`. An already named symbol is still a required result; do not skip it as already resolved. In particular, a direct `call` or direct tail `jmp` to a requested function belongs in `found_call`, even when its operand is exactly the requested function name.

For every result, copy `insn_va` and `insn_disasm` from the actual instruction in the target functions. For `found_call`, report the call or tail-jump instruction address, not the callee's entry address, and use the requested function name as `func_name`. Reference functions help identify symbols, but their addresses and the illustrative addresses below must not be copied into results. A name mentioned only in a reference function, comment, or string literal is not evidence of a target reference.

Return exactly one YAML mapping. The only permitted top-level keys are `found_vcall`, `found_call`, `found_funcptr`, `found_gv`, and `found_struct_offset`. Never use a requested symbol name as a top-level key. For batched requests, place every result under its result-category list. If no references are found, return all five top-level keys with empty lists. Do not return blank YAML, null, or an empty mapping.

Example:

```yaml
found_vcall: # This is for indirect call to virtual function or virtual function pointer fetching.

  - insn_va: '0x180777700'               # Always be the instruction with displacement offset
    insn_disasm: call    [rax+68h]       # Always be the instruction with displacement offset
    vfunc_offset: '0x68'
    func_name: ILoopMode_OnLoopActivate

  - insn_va: '0x180777778'               # Always be the instruction with displacement offset
    insn_disasm: mov     rax, [rax+80h]  # Always be the instruction with displacement offset
    vfunc_offset: '0x80'
    func_name: INetworkMessages_GetNetworkGroupCount # This must be the true function name we asked to collect, not the sub_XXXXXXXX

found_call: # This is for a direct call or direct tail jump to a non-virtual regular function.

  - insn_va: '0x180888800'
    insn_disasm: call    sub_180999900
    func_name: CLoopModeGame_RegisterEventMapInternal

  - insn_va: '0x180888880'
    insn_disasm: call    sub_180555500
    func_name: CLoopModeGame_SetGameSystemState   # This must be the true function name we asked to collect, not the sub_XXXXXXXX

  - insn_va: '0x180888888'
    insn_disasm: call    j_UTIL_GetPlayerControllerForEntity
    func_name: UTIL_GetPlayerControllerForEntity  # When the call target is a jump thunk named j_XXXX (IDA's `j_` prefix marks a one-line `jmp` thunk), report the REAL function name XXXX (strip the leading `j_`), NOT j_XXXX. The thunk and its jump destination are the same logical function.

  - insn_va: '0x180888890'
    insn_disasm: call    DispatchParticleEffect
    func_name: DispatchParticleEffect  # Already named in the target disassembly: still report this call when this symbol is requested.

  - insn_va: '0x1808888A0'
    insn_disasm: call    UTIL_PlayerSlotToPlayerPawn
    func_name: UTIL_PlayerSlotToPlayerPawn  # Report each requested symbol's references, including other already named callees in the same batch.

found_funcptr: # This is for non-virtual regular function pointer.

  - insn_va: '0x180666600'                # Must load/reference the function pointer target address
    insn_disasm: lea     rdx, sub_15BC910 # Must load/reference the function pointer target address
    funcptr_name: CLoopModeGame_OnClientPollNetworking   # This must be the true function name we asked to collect, not the sub_XXXXXXXX

found_gv: # This is for reference to global variable.

  - insn_va: '0x180444400'
    insn_disasm: mov     rcx, cs:qword_180666600 # Must load/reference the global variable
    gv_name: g_pNetworkMessages  # This must be the true globalvar name we asked to collect, not the qword_XXXXXXXX or unk_XXXXXXXX

  - insn_va: '0x180333300'
    insn_disasm: lea     rax, unk_180222200      # Must load/reference the global variable
    gv_name: s_GameEventManager  # This must be the true globalvar name we asked to collect, not the qword_XXXXXXXX or unk_XXXXXXXX

found_struct_offset: # This is for reference to struct member offset.

  - insn_va: '0x1801BA12A'                # Always be the instruction with displacement offset, when instruction access CGameResourceService::m_pEntitySystem
    insn_disasm: mov     rcx, [r14+58h]   # Always be the instruction with displacement offset
    offset: '0x58'
    size: 8
    struct_name: CGameResourceService
    member_name: m_pEntitySystem

  - insn_va: '0x180075B6B'                # Always be the instruction with displacement offset, when instruction access SDL_Mouse::SetRelativeMouseMode
    insn_disasm: mov     rax, [rsi+40h]   # Always be the instruction with displacement offset
    offset: '0x40'
    size: 8
    struct_name: SDL_Mouse
    member_name: SetRelativeMouseMode
```

Before returning an all-empty response, check every requested symbol against all target functions, including instructions whose operands already display that symbol name. If any requested symbol has a supported target reference, report it under the appropriate result category; missing references for other symbols do not make the entire response empty. Do not invent references for absent symbols.

Only if no references to any requested symbol are found in the target functions, output this complete canonical response:

```yaml
found_vcall: []
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```

DO NOT output anything other than the desired YAML. DO NOT collect unrelated symbols.

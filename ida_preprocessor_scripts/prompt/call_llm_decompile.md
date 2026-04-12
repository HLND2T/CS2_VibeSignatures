You are a reverse engineering expert. I have disassembly outputs and procedure code of the same function.

This is the function for reference:

**Disassembly for Reference**

```c
{disasm_for_reference}
```

**Procedure code for Reference**

```c
{procedure_for_reference}
```

This is the function you need to reverse-engineering:

**Disassembly to reverse-engineering**

```c
{disasm_code}
```

**Procedure code to reverse-engineering**

```c
{procedure}
```

Please collect all references to "{symbol_name_list}" in the function you need to reverse-engineering and output those references as YAML.
`found_vcall` is for indirect call to virtual function. the `insn_disasm` and `insn_va` must be the instruction with displacement offset.
`found_call` is for direct call to regular non-virtual function.
`found_funcptr` is for reference to function pointer. the `insn_disasm` and `insn_va` must be the instruction that loads or references the function pointer target address, not a later use-site such as `call reg`.
`found_gv` is for reference to global variable.
`found_struct_offset` is for reference to struct offset. the `insn_disasm` and `insn_va` must be the instruction with displacement offset.

Example:

```yaml
found_vcall:
  - insn_va: '0x180777700'               # Always be the instruction with displacement offset
    insn_disasm: call    [rax+68h]       # Always be the instruction with displacement offset
    vfunc_offset: '0x68'
    func_name: ILoopMode_OnLoopActivate
  - insn_va: '0x180777778'               # Always be the instruction with displacement offset
    insn_disasm: mov     rax, [rax+80h]  # Always be the instruction with displacement offset
    vfunc_offset: '0x80'
    func_name: INetworkMessages_GetNetworkGroupCount
found_call:
  - insn_va: '0x180888800'
    insn_disasm: call    sub_180999900
    func_name: CLoopModeGame_RegisterEventMapInternal
  - insn_va: '0x180888880'
    insn_disasm: call    sub_180555500
    func_name: CLoopModeGame_SetGameSystemState
found_funcptr:
  - insn_va: '0x180666600'                # Must load/reference the function pointer target address
    insn_disasm: lea     rdx, sub_15BC910 # Must load/reference the function pointer target address
    funcptr_name: CLoopModeGame_OnClientPollNetworking
found_gv:
  - insn_va: '0x180444400'
    insn_disasm: mov     rcx, cs:qword_180666600
    gv_name: s_GameEventManager
found_struct_offset:
  - insn_va: '0x1801BA12A'                # Always be the instruction with displacement offset
    insn_disasm: mov     rcx, [r14+58h]   # Always be the instruction with displacement offset
    offset: '0x58'
    size: 8
    struct_name: CGameResourceService
    member_name: m_pEntitySystem
```

If nothing found, output an empty YAML. DO NOT output anything other than the desired YAML. DO NOT collect unrelated symbols.

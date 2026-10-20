Identify the direct call to ICvar_RegisterConVar_Impl inside RegisterConVar.

Reference functions:

{reference_blocks}

Target functions:

{target_blocks}

RegisterConVar builds a registration record containing the name, flags, type,
default value, and output-reference pointers. ICvar_RegisterConVar_Impl consumes
that record, either registering it through ICvar or appending it to the pending
registration list. On a build where that body is inlined, there is no direct
helper call and an empty result is correct.

Inspect the target instructions for a direct call or tail jump passing that
registration record. An operand already named ICvar_RegisterConVar_Impl is
positive evidence: report that instruction even though IDA already knows its
name. Do not return an empty result for an already named direct call. Use the
instruction address from the target, never the callee entry or a reference
address. Do not report RegisterConVar itself, type-trait accessors, allocators,
logging, TLS initialization, or the indirect ICvar virtual call as this helper.

Return exactly one YAML mapping with these five keys. Put the helper's direct
call instruction in found_call with func_name: ICvar_RegisterConVar_Impl,
insn_va, and insn_disasm copied from the target. Leave the other lists empty.
If the helper body is inlined and no direct call exists, leave all lists empty.

found_vcall: []
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []

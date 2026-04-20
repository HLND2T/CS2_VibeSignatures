创建一个不依赖LLM的，程序化实现的 preprocessor script:  ida_preprocessor_scripts/find-IGameSystem_GamePostInit.py 用于从IGameSystem_LoopPostInitAllSystems 里提取slot-only的IGameSystem_GamePostInit信息：func_name + vfunc_offset + vfunc_index + vtable_name

Windows:

```
bool __fastcall IGameSystem_LoopPostInitAllSystems(__int64 a1, __int64 a2)
{
  int v4; // eax
  __int64 v5; // rbx
  _QWORD *ThreadLocalStoragePointer; // rax
  __int64 v7; // rsi
  __int64 v8; // rdi
  char v9; // bl
  _QWORD v11[5]; // [rsp+20h] [rbp-28h] BYREF

  COM_TimestampedLog("%s:  IGameSystem::LoopPostInitAllSystems(start)\n", "SV");
  v4 = dword_181B22580;
  v11[2] = a1;
  v5 = 0;
  byte_181D8C5FB = 0;
  v11[3] = a2;
  if ( dword_181B22580 < 0 )
  {
    ThreadLocalStoragePointer = NtCurrentTeb()->ThreadLocalStoragePointer;
    v11[1] = 0;
    if ( dword_181D8C680 > *(_DWORD *)(ThreadLocalStoragePointer[TlsIndex] + 520LL) )
    {
      sub_181486994(&dword_181D8C680);
      if ( dword_181D8C680 == -1 )
      {
        qword_181D8C678 = (__int64)off_181B22688[0];
        sub_181486928(&dword_181D8C680);
      }
    }
    v11[0] = qword_181D8C678;
    v4 = GameSystem_OnGamePostInit(v11);
    dword_181B22580 = v4;
  }
  if ( IGameSystem_LoopPostInitAllSystems_pEventDispatcher )
  {
    if ( dword_181D8C548 > v4 )
    {
      v7 = *(int *)(qword_181D8C550 + 24LL * v4);
      v8 = qword_181D8C550 + 24LL * v4;
      if ( v7 > 0 )
      {
        do
          GameSystem_OnGamePostInit(*(_QWORD *)(*(_QWORD *)(v8 + 8) + 8 * v5++));
        while ( v5 < v7 );
      }
    }
  }
  v9 = byte_181D8C5FB;
  byte_181D8C5FB = 0;
  COM_TimestampedLog("%s:  IGameSystem::LoopPostInitAllSystems(finish)\n", "SV");
  return v9 == 0;
}
```

```
.text:00000001805000C0                                     IGameSystem_LoopPostInitAllSystems proc near
.text:00000001805000C0                                                                             ; CODE XREF: CLoopModeGame_LoopInit+FCD↓p
.text:00000001805000C0                                                                             ; CLoopModeGame_ReceivedServerInfo+439↓p
.text:00000001805000C0                                                                             ; DATA XREF: ...
.text:00000001805000C0
.text:00000001805000C0                                     var_28          = qword ptr -28h
.text:00000001805000C0                                     var_20          = qword ptr -20h
.text:00000001805000C0                                     var_18          = qword ptr -18h
.text:00000001805000C0                                     var_10          = qword ptr -10h
.text:00000001805000C0                                     arg_0           = qword ptr  8
.text:00000001805000C0                                     arg_8           = qword ptr  10h
.text:00000001805000C0
.text:00000001805000C0 48 89 5C 24 10                                      mov     [rsp+arg_8], rbx
.text:00000001805000C5 57                                                  push    rdi
.text:00000001805000C6 48 83 EC 40                                         sub     rsp, 40h
.text:00000001805000CA 48 8B FA                                            mov     rdi, rdx
.text:00000001805000CD 48 8B D9                                            mov     rbx, rcx
.text:00000001805000D0 48 8D 15 A1 47 03 01                                lea     rdx, aSv_2      ; "SV"
.text:00000001805000D7 48 8D 0D 6A 73 0B 01                                lea     rcx, aSIgamesystemLo_5 ; "%s:  IGameSystem::LoopPostInitAllSystem"...
.text:00000001805000DE FF 15 D4 E4 01 01                                   call    cs:COM_TimestampedLog
.text:00000001805000E4 8B 05 96 24 62 01                                   mov     eax, cs:dword_181B22580
.text:00000001805000EA 48 89 5C 24 30                                      mov     [rsp+48h+var_18], rbx
.text:00000001805000EF 33 DB                                               xor     ebx, ebx
.text:00000001805000F1 C6 05 03 C5 88 01 00                                mov     cs:byte_181D8C5FB, 0
.text:00000001805000F8 48 89 7C 24 38                                      mov     [rsp+48h+var_10], rdi
.text:00000001805000FD 85 C0                                               test    eax, eax
.text:00000001805000FF 79 48                                               jns     short loc_180500149
.text:0000000180500101 8B 0D 49 A3 B5 01                                   mov     ecx, cs:TlsIndex
.text:0000000180500107 65 48 8B 04 25 58 00 00 00                          mov     rax, gs:58h
.text:0000000180500110 BA 08 02 00 00                                      mov     edx, 208h
.text:0000000180500115 48 89 5C 24 28                                      mov     [rsp+48h+var_20], rbx
.text:000000018050011A 48 8B 04 C8                                         mov     rax, [rax+rcx*8]
.text:000000018050011E 8B 04 02                                            mov     eax, [rdx+rax]
.text:0000000180500121 39 05 59 C5 88 01                                   cmp     cs:dword_181D8C680, eax
.text:0000000180500127 0F 8F A4 00 00 00                                   jg      loc_1805001D1
.text:000000018050012D
.text:000000018050012D                                     loc_18050012D:                          ; CODE XREF: IGameSystem_LoopPostInitAllSystems+124↓j
.text:000000018050012D                                                                             ; IGameSystem_LoopPostInitAllSystems+144↓j
.text:000000018050012D 48 8B 05 44 C5 88 01                                mov     rax, cs:qword_181D8C678
.text:0000000180500134 48 8D 4C 24 20                                      lea     rcx, [rsp+48h+var_28]
.text:0000000180500139 48 89 44 24 20                                      mov     [rsp+48h+var_28], rax
.text:000000018050013E E8 61 35 FE FF                                      call    GameSystem_OnGamePostInit
.text:0000000180500143 89 05 37 24 62 01                                   mov     cs:dword_181B22580, eax
.text:0000000180500149
.text:0000000180500149                                     loc_180500149:                          ; CODE XREF: IGameSystem_LoopPostInitAllSystems+3F↑j
.text:0000000180500149 48 39 1D A0 C4 88 01                                cmp     cs:IGameSystem_LoopPostInitAllSystems_pEventDispatcher, rbx
.text:0000000180500150 74 4D                                               jz      short loc_18050019F
.text:0000000180500152 39 05 F0 C3 88 01                                   cmp     cs:dword_181D8C548, eax
.text:0000000180500158 7E 45                                               jle     short loc_18050019F
.text:000000018050015A 48 98                                               cdqe
.text:000000018050015C
.text:000000018050015C                                     loc_18050015C:                          ; DATA XREF: .rdata:00000001819892B0↓o
.text:000000018050015C                                                                             ; .rdata:00000001819892C0↓o ...
.text:000000018050015C 48 89 74 24 50                                      mov     [rsp+48h+arg_0], rsi
.text:0000000180500161 48 8D 0C 40                                         lea     rcx, [rax+rax*2]
.text:0000000180500165 48 8B 05 E4 C3 88 01                                mov     rax, cs:qword_181D8C550
.text:000000018050016C 48 63 34 C8                                         movsxd  rsi, dword ptr [rax+rcx*8]
.text:0000000180500170 48 8D 3C C8                                         lea     rdi, [rax+rcx*8]
.text:0000000180500174 48 85 F6                                            test    rsi, rsi
.text:0000000180500177 7E 21                                               jle     short loc_18050019A
.text:0000000180500179 0F 1F 80 00 00 00 00                                nop     dword ptr [rax+00000000h]
.text:0000000180500180
.text:0000000180500180                                     loc_180500180:                          ; CODE XREF: IGameSystem_LoopPostInitAllSystems+D8↓j
.text:0000000180500180 48 8B 4F 08                                         mov     rcx, [rdi+8]
.text:0000000180500184 48 8D 54 24 30                                      lea     rdx, [rsp+48h+var_18]
.text:0000000180500189 48 8B 0C D9                                         mov     rcx, [rcx+rbx*8]
.text:000000018050018D E8 12 35 FE FF                                      call    GameSystem_OnGamePostInit
.text:0000000180500192 48 FF C3                                            inc     rbx
.text:0000000180500195 48 3B DE                                            cmp     rbx, rsi
.text:0000000180500198 7C E6                                               jl      short loc_180500180
.text:000000018050019A
.text:000000018050019A                                     loc_18050019A:                          ; CODE XREF: IGameSystem_LoopPostInitAllSystems+B7↑j
.text:000000018050019A 48 8B 74 24 50                                      mov     rsi, [rsp+48h+arg_0]
.text:000000018050019F
.text:000000018050019F                                     loc_18050019F:                          ; CODE XREF: IGameSystem_LoopPostInitAllSystems+90↑j
.text:000000018050019F                                                                             ; IGameSystem_LoopPostInitAllSystems+98↑j
.text:000000018050019F                                                                             ; DATA XREF: ...
.text:000000018050019F 0F B6 1D 55 C4 88 01                                movzx   ebx, cs:byte_181D8C5FB
.text:00000001805001A6 48 8D 15 CB 46 03 01                                lea     rdx, aSv_2      ; "SV"
.text:00000001805001AD 48 8D 0D CC 72 0B 01                                lea     rcx, aSIgamesystemLo_6 ; "%s:  IGameSystem::LoopPostInitAllSystem"...
.text:00000001805001B4 C6 05 40 C4 88 01 00                                mov     cs:byte_181D8C5FB, 0
.text:00000001805001BB FF 15 F7 E3 01 01                                   call    cs:COM_TimestampedLog
.text:00000001805001C1 84 DB                                               test    bl, bl
.text:00000001805001C3 48 8B 5C 24 58                                      mov     rbx, [rsp+48h+arg_8]
.text:00000001805001C8 0F 94 C0                                            setz    al
.text:00000001805001CB 48 83 C4 40                                         add     rsp, 40h
.text:00000001805001CF 5F                                                  pop     rdi
.text:00000001805001D0 C3                                                  retn
.text:00000001805001D1                                     ; ---------------------------------------------------------------------------
.text:00000001805001D1
.text:00000001805001D1                                     loc_1805001D1:                          ; CODE XREF: IGameSystem_LoopPostInitAllSystems+67↑j
.text:00000001805001D1 48 8D 0D A8 C4 88 01                                lea     rcx, dword_181D8C680
.text:00000001805001D8 E8 B7 67 F8 00                                      call    sub_181486994
.text:00000001805001DD 83 3D 9C C4 88 01 FF                                cmp     cs:dword_181D8C680, 0FFFFFFFFh
.text:00000001805001E4 0F 85 43 FF FF FF                                   jnz     loc_18050012D
.text:00000001805001EA 48 8B 05 97 24 62 01                                mov     rax, cs:off_181B22688
.text:00000001805001F1 48 8D 0D 88 C4 88 01                                lea     rcx, dword_181D8C680
.text:00000001805001F8 48 89 05 79 C4 88 01                                mov     cs:qword_181D8C678, rax
.text:00000001805001FF E8 24 67 F8 00                                      call    sub_181486928
.text:0000000180500204 E9 24 FF FF FF                                      jmp     loc_18050012D
.text:0000000180500204                                     IGameSystem_LoopPostInitAllSystems endp
```

```
__int64 __fastcall GameSystem_OnGamePostInit(__int64 a1)
{
  return (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)a1 + 40LL))(a1);// 0x28 = 40LL = IGameSystem_GamePostInit
}
```

```
.text:00000001804E36A4                                     ; __int64 __fastcall GameSystem_OnGamePostInit(__int64)
.text:00000001804E36A4                                     GameSystem_OnGamePostInit proc near     ; CODE XREF: IGameSystem_LoopPostInitAllSystems+7E↓p
.text:00000001804E36A4                                                                             ; IGameSystem_LoopPostInitAllSystems+CD↓p ...
.text:00000001804E36A4 48 8B 01                                            mov     rax, [rcx]
.text:00000001804E36A7 FF 60 28                                            jmp     qword ptr [rax+28h] ; 0x28 = 40LL = IGameSystem_GamePostInit
.text:00000001804E36A7                                     GameSystem_OnGamePostInit endp
```

Linux:

```
__int64 __fastcall IGameSystem_LoopPostInitAllSystems(unsigned __int64 a1, signed __int64 a2)
{
  int v2; // eax
  int *v3; // r13
  __int64 v4; // r12
  __int64 v5; // r12
  __int64 v6; // rbx
  __int64 v7; // rdi
  int v8; // ebx
  __m128i inserted; // [rsp-60h] [rbp-68h] BYREF
  __m128i v11; // [rsp-50h] [rbp-58h] BYREF
  _QWORD v12[9]; // [rsp-40h] [rbp-48h] BYREF

  inserted = _mm_insert_epi64((__m128i)a1, a2, 1);
  sub_9802C0("%s:  IGameSystem::LoopPostInitAllSystems(start)\n", "SV");
  v2 = dword_235E65C;
  byte_24D9D99 = 0;
  v11 = _mm_load_si128(&inserted);
  if ( dword_235E65C < 0 )
  {
    v12[1] = 0;
    v12[0] = off_217A8E0;
    v2 = sub_DD4690(v12, 41, 0);
    dword_235E65C = v2;
  }
  if ( IGameSystem_LoopPostInitAllSystems_pEventDispatcher )
  {
    if ( (int)qword_24D9DD0 > v2 )
    {
      v3 = (int *)(qword_24D9DD8 + 24LL * v2);
      v4 = *v3;
      if ( (int)v4 > 0 )
      {
        v5 = 8 * v4;
        v6 = 0;
        do
        {
          v7 = *(_QWORD *)(*((_QWORD *)v3 + 1) + v6);
          v6 += 8;
          (*(void (__fastcall **)(__int64, __m128i *))(*(_QWORD *)v7 + 40LL))(v7, &v11);// 0x28 = 40LL = IGameSystem_GamePostInit
        }
        while ( v6 != v5 );
      }
    }
  }
  v8 = (unsigned __int8)byte_24D9D99;
  byte_24D9D99 = 0;
  sub_9802C0("%s:  IGameSystem::LoopPostInitAllSystems(finish)\n", "SV");
  return v8 ^ 1u;
}
```

```
.text:0000000000DD4720                                     ; __int64 __fastcall IGameSystem_LoopPostInitAllSystems(unsigned __int64, signed __int64)
.text:0000000000DD4720                                     IGameSystem_LoopPostInitAllSystems proc near
.text:0000000000DD4720                                                                             ; CODE XREF: CLoopModeGame_ReceivedServerInfo+1BC↓p
.text:0000000000DD4720                                                                             ; CLoopModeGame_LoopInitInternal+B3E↓p
.text:0000000000DD4720 55                                                  push    rbp
.text:0000000000DD4721 66 48 0F 6E C7                                      movq    xmm0, rdi
.text:0000000000DD4726 31 C0                                               xor     eax, eax
.text:0000000000DD4728 48 89 E5                                            mov     rbp, rsp
.text:0000000000DD472B 41 57                                               push    r15
.text:0000000000DD472D 66 48 0F 3A 22 C6 01                                pinsrq  xmm0, rsi, 1
.text:0000000000DD4734 41 56                                               push    r14
.text:0000000000DD4736 4C 8D 3D 2A 22 AE FF                                lea     r15, aSv        ; "SV"
.text:0000000000DD473D 41 55                                               push    r13
.text:0000000000DD473F 48 8D 3D 2A 42 B4 FF                                lea     rdi, aSIgamesystemLo_5 ; "%s:  IGameSystem::LoopPostInitAllSystem"...
.text:0000000000DD4746 4C 89 FE                                            mov     rsi, r15
.text:0000000000DD4749 41 54                                               push    r12
.text:0000000000DD474B 53                                                  push    rbx
.text:0000000000DD474C 48 83 EC 38                                         sub     rsp, 38h
.text:0000000000DD4750 0F 29 45 A0                                         movaps  xmmword ptr [rbp-60h], xmm0
.text:0000000000DD4754 E8 67 BB BA FF                                      call    sub_9802C0
.text:0000000000DD4759 8B 05 FD 9E 58 01                                   mov     eax, cs:dword_235E65C
.text:0000000000DD475F C6 05 33 56 70 01 00                                mov     cs:byte_24D9D99, 0
.text:0000000000DD4766 66 0F 6F 45 A0                                      movdqa  xmm0, xmmword ptr [rbp-60h]
.text:0000000000DD476B 0F 29 45 B0                                         movaps  xmmword ptr [rbp-50h], xmm0
.text:0000000000DD476F 85 C0                                               test    eax, eax
.text:0000000000DD4771 0F 88 89 00 00 00                                   js      loc_DD4800
.text:0000000000DD4777
.text:0000000000DD4777                                     loc_DD4777:                             ; CODE XREF: IGameSystem_LoopPostInitAllSystems+109↓j
.text:0000000000DD4777 48 83 3D 21 56 70 01 00                             cmp     cs:IGameSystem_LoopPostInitAllSystems_pEventDispatcher, 0
.text:0000000000DD477F 74 49                                               jz      short loc_DD47CA
.text:0000000000DD4781 39 05 49 56 70 01                                   cmp     dword ptr cs:qword_24D9DD0, eax
.text:0000000000DD4787 7E 41                                               jle     short loc_DD47CA
.text:0000000000DD4789 48 98                                               cdqe
.text:0000000000DD478B 48 8D 14 40                                         lea     rdx, [rax+rax*2]
.text:0000000000DD478F 48 8B 05 42 56 70 01                                mov     rax, cs:qword_24D9DD8
.text:0000000000DD4796 4C 8D 2C D0                                         lea     r13, [rax+rdx*8]
.text:0000000000DD479A 4D 63 65 00                                         movsxd  r12, dword ptr [r13+0]
.text:0000000000DD479E 45 85 E4                                            test    r12d, r12d
.text:0000000000DD47A1 7E 27                                               jle     short loc_DD47CA
.text:0000000000DD47A3 4C 8D 75 B0                                         lea     r14, [rbp-50h]
.text:0000000000DD47A7 49 C1 E4 03                                         shl     r12, 3
.text:0000000000DD47AB 31 DB                                               xor     ebx, ebx
.text:0000000000DD47AD 0F 1F 00                                            nop     dword ptr [rax]
.text:0000000000DD47B0
.text:0000000000DD47B0                                     loc_DD47B0:                             ; CODE XREF: IGameSystem_LoopPostInitAllSystems+A8↓j
.text:0000000000DD47B0 49 8B 45 08                                         mov     rax, [r13+8]
.text:0000000000DD47B4 4C 89 F6                                            mov     rsi, r14
.text:0000000000DD47B7 48 8B 3C 18                                         mov     rdi, [rax+rbx]
.text:0000000000DD47BB 48 83 C3 08                                         add     rbx, 8
.text:0000000000DD47BF 48 8B 07                                            mov     rax, [rdi]
.text:0000000000DD47C2 FF 50 28                                            call    qword ptr [rax+28h] ; 0x28 = 40LL = IGameSystem_GamePostInit
.text:0000000000DD47C5 4C 39 E3                                            cmp     rbx, r12
.text:0000000000DD47C8 75 E6                                               jnz     short loc_DD47B0
.text:0000000000DD47CA
.text:0000000000DD47CA                                     loc_DD47CA:                             ; CODE XREF: IGameSystem_LoopPostInitAllSystems+5F↑j
.text:0000000000DD47CA                                                                             ; IGameSystem_LoopPostInitAllSystems+67↑j ...
.text:0000000000DD47CA 0F B6 1D C8 55 70 01                                movzx   ebx, cs:byte_24D9D99
.text:0000000000DD47D1 4C 89 FE                                            mov     rsi, r15
.text:0000000000DD47D4 31 C0                                               xor     eax, eax
.text:0000000000DD47D6 C6 05 BC 55 70 01 00                                mov     cs:byte_24D9D99, 0
.text:0000000000DD47DD 48 8D 3D 44 D2 B4 FF                                lea     rdi, aSIgamesystemLo_6 ; "%s:  IGameSystem::LoopPostInitAllSystem"...
.text:0000000000DD47E4 E8 D7 BA BA FF                                      call    sub_9802C0
.text:0000000000DD47E9 48 83 C4 38                                         add     rsp, 38h
.text:0000000000DD47ED 89 D8                                               mov     eax, ebx
.text:0000000000DD47EF 5B                                                  pop     rbx
.text:0000000000DD47F0 83 F0 01                                            xor     eax, 1
.text:0000000000DD47F3 41 5C                                               pop     r12
.text:0000000000DD47F5 41 5D                                               pop     r13
.text:0000000000DD47F7 41 5E                                               pop     r14
.text:0000000000DD47F9 41 5F                                               pop     r15
.text:0000000000DD47FB 5D                                                  pop     rbp
.text:0000000000DD47FC C3                                                  retn
.text:0000000000DD47FC                                     ; ---------------------------------------------------------------------------
.text:0000000000DD47FD 0F 1F 00                                            align 20h
.text:0000000000DD4800
.text:0000000000DD4800                                     loc_DD4800:                             ; CODE XREF: IGameSystem_LoopPostInitAllSystems+51↑j
.text:0000000000DD4800 48 8D 05 D9 60 3A 01                                lea     rax, off_217A8E0
.text:0000000000DD4807 BE 29 00 00 00                                      mov     esi, 29h ; ')'
.text:0000000000DD480C 31 D2                                               xor     edx, edx
.text:0000000000DD480E 48 C7 45 C8 00 00 00 00                             mov     qword ptr [rbp-38h], 0
.text:0000000000DD4816 48 8D 7D C0                                         lea     rdi, [rbp-40h]
.text:0000000000DD481A 48 89 45 C0                                         mov     [rbp-40h], rax
.text:0000000000DD481E E8 6D FE FF FF                                      call    sub_DD4690
.text:0000000000DD4823 89 05 33 9E 58 01                                   mov     cs:dword_235E65C, eax
.text:0000000000DD4829 E9 49 FF FF FF                                      jmp     loc_DD4777
.text:0000000000DD4829                                     IGameSystem_LoopPostInitAllSystems endp

```
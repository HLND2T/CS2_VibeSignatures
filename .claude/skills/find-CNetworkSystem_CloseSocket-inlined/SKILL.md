---
name: find-CNetworkSystem_CloseSocket-inlined
description: |
  Final-guarantee fallback for the find-CNetworkSystem_CloseSocket-inlined preprocessor. Recovers the
  CNetworkSystem::CloseSocket vtable member in CS2 networksystem.dll / libnetworksystem.so by anchoring on the
  "Closing '%s' UDP listen socket" teardown string and, when the string-owning body has been de-inlined into
  CNetworkSystem::CloseSocketInternal, following that body's callers back into CNetworkSystem_vtable. Use this
  skill when the deterministic preprocessor (ida_preprocessor_scripts/find-CNetworkSystem_CloseSocket-inlined.py)
  and its -deinlined sibling could not resolve the vfunc because the teardown body moved across the
  inline/de-inline boundary.
  Trigger: CNetworkSystem_CloseSocket
disable-model-invocation: true
---

# Find CNetworkSystem_CloseSocket (final-guarantee fallback)

Recover the `CNetworkSystem::CloseSocket` virtual function in CS2 `networksystem.dll` / `libnetworksystem.so`
using IDA Pro MCP tools.

This is the **Agent fallback** for the 3-skill chain
`find-CNetworkSystem_CloseSocketInternal` -> `find-CNetworkSystem_CloseSocket-deinlined` ->
`find-CNetworkSystem_CloseSocket-inlined`. It only runs when `-inlined` (the sole `expected_output` link, hence
the only one that reaches the Agent) returned failure — which means the teardown body's position relative to the
vfunc is neither of the two states the two preprocessor paths cover.

Your job is to produce `CNetworkSystem_CloseSocket.{platform}.yaml` regardless of that inline/de-inline boundary.

## Realworld Function References

Read the platform-relevant real-world YAMLs before searching in IDA. Together they show **both** sides of the
known boundary: the fused Windows vfunc, the thin Linux forwarder, and the de-inlined Linux body. Treat their
addresses and offsets as reference-build (14178) values only; verify every result against the current binary.

- Windows fused baseline (body inlined into the vfunc, owns all four teardown strings):
  `ida_preprocessor_scripts/references/networksystem/CNetworkSystem_CloseSocket.windows.yaml`
- Linux de-inlined baseline (the vfunc reduced to a bounds-check forwarder, no strings):
  `ida_preprocessor_scripts/references/networksystem/CNetworkSystem_CloseSocket.linux.yaml`
- Linux de-inlined teardown body (owns all four teardown strings):
  `ida_preprocessor_scripts/references/networksystem/CNetworkSystem_CloseSocketInternal.linux.yaml`

## Background — what CloseSocket does and where the strings live

`CNetworkSystem::CloseSocket(this, int nSocket)` is vtable member 17 of `CNetworkSystem`. Logically it is:

```c
bool CNetworkSystem::CloseSocket(int nSocket)
{
    if (nSocket < 0 || nSocket >= this->m_nSockets)   // m_nSockets @ this+0xA8 (ref)
        return false;
    CloseSocketInternal(nSocket);                     // the teardown body
    return true;
}
```

The **teardown body** is what owns the four log strings, all emitted through
`LoggingSystem_IsChannelEnabled` / `LoggingSystem_Log` on the networksystem channel:

- `"Closing '%s' UDP listen socket\n"`  <- the anchor this fallback uses
- `"Closing '%s' P2P listen socket\n"`
- `"Closing '%s' SDR listen socket\n"`
- `"Closing '%s' poll group\n"`

It also calls `netadr_t::Clear` on the socket's address and zeroes the socket slot (`0x70`-byte stride array at
`this+0xB0`, ref).

The compiler decides per platform whether that body is fused into the vfunc:

| Build | Teardown body | The `CloseSocket` vtable member |
|-------|---------------|---------------------------------|
| `networksystem.dll` (all observed) | inlined into the vfunc | large, **owns** the four strings |
| `libnetworksystem.so` (14177b, 14178) | separate `CloseSocketInternal` | ~0x21 bytes, **owns no string at all** |

## Robustness principle — follow the *caller*, not the callee

This target is an **inverted** de-inline topology: the public symbol is the thin string-less wrapper and the
helper keeps the strings. So the usual "follow the callee" move is reversed:

1. Find the function that owns the `"Closing '%s' UDP listen socket"` string.
2. If that function **is** an entry of `CNetworkSystem_vtable`, the body is fused — that function is
   `CloseSocket` (Windows case). Beware the `CloseAllSockets` decoy below.
3. If it is **not** a vtable entry, it is the de-inlined `CloseSocketInternal`. Enumerate **its callers**,
   intersect them with `CNetworkSystem_vtable`, and pick the thin bounds-check forwarder (Linux case).
4. The method is state-agnostic: it works if Windows ever de-inlines or Linux ever re-fuses. Never assume a
   platform implies a state — always classify from what you actually see in the current binary.

Anchor by semantics (the string, the `nSocket < 0 || nSocket >= this->m_nSockets` guard, the vtable membership),
never by a fixed address or a fixed containing function.

## Output inventory

Exactly one output, produced on **both** platforms. Values are **reference values from build 14178 — verify
against the binary, do not assume**; they change across updates and differ per platform.

| # | Output symbol | Kind | Windows | Linux | Writer skill |
|---|---------------|------|---------|-------|--------------|
| 1 | `CNetworkSystem_CloseSocket` | real vtable vfunc (has a body) | `func_va 0x1800f15b0`, `func_size 0x21e`, vtable `CNetworkSystem_vtable`, offset `0x88`, index `17` | `func_va 0x2d9db0`, `func_size 0x21`, vtable `CNetworkSystem_vtable`, offset `0x88`, index `17` | `/write-vfunc-as-yaml` |

Platform gating: none — the symbol is required on **both** `windows` and `linux`.

> **Do NOT emit `func_sig`.** The preprocessor deliberately omits it on both chain paths so the symbol's output
> shape does not flip with the inline state (the Linux forwarder is a ~0x21-byte thunk while the Windows body is
> ~0x21e bytes). The stable locator is the vtable slot. Emit exactly these fields:
> `func_name, func_va, func_rva, func_size, vtable_name, vfunc_offset, vfunc_index`.

## Step 0. Skip if already produced

If `CNetworkSystem_CloseSocket.<platform>.yaml` already exists beside the binary and parses to a non-empty
mapping, **skip everything** — the preprocessor or the `-deinlined` sibling wrote it. List the binary directory
with:

```
mcp__ida-pro-mcp__py_eval code="import idaapi, os; d=os.path.dirname(idaapi.get_input_file_path()); print('\n'.join(sorted(f for f in os.listdir(d) if f.endswith('.yaml'))))"
```

`/get-func-from-yaml` with `func_name=CNetworkSystem_CloseSocket` also reports existence (it errors when absent).

## Step 1. Load the vtable

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CNetworkSystem` to load
`CNetworkSystem_vtable.<platform>.yaml` (the chain's `expected_input`).

If it returns an error, **STOP** and report to user — this fallback cannot disambiguate candidates without the
vtable entry set.

Keep the full `vtable_entries` map; both branches below intersect against it.

## Step 2. Locate the teardown-string owner(s)

Find every function that references the anchor string. The literal in the binary ends with `\n`; match on the
substring `Closing '%s' UDP listen socket`:

```
mcp__ida-pro-mcp__py_eval code="""
import idaapi, idautils, idc, ida_funcs

ANCHOR = "Closing '%s' UDP listen socket"
hits = []
for s in idautils.Strings():
    if ANCHOR in str(s):
        for xref in idautils.XrefsTo(int(s.ea), 0):
            f = ida_funcs.get_func(xref.frm)
            if f:
                hits.append((hex(int(f.start_ea)), idc.get_func_name(int(f.start_ea)),
                             int(f.end_ea - f.start_ea)))
result = sorted(set(hits))
print(result)
"""
```

If the anchor string cannot be found at all, **STOP** and report to user (Valve renamed or removed the log line;
the references must be regenerated).

Then classify each owner: is its start address present in `vtable_entries` from Step 1?

- **at least one owner IS a vtable entry** -> fused state, go to Step 3.
- **no owner is a vtable entry** -> de-inlined state, go to Step 4.

## Step 3. Fused state — the string owner IS the vfunc

Observed on `networksystem.dll`, where the anchor has **two** owners and both are `CNetworkSystem` vtable
members:

| Owner | Identify by | Verdict |
|-------|-------------|---------|
| `CNetworkSystem::CloseSocket` (idx 17, ref `0x1800f15b0`) | takes `(this, int nSocket)`; guards with `nSocket < 0 \|\| nSocket >= this->m_nSockets`; closes **one** slot | **the target** |
| `CNetworkSystem::CloseAllSockets` (idx 38, ref `0x1800effd0`) | owns the VProf string `"CNetworkSystem::CloseAllSockets()"`; **loops** `for (i = 0; i < this->m_nSockets; ++i)` closing every slot | **decoy — reject** |

Reject any owner that references `"CNetworkSystem::CloseAllSockets()"`. Confirm the survivor by decompiling it
and checking the single-slot bounds-check guard:

```
mcp__ida-pro-mcp__decompile addr="<owner.func_va>"
```

The surviving owner is `CloseSocket`. Go to Step 5.

> If more than one non-decoy owner survives, decompile each and keep the one whose **first int parameter** is
> range-checked against `this->m_nSockets` and which closes exactly one socket slot.

## Step 4. De-inlined state — follow the body's callers

Observed on `libnetworksystem.so`. The single string owner is the de-inlined teardown body
(`CloseSocketInternal`, ref `0x2d9a80`, ~`0x32e` bytes) and it is **not** in the vtable.

Shortcut: if `CNetworkSystem_CloseSocketInternal.<platform>.yaml` already exists beside the binary (the
`find-CNetworkSystem_CloseSocketInternal` link may have written it), use `/get-func-from-yaml` with
`func_name=CNetworkSystem_CloseSocketInternal` to get its `func_va` instead of re-deriving it from Step 2.

Now enumerate the body's callers and intersect with `vtable_entries`:

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, idc, ida_funcs

BODY = <CloseSocketInternal.func_va>
callers = set()
for xref in idautils.XrefsTo(BODY, 0):
    f = ida_funcs.get_func(xref.frm)
    if f:
        callers.add((hex(int(f.start_ea)), idc.get_func_name(int(f.start_ea)),
                     int(f.end_ea - f.start_ea)))
result = sorted(callers)
print(result)
"""
```

On 14178 that intersection is **six** `CNetworkSystem` vtable members. Every one of them logs; `CloseSocket`
alone references **no string at all** — that is the discriminator. Reject a candidate if it owns any string; in
practice the colliders are:

| idx | Member | Owns the string |
|-----|--------|-----------------|
| 4 | `CNetworkSystem::Shutdown` | `"CNetworkSystem::Shutdown()"` (also refs `"CNetworkSystem::CloseAllSockets()"`) |
| 12 | `CNetworkSystem::ShutdownGameServer` | `"CNetworkSystem::ShutdownGameServer"` |
| 15 | `CNetworkSystem::ConnectSocket` | `"Reusing cacheable shared Steam Net Connection to '%s'"` |
| **17** | **`CNetworkSystem::CloseSocket`** | **none — the target** |
| 18 | `CNetworkSystem::EnableLoopbackBetweenSockets` | `"Can't ConnectLoopback between socket %d and %d, not enough slots"` |
| 38 | `CNetworkSystem::CloseAllSockets` | `"CNetworkSystem::CloseAllSockets()"` |

Enumerate each candidate's string xrefs and drop every candidate that has any:

```
mcp__ida-pro-mcp__py_eval code="""
import idautils, ida_funcs

CANDIDATES = [<vtable-filtered caller addresses>]
strmap = {}
for s in idautils.Strings():
    strmap[int(s.ea)] = str(s)

out = {}
for ea in CANDIDATES:
    f = ida_funcs.get_func(ea)
    found = []
    if f:
        for h in idautils.Heads(f.start_ea, f.end_ea):
            for xr in idautils.XrefsFrom(h, 0):
                t = strmap.get(int(xr.to))
                if t:
                    found.append(t)
    out[hex(ea)] = sorted(set(found))
result = out
print(result)
"""
```

Confirm the string-less survivor by decompiling it — it must be the thin forwarder: the
`nSocket < 0 || nSocket >= this->m_nSockets` guard, one `call` to the teardown body, `return true`.

```
mcp__ida-pro-mcp__decompile addr="<survivor.func_va>"
```

> If the string-less filter leaves **more than one** candidate, prefer the **smallest** one whose only named
> callee is the teardown body (the reference Linux forwarder is `0x21` bytes). If it leaves **none**, the vfunc
> gained a log line: fall back to the bounds-check-guard shape and the "only calls the teardown body" property.

Go to Step 5.

## Step 5. Resolve the vtable slot and write the YAML

1. **ALWAYS** Use SKILL `/get-vtable-index` with `class_name=CNetworkSystem` and `func_addr=<resolved func_va>`
   to obtain `vfunc_offset` and `vfunc_index`. Do **not** assume offset `0x88` / index `17` — verify.
   If the address is not found in the vtable, the candidate is wrong; go back to Step 3/4.
2. Optionally rename the function for readability:
   `mcp__ida-pro-mcp__rename addr="<func_va>" new_name="CNetworkSystem_CloseSocket"`.
3. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `CNetworkSystem_CloseSocket`
   - `func_addr`: the resolved `func_va`
   - `func_sig`: `None`   (intentionally omitted — see the note in the output inventory)
   - `vfunc_sig`: `None`  (this is a real vtable member with a body, not an indirect vcall)
   - `vfunc_sig_disp`: `None`
   - `vtable_name`: `CNetworkSystem_vtable`
   - `vfunc_offset`: from step 1
   - `vfunc_index`: from step 1

Do **not** call `/generate-signature-for-function` — no `func_sig` is emitted for this symbol.

## Failure handling

- `CNetworkSystem_vtable.<platform>.yaml` missing → **STOP** and report to user.
- Anchor string `"Closing '%s' UDP listen socket"` not present in the binary → **STOP** and report to user, so
  the references and both preprocessor paths can be re-anchored.
- Candidate set does not collapse to one function after Step 3/4 → **STOP** and report exactly which candidates
  survived (address, size, owned strings, vtable index) so the user can extend the exclusion set in
  `find-CNetworkSystem_CloseSocket-deinlined.py`.
- Resolved address not present in `CNetworkSystem_vtable` → **STOP**; do not write a YAML with a guessed slot.

## Output YAML filenames

Written beside the binary by `/write-vfunc-as-yaml`:

- Windows (`networksystem.dll`): `CNetworkSystem_CloseSocket.windows.yaml`
- Linux (`libnetworksystem.so`): `CNetworkSystem_CloseSocket.linux.yaml`

## Why this is robust

- The anchor is a **log string**, not an address, and it is the same literal both preprocessor paths use — so a
  Valve string change breaks (and gets fixed) in one place.
- Classification is done from the **current binary** (is the string owner in the vtable?), not from a
  platform assumption, so it survives Windows de-inlining or Linux re-fusing.
- In the de-inlined state the discriminator is a structural property — `CloseSocket` is the only close-related
  `CNetworkSystem` vfunc that logs nothing — which does not depend on codegen details such as register
  allocation or the `m_nSockets` displacement encoding.
- The output locator is the vtable slot, which has been stable (offset `0x88` / index `17`) across both
  platforms and both observed builds, and it is re-verified with `/get-vtable-index` rather than assumed.
- The existing-output check in Step 0 makes this fallback compose with the preprocessor chain instead of
  fighting it.

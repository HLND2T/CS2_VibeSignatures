---
name: find-CNetworkMessages_FindOrCreateNetMessage-14197
description: |
  Recover CNetworkMessages_FindOrCreateNetMessage in CS2 networksystem.dll or libnetworksystem.so
  when signature reuse and diagnostic-string preprocessing fail. Identify the registration vfunc
  through current CNetworkMessages vtable entries, string references, and message creation semantics.
disable-model-invocation: true
---

# Find CNetworkMessages_FindOrCreateNetMessage

Recover the concrete registration vfunc for the active platform using IDA Pro MCP.
The configured prerequisite is `CNetworkMessages_vtable.<platform>.yaml`.

## Realworld Function References

- `bin_artifacts/14198/networksystem/CNetworkMessages_FindOrCreateNetMessage.windows.yaml`
- `bin_artifacts/14198/networksystem/CNetworkMessages_FindOrCreateNetMessage.linux.yaml`
- `bin_artifacts/14198/networksystem/CNetworkMessages_vtable.windows.yaml`
- `bin_artifacts/14198/networksystem/CNetworkMessages_vtable.linux.yaml`

These are reference-build values. Confirm the function and its slot against the current binary.
Build 14198 places the function at vtable index 20, offset `0xA0`, on both platforms.
In 14198b Linux, the body is at `0x2BB280`, size `0xD18`, with the same slot.

## Output inventory

| Platform | Required output | Kind | Required fields |
| --- | --- | --- | --- |
| Windows | `CNetworkMessages_FindOrCreateNetMessage.windows.yaml` | Concrete vfunc | `func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`, `vtable_name`, `vfunc_offset`, `vfunc_index` |
| Linux | `CNetworkMessages_FindOrCreateNetMessage.linux.yaml` | Concrete vfunc | Same fields |

Use the analyzer-reported active artifact module directory, exposed as `CS2VIBE_ARTIFACT_DIR`.
For the active platform, skip an existing output that parses as a non-empty mapping unless the analyzer
has reported that output as invalid. Resolve the corresponding prerequisite vtable YAML from this directory.

## Identify the registration implementation

1. Load the current `CNetworkMessages` vtable with `/get-vtable-from-yaml`.
2. Search strings for `CNetworkMessages::FindOrCreateNetMessage:` and follow their code xrefs to
   containing functions. Diagnostic suffixes vary across builds. Observed forms include

   - `It is illegal to register new net messages after serialization!`
   - `Registering net message %s after registration closed`
   - `Message %s is expected to have already been registered!`

3. Intersect candidate function starts with the current vtable entries and decompile the survivors.
   The implementation formats the message name and numeric ID using `%s [%d]`, looks up an existing
   registration under a lock, and returns the existing descriptor or creates and inserts a descriptor
   holding the message factory, ID, category, and flags. Additional anchors include category labels
   such as `Generic`, `Local Player`, `Voice`, `User Messages`, and the diagnostic beginning
   `NetMessage '%s' still using auto-assigned`.
4. If a diagnostic belongs to a separate helper, inspect its callers in the vtable and follow callees
   from plausible registration entries. If diagnostic text is absent, inspect the reference slot and
   nearby entries, then expand through the vtable until the registration semantics identify one entry.
   Read the current slot from the verified function pointer.

In 14198b Linux the new diagnostic is at `0x1674C8`, referenced at `0x2BBC38` inside `0x2BB280`.
When registration is closed, this function logs a warning, sets the local non-networkable flag,
sets the message ID to `-1`, and continues descriptor creation. In 14197 and 14198, the corresponding
registration-closed branch logged the older diagnostic and returned a null descriptor. Check these
branches when identifying the implementation across builds.

## Signature and YAML output

Rename the verified function to `CNetworkMessages_FindOrCreateNetMessage`.
Use `/get-vtable-index` against the current `CNetworkMessages` vtable to obtain its index and byte offset.
Use `/generate-signature-for-function` on the verified entry point and confirm a unique match.
Write the result with `/write-vfunc-as-yaml` using the following parameters.

- `func_name` and `artifact_name` are `CNetworkMessages_FindOrCreateNetMessage`.
- `func_addr` is the verified function entry point.
- `func_sig` is the validated unique function signature.
- `vtable_name` is `CNetworkMessages`.
- `vfunc_index` and `vfunc_offset` come from the current vtable, with `vfunc_offset = vfunc_index * 8`.
- `vfunc_sig` is `None`.

Write only the active platform's required output under the active artifact module directory.
The analyzer's trusted finalizer canonicalizes the semantic payload.

## Failure handling

If the prerequisite vtable is missing, report its exact path.
If candidates remain ambiguous or the registration implementation cannot be confirmed, report the
candidate addresses, diagnostic xrefs, and unresolved output. Require a verified concrete implementation
before writing the function fields.

---
name: generate-reference-yaml
description: Generate reference YAML via project CLI into ida_preprocessor_scripts/references/<module>/<func_name>.<platform>.yaml
---

# Generate Reference YAML

Use this skill as the unified backend entrypoint through project CLI.

Do not call IDA API directly in this skill. Always run `generate_reference_yaml.py`.

## Required parameters

- `func_name`
- `gamever` (Obtain from dll path via ida-pro-mcp if not specified)
- `module` (Obtain from dll path via ida-pro-mcp if not specified)
- `platform` (Obtain from dll path via ida-pro-mcp if not specified)

## Command examples

### 1) Attach to existing MCP (should be used when there is an existing ida-pro-mcp connection)

```bash
uv run generate_reference_yaml.py -gamever 14141 -module engine -platform windows -func_name CNetworkGameClient_RecordEntityBandwidth -mcp_host 127.0.0.1 -mcp_port 13337
```

### 2) Auto-start `idalib-mcp` with binary (fallback when no MCP is attached)

```bash
# Windows -- always pass -platform windows explicitly
uv run generate_reference_yaml.py -func_name {FUNC_NAME} -auto_start_mcp -binary "bin/{gamever}/{module}/{binary_name}.dll" -platform windows -debug

# Linux -- always pass -platform linux explicitly
uv run generate_reference_yaml.py -func_name {FUNC_NAME} -auto_start_mcp -binary "bin/{gamever}/{module}/lib{module}.so" -platform linux -debug
```

where `{gamever}` can be obtained from `.env` -> `CS2VIBE_GAMEVER`.

**IMPORTANT -- Always pass `-platform` explicitly.** While `-platform` can theoretically be inferred from the binary extension (`.dll` -> windows, `.so` -> linux), auto-inference is unreliable and may produce the wrong platform's reference YAML. Always pass `-platform windows` or `-platform linux` explicitly.

### 3) Custom output name

Use `-output_filename` when the reference YAML file name should differ from the default `<func_name>.<platform>.yaml`:

```bash
uv run generate_reference_yaml.py -gamever 14141 -module engine -platform windows -func_name CNetworkGameClient_RecordEntityBandwidth -output_filename CNetworkGameClient_RecordEntityBandwidthReference.windows.yaml -mcp_host 127.0.0.1 -mcp_port 13337
```

`-output_filename` accepts a file name ending in `.yaml`, not a path. The file is still written under `ida_preprocessor_scripts/references/<module>/`. The YAML payload's `func_name` remains the value passed to `-func_name`.

**IMPORTANT -- Run `generate_reference_yaml.py` sequentially, NOT in parallel.** All invocations share the same IDA MCP connection. Running them in parallel will cause connection conflicts and failures. Run one command at a time, waiting for each to complete before starting the next.

## Output path

- Default: `ida_preprocessor_scripts/references/<module>/<func_name>.<platform>.yaml`
- With `-output_filename <name>.yaml`: `ida_preprocessor_scripts/references/<module>/<name>.yaml`

## Manual checks after generation

1. `func_va` is credible for current binary/version.
2. `disasm_code` is non-empty and matches target function semantics.
3. `procedure` matches expected semantics when available; it can be an empty string when Hex-Rays is unavailable.
4. `func_name` only confirms the output file targets your requested canonical name; it does not prove address resolution correctness.

## `LLM_DECOMPILE` path wiring

- Generated file path in repository:
  - `ida_preprocessor_scripts/references/<module>/<func_name>.<platform>.yaml`
- In target `find-*.py`, when `LLM_DECOMPILE` uses relative paths, write:
  - `references/<module>/<func_name>.<platform>.yaml`
- Example tuple:
  - `("CNetworkMessages_FindNetworkGroup", "prompt/call_llm_decompile.md", "references/engine/CNetworkGameClient_RecordEntityBandwidth.windows.yaml")`

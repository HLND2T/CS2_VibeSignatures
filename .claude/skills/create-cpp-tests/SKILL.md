---
name: create-cpp-tests
description: |
  Create a new cpp_tests entry for validating a C++ interface vtable layout against binary reference YAMLs.
  Creates the .cpp test file in cpp_tests/ and appends a config.yaml entry under cpp_tests:.
  Use when a user asks to add vtable layout validation for a new hl2sdk_cs2 interface class.
disable-model-invocation: true
---

# Create cpp_tests for Interface Vtable Validation

Create a `cpp_tests/<interface_lowercase>.cpp` test file and append a matching `config.yaml`
entry so that `run_cpp_tests.py` can compile the header with clang, dump the vtable layout,
and compare it against reference YAML files from the binary analysis.

## When to Use

- User asks to create cpp_tests for an interface (e.g., "create cpp_tests for ILoopMode")
- User provides or references a header file from `hl2sdk_cs2/`

## Inputs

The user will provide some or all of:

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| **Interface name** | Yes | The abstract class to validate | `ILoopMode` |
| **Header path** | Yes | Path to the header in hl2sdk_cs2 | `hl2sdk_cs2/public/iloopmode.h` |
| **Alias symbols** | No | Concrete class name(s) used in binary YAML files | `CLoopModeGame` |
| **Reference modules** | No | Modules where vtable YAMLs live | `client`, `server` |

## Step-by-Step Procedure

### Step 1: Read the target header

Read the header file to understand:
- What `#include` directives it uses
- What types are referenced in virtual method signatures
- Whether it inherits from another interface (e.g., `IAppSystem`)

### Step 2: Identify compilation dependencies

Check if the header's transitive includes will compile cleanly with the standard include set:
- `hl2sdk_cs2/game/shared`
- `hl2sdk_cs2/public`
- `hl2sdk_cs2/public/tier0`
- `hl2sdk_cs2/public/tier1`

Common issues to watch for:
- **Missing types** referenced in method signatures (e.g., `CSplitScreenSlot` needs `<tier1/convar.h>`)
- **Heavy transitive includes** that pull in protobuf or other unavailable deps (e.g., `eiface.h` -> protobuf chain)

For heavy transitive includes, pre-define include guards to block them and forward-declare/stub the minimum needed types. See the `inetworkmessages.cpp` and `inetworksystem.cpp` examples for this technique:

```cpp
// Example: blocking heavy include chains
#define EIFACE_H
#define INETCHANNEL_H
enum NetChannelBufType_t : int8 {};
```

### Step 3: Create the cpp test file

Create `cpp_tests/<interface_lowercase>.cpp` following this template:

```cpp
#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// Add any extra includes needed for types in the interface signatures
// Add any include-guard stubs to block heavy transitive includes

#include <path/to/interface_header.h>

InterfaceName * instanceptr();

int main() {

    instanceptr()->SomeMethod();

    return 0;
}
```

Key rules:
- Always start with the `platform.h` + `RESTRICT` preamble
- The extern function declaration (e.g., `ILoopMode * loopmode();`) forces the compiler to emit vtable info
- `main()` must call at least one virtual method to trigger vtable layout dump
- Pick a simple void-returning method with no complex args for the call in `main()`

### Step 4: Determine alias_symbols and reference_modules

If the user didn't provide these, discover them:

1. **alias_symbols**: Search for existing vtable YAML files:
   ```
   bin/**/*<ClassName>*vtable*
   ```
   The `vtable_class` field in those YAMLs gives the alias symbol (typically the concrete class name like `CLoopModeGame` for `ILoopMode`).

2. **reference_modules**: The subdirectories under `bin/{gamever}/` where vtable YAMLs exist (e.g., `client`, `server`, `engine`, `networksystem`).

### Step 5: Append config.yaml entry

Append a new entry at the end of the `cpp_tests:` section in `config.yaml`:

```yaml
  - name: {InterfaceName}_MSVC
    symbol: {InterfaceName}
    alias_symbols:                          # omit this block if no aliases
      - {ConcreteClassName}
    cpp: cpp_tests/{interface_lowercase}.cpp
    headers:
    - {header_path} # This is for LLM agent
    claude_permission_mode: acceptEdits
    claude_allowed_tools: Read,Edit,MultiEdit,Write
    target: x86_64-pc-windows-msvc
    include_directories:
      - hl2sdk_cs2/game/shared
      - hl2sdk_cs2/public
      - hl2sdk_cs2/public/tier0
      - hl2sdk_cs2/public/tier1
    defines:
      - COMPILER_MSVC=1
      - COMPILER_MSVC64=1
      - _MSVC_STL_USE_ABORT_AS_DOOM_FUNCTION
    additional_compiler_options:
      - fms-extensions
      - fms-compatibility
      - Xclang
      - fdump-vtable-layouts
    reference_modules:
      - {module1} # bin/{gamever}/{module1}/{AliasOrSymbol}_*.{platform}.yaml
      - {module2}
```

Notes:
- `include_directories`, `defines`, and `additional_compiler_options` are always the same standard set
- `reference_modules` comments should document the YAML file naming pattern
- If no `alias_symbols`, the reference YAML files use the `symbol` name directly

### Step 6: Test compilation

Run the test to verify it compiles:

```bash
uv run run_cpp_tests.py -gamever {latest_gamever} -debug
```

Look at the output for the new test entry. Expected results:
- **[PASS]**: compilation succeeded, vtable comparison ran
- **[FAIL] compile failed**: fix the compilation error (usually a missing type or blocked include)

### Step 7: Fix compilation errors (if any)

Common fixes:
- **Unknown type**: Add the appropriate `#include` before the interface header
- **Missing definition from heavy include**: Add `#define HEADER_GUARD_H` before the include to block it, then forward-declare or stub the minimum types needed
- Iterate: fix, re-run test, repeat until `[PASS]`

## Reference: Existing Examples

| Test Name | Interface | Header | Has Aliases | Has Include Stubs | Reference Modules |
|-----------|-----------|--------|-------------|-------------------|-------------------|
| `IGameSystem_MSVC` | `IGameSystem` | `igamesystem.h` | No | No | server, client |
| `INetworkMessages_MSVC` | `INetworkMessages` | `inetworkmessages.h` | `CNetworkMessages` | Yes (EIFACE_H, INETCHANNEL_H) | networksystem, engine, server, client |
| `ILoopMode_MSVC` | `ILoopMode` | `iloopmode.h` | `CLoopModeGame` | No (just extra `convar.h` include) | client, server |

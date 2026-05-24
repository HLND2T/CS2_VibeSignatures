# IDA Pro MCP Tools Reference

## `rename` — Unified Renaming Tool

Supports renaming functions, global variables, local variables, and stack variables.

### Parameter Structure

```json
{
  "batch": {
    "func": [...],      // Function renaming
    "data": [...],      // Global/data variable renaming
    "local": [...],     // Local variable renaming
    "stack": [...]      // Stack variable renaming
  }
}
```

### 1. Function renaming (`func`)

```json
{ "batch": { "func": { "addr": "0x12345678", "name": "NewFuncName" } } }
```

### 2. Global / Data variable renaming (`data`)

```json
{ "batch": { "data": { "old": "old_global_name", "new": "new_global_name" } } }
```

### 3. Local variable renaming (`local`)

```json
{ "batch": { "local": { "func_addr": "0x12345678", "old": "v1", "new": "playerIndex" } } }
```

### 4. Stack variable renaming (`stack`)

```json
{ "batch": { "stack": { "func_addr": "0x12345678", "old": "var_20", "new": "bufferSize" } } }
```

### Batch Example

```json
{
  "batch": {
    "func": [
      {"addr": "0x1000", "name": "InitPlayer"},
      {"addr": "0x2000", "name": "UpdateHealth"}
    ],
    "local": [
      {"func_addr": "0x1000", "old": "a1", "new": "pPlayer"},
      {"func_addr": "0x1000", "old": "v5", "new": "healthValue"}
    ]
  }
}
```

---

## `get_bytes` — Read Raw Bytes

```json
{
  "regions": [
    {"addr": "0x140001000", "size": 16},
    {"addr": "0x140002000", "size": 32}
  ]
}
```

Single region: pass an object instead of an array.

---

## `int_convert` — Number Format Conversion

Converts hex/decimal/binary to all formats (including ASCII).

```json
{
  "inputs": [
    {"text": "0x41424344"},
    {"text": "12345"},
    {"text": "0b11001100"}
  ]
}
```

Use `"size": N` to force a specific byte size.

---

## `get_int` — Read Integer from Address

Type format: `{sign}{bits}{endian}` — e.g. `i8`, `u64`, `i16le`, `i16be`, `u32be`

```json
{
  "queries": [
    {"addr": "0x140001000", "ty": "u32"},
    {"addr": "0x140001004", "ty": "i16le"},
    {"addr": "0x140001008", "ty": "u64"}
  ]
}
```

Single query: pass an object instead of an array.

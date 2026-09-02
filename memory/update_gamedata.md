---
title: update_gamedata
type: note
permalink: cs2-vibesignatures/update-gamedata
---

# Update Gamedata

## Overview
The gamedata subsystem converts one guarded release-local symbol snapshot into exact downstream payloads below an explicit candidate root. Generator source lives in `gamedata-generators/`; gamedata is Release-derived and never tracked on the source branch.
## Responsibilities
- Load symbols from the exact snapshot candidate and merge analysis/module config.
- Enforce declared `OUTPUT_PATHS`, static/download sources, path containment, canonical text, and allowed final formats.
- Fail strict generation on download, module, missing, extra, link/reparse, or identity errors.
- Build and guard immutable release-local gamedata candidate sessions.
- Preserve target-specific JSON/JSONC/VDF conversions for Release packaging.
## Involved Files & Symbols
- `update_gamedata.py` - `generate_gamedata`, requiring explicit snapshot and output root.
- `gamedata_symbol_data.py` - snapshot-backed symbol/config loading.
- `gamedata_contract.py` - generator discovery, contract digest, output validation.
- `gamedata_candidate.py` - release-local build/guard lifecycle; no publish/verify-tracked API.
- `gamedata-generators/<MODULE>/gamedata.py` - converters and declarations.
## Architecture
```text
validated bin_artifacts -> release-local symbol snapshot + exact config
  -> discover generator contracts
  -> explicit candidate root
  -> strict per-generator update and canonicalization
  -> exact OUTPUT_PATHS inventory
  -> guarded gamedata candidate
  -> C++/archive/manifest evidence
  -> hosted verification and immutable Release
```

`generate_gamedata()` is the engine. `gamedata_candidate.py build` calls it in strict mode and binds snapshot/config/generator/output digests in the session. No command copies it into a tracked `gamedata/` namespace.
## Dependencies
- Guarded snapshot store, exact analysis config, trusted generator source/templates, PyYAML, httpx, vdf, JSONC helpers.
- Release-local output/session paths and immutable source/binary identity.
## Notes
- `OUTPUT_PATHS`, not extension globs, authorizes files; version roots reject Python/YAML/cache/link/undeclared content.
- `update_gamedata.py` requires explicit `-outputdir` and `-snapshot`.
- Enabled generators include CounterStrikeSharp, CS2Fixes, CS2FOW, swiftlys2, plugify, cs2kz, modsharp, and cs2surf.
- Build locally only from a candidate created from `bin_artifacts`; never fall back to tracked `gamesymbols/` or per-symbol YAML in `bin/`.
## Callers
- `pr-self-runner.yml` for release-local downstream evidence after exact artifact validation.
- `build-on-self-runner.yml` for the hosted-verified immutable Release bundle.
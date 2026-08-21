---
title: update_gamedata
type: note
permalink: cs2-vibesignatures/update-gamedata
---

# Update Gamedata

## Overview
The gamedata subsystem converts an immutable symbol snapshot into exact downstream payloads. Generator source lives in `gamedata-generators/`; release output is versioned below `gamedata/<GAMEVER>/`.

## Responsibilities
- Load snapshot symbols and merged analysis/module config.
- Enforce exact `OUTPUT_PATHS`, download/static sources, path containment, and allowed final formats.
- Fail strict generation on download, module, missing, extra, or reparse errors.
- Build, guard, and atomically publish versioned gamedata candidate sessions.
- Preserve target-specific JSON/JSONC/VDF conversions.

## Involved Files & Symbols
- `update_gamedata.py` - `generate_gamedata`.
- `gamedata_symbol_data.py` - config and symbol loading.
- `gamedata_contract.py` - generator discovery, contract digest, output validation.
- `gamedata_candidate.py` - build/guard/publish.
- `gamedata-generators/<MODULE>/gamedata.py` - converters and declarations.

## Architecture
```text
symbol candidate + config -> trusted generator contract
 -> static/download baselines -> module conversion -> exact inventory guard
 -> candidate session -> atomic gamedata/<GAMEVER> publication
```

## Dependencies
- Snapshot store, PyYAML, httpx, vdf, JSONC helpers, trusted generator source/templates.

## Notes
- `OUTPUT_PATHS`, not extension globs, authorizes outputs.
- Version roots reject Python, YAML, caches, links, metadata, and undeclared files.
- ModSharp EntityEnhancement is a reviewed static template because its former upstream URL is unavailable.

## Callers
- Build and PR self-runner workflows.
- `pr-self-runner.yml` builds an isolated gamedata candidate from the validated symbol candidate for C++ ABI and
  contract checks; it does not publish it. Versioned `gamedata/<GAMEVER>` publication is release-pipeline only.
- `create-pr` delivers source changes only and delegates PR gamedata generation/validation to CI.

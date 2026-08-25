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
symbol candidate + configs/<GAMEVER>.yaml
 -> discover gamedata-generators/*/gamedata.py (MODULE_ENABLED, OUTPUT_PATHS, update())
 -> seed STATIC_SOURCES; optional DOWNLOAD_SOURCES into gamedata/<GAMEVER>/<module>/
 -> per generator: merge overlay config.yaml, load yaml_data from snapshot, module.update()
 -> canonicalize LF; strict validate_output_tree == declared OUTPUT_PATHS
 -> gamedata_candidate session (snapshot/config/contract/manifest SHA) -> guard -> atomic publish
```

`generate_gamedata()` is the engine. `gamedata_candidate.py build` calls it with `download_latest=True, strict=True`. Publish copies guarded candidate bytes; it does not regenerate.

Downstream key matching: see [[gamedata_aliases]]. Snapshot has no alias fields.

Per-module overlay `gamedata-generators/<module>/config.yaml` merges into the analysis config for that generator only (extra symbols / alias overrides).

Generator API: v1 `update(yaml_data, func_lib_map, platforms, output_dir, alias_map, debug)`; v2 also takes `context=GeneratorContext(game_version, binaries, game_version_name)`, where `game_version_name` is the human-readable version name resolved from `download.yaml`'s tag->name mapping.

## Dependencies
- Snapshot store, PyYAML, httpx, vdf, JSONC helpers, trusted generator source/templates.

## Notes
- `OUTPUT_PATHS`, not extension globs, authorizes outputs. Allowed suffixes: `.json`, `.jsonc`, `.txt`.
- Version roots reject Python, YAML, caches, links, metadata, and undeclared files.
- ModSharp EntityEnhancement is a reviewed static template because its former upstream URL is unavailable.
- Enabled generators: CounterStrikeSharp, CS2Fixes, CS2FOW, swiftlys2, plugify-plugin-s2sdk, cs2kz-metamod, modsharp-public, cs2surf.
- Local engine-only path: `uv run update_gamedata.py -gamever <v> -snapshot gamesymbols/<v>.yaml -download_latest -strict`. Release/CI must use the candidate transaction in [[post_change_candidate_lifecycle]].

## Callers
- Build and PR self-runner workflows.
- `pr-self-runner.yml` builds an isolated gamedata candidate from the validated symbol candidate for C++ ABI and
  contract checks; it does not publish it. Versioned `gamedata/<GAMEVER>` publication is release-pipeline only.
- `create-pr` delivers source changes only and delegates PR gamedata generation/validation to CI.

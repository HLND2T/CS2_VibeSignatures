---
title: gamesymbol_metadata
type: note
permalink: cs2-vibesignatures/gamesymbol-metadata
---

# gamesymbols/<GAMEVER>.metadata.yaml — field scope decision

## Decision

When releasing `gamesymbols/<GAMEVER>.yaml`, also emit a bound, immutable
`gamesymbols/<GAMEVER>.metadata.yaml` (or `.json`) carrying the subset of
`configs/<GAMEVER>.yaml` fields that are **present in config, absent from the
snapshot, and actually consumed by the pages app**.

Field-scope rule: include a config field in metadata IFF it is all three of

1. present in `configs/<GAMEVER>.yaml`, AND
2. NOT already in `gamesymbols/<GAMEVER>.yaml`, AND
3. consumed by `pages/` at build time.

## Scan result (current state)

Pages consumes exactly one thing from config: the **alias map**
(`module/symbol -> alias[]`). No other config field reaches the pages app.

Full config -> pages data path:

- `pages/gameSymbolsPlugin.ts` `loadDataset` reads `configs/<GAMEVER>.yaml`
  and calls `buildConfigAliasIndex`.
- `buildConfigAliasIndex` (gameSymbolsPlugin.ts:98) reads only
  `modules[].name`, `modules[].symbols[].name`, and `modules[].symbols[].alias`;
  it emits `ConfigAliasIndex { aliases: Map<"module/name", string[]> }`.
- `attachAliasesToDataset` (gameSymbolsPlugin.ts:127) writes those into
  `record.aliases`.
- Frontend `GameSymbolRecord.aliases` (pages/src/features/symbols/types.ts:37)
  is the only config-sourced record field; every other record field
  (id / module / artifact / symbolName / platform / kind / payload) comes from
  `normalizeGameSymbolSnapshot`.

Config fields NOT consumed by pages (thus excluded from metadata): `skills`,
`path_windows`, `path_linux`, `category`, `struct`, `member`, `cpp_tests`,
`description`, `expected_input`, `expected_output`, `max_retries`, `prerequisite`.

## Companion decisions

- **Metadata is NOT listed in `index.json`.** It is a build-time join input
  only; after the join the aliases live inside the snapshot asset
  (`gamesymbols/<ver>.<sha>.json`), so the frontend index needs no awareness of
  metadata.
- Metadata is emitted alongside the snapshot during release build
  (trigger-release-build) from `--analysis-config`, and freezes together with
  the snapshot. Config's everyday PR edits (`feat(preprocessor): add ...`) do
  not retroactively touch a published snapshot/metadata.
- The release allow-list (`build-on-self-runner.yml`, `$allowedSnapshot`
  check) must be extended to admit the metadata path, otherwise publication is
  rejected.
- The release tracked-output inventory includes and requires the metadata path,
  so staging, output-PR validation, and promotion bind its exact bytes together
  with the snapshot and versioned gamedata.

## Publishing model reminder

`gamesymbols/<GAMEVER>.yaml` is generated only on release build and overwritten
per release; `configs/<GAMEVER>.yaml` iterates freely between releases.
Metadata follows the snapshot's release/freeze cadence, not the config's.

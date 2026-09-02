---
title: gamesymbol_metadata
type: note
permalink: cs2-vibesignatures/gamesymbol-metadata
---

# gamesymbols/<GAMEVER>.metadata.yaml — field scope decision

## Decision
Generate alias metadata only as an explicit release-local companion to the release-local snapshot. Its bytes are derived from the immutable source SHA/config and packaged in the verified Release bundle; they are not tracked in Git.

Field-scope rule: include a config field iff it is present in `configs/<GAMEVER>.yaml`, absent from the snapshot, and consumed by Pages at build time.
## Scan result (current state)
Pages needs only the alias map (`module/symbol -> alias[]`). `gamesymbol_metadata.py` reads `modules[].name`, `modules[].symbols[].name`, and `modules[].symbols[].alias`; other config fields are excluded. Pages now receives this metadata through a verified published Release, not by reading main's config/snapshot directories as its historical data source.
## Companion decisions
- The metadata output path is always explicit and release-local.
- Metadata freezes with the exact snapshot/config/source identity in the Release manifest and checksums.
- Hosted verification checks the candidate bytes and archive allowlist before the protected publisher uploads them.
- Pages downloads the published immutable Release assets and verifies manifest/SHA256SUMS identity before joining aliases.
- Metadata is not a source-owned artifact and never appears under tracked `gamesymbols/`.
## Publishing model reminder
`bin_artifacts/<GAMEVER>/` is the only tracked per-symbol truth. Snapshot and metadata are rebuilt from an immutable default-branch source SHA during Release. Same-version assets may be reused only when their exact identity/content already matches; content changes require a new version.
## Relations
- contrasts_with [[gamedata_aliases]] — gamedata generation consumes the same release-local snapshot but applies generator overlays.
- derived_by [[build-on-self-runner]] and consumed by the published-Release Pages pipeline.
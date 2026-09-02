# CS2 VibeSignatures

[中文文档](README_CN.md) | [GUI](https://hlnd2t.github.io/CS2_VibeSignatures/)

CS2 VibeSignatures generates CS2 signatures and offsets, updates HL2SDK_CS2 C++ headers through Agent skills and MCP calls, and produces versioned downstream gamedata.

The project is designed to update signatures, offsets, and C++ headers without manual intervention. It currently automates the signatures and offsets consumed by CounterStrikeSharp, CS2Fixes, and other supported projects.

## Quick start

Install the [requirements](docs/en/requirements.md), then prepare and analyze one game version:

```bash
uv sync
uv run download_depot.py -tag 14156
uv run copy_depot_bin.py -gamever 14156 -platform all-platform
uv run ida_analyze_bin.py -gamever 14156 -oldgamever 14155
```

These commands populate the binary workspace under `bin/<GAMEVER>/` and run the configured deterministic, LLM-assisted, and Agent-assisted analysis. Canonical per-symbol results belong in `bin_artifacts/<GAMEVER>/` and must be committed with the source/config changes that produce them.

## Documentation

- [Requirements and environment setup](docs/en/requirements.md)
- [Development checks: formatting and tests](docs/en/development.md)
- [Binary acquisition and symbol analysis](docs/en/analysis.md)
- [Process reporting, scheduling, and dashboard](docs/en/process-monitoring.md)
- [Reference YAML for `LLM_DECOMPILE`](docs/en/reference-yaml.md)
- [Snapshots, gamedata, and C++ validation](docs/en/snapshot-and-gamedata.md)
- [Creating symbol-analysis skills](docs/en/creating-skills.md)
- [Contributing symbol-analysis skills via a pull request](docs/en/conributing-via-pr.md)
- [CI/CD and Jenkins workflow reference](docs/en/ci-cd.md)

The only Git-tracked symbol truth is `bin_artifacts/<GAMEVER>/<module>/*.yaml`. `bin/` is a disposable binary/IDA workspace. Snapshots, metadata, gamedata, archives, and manifests are Release-derived assets and are not tracked on `main`.

## Supported gamedata

Versioned gamedata is generated for CounterStrikeSharp, CS2Fixes, CS2FOW, swiftlys2, plugify, cs2kz-metamod, modsharp, and CS2Surf/Timer. See [supported gamedata paths and exceptions](docs/en/snapshot-and-gamedata.md#supported-gamedata).

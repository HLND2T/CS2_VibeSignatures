[Back to README](../../README.md) | [中文](../zh-CN/requirements.md)

# Requirements and environment setup

## Required tools

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. [DepotDownloader](https://github.com/SteamRE/DepotDownloader), with `depotdownloader.exe` available in `PATH`
3. One supported agent CLI: Claude Code, Codex, or OpenCode
4. IDA Pro 9.0+
5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
6. [idalib](https://docs.hex-rays.com/user-guide/idalib), required by `ida_analyze_bin.py`
7. Clang/LLVM, with `clang` available in `PATH`. [llvm-msvc](https://github.com/backengineering/llvm-msvc) is recommended.
8. [binsync](https://github.com/binsync/binsync)

Install the Python dependencies after cloning the repository:

```bash
uv sync
```

## Initialize the latest game binaries

For a new checkout, use `SKILL: init-gamebin` to initialize the binaries for the latest game version listed in
`download.yaml` before running symbol analysis. Ask the agent explicitly:

```text
Use SKILL: init-gamebin to initialize the latest game version's binaries.
```

The skill resolves `latest` from the repository's version list, downloads or merges the matching binaries without
overwriting existing files, and then delegates symbol YAML restoration to `restore-from-snapshot`. If no game version
is specified, the skill lists the available entries and asks you to choose one

## Troubleshooting

### `error: could not create 'ida.egg-info': access denied`

Run `python py-activate-idalib.py` with administrator privileges from:

```text
C:\Program Files\IDA Professional 9.0\idalib\python
```

### `Could not find idalib64.dll in .........`

Set `IDADIR` for the current shell or add it to the system environment:

```batch
set IDADIR=C:\Program Files\IDA Professional 9.0
```

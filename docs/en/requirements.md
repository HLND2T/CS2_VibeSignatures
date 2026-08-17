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
8. [GitHub CLI](https://cli.github.com/)
9. [binsync](https://github.com/HLND2T/binsync) (optional, always use the HLND2T fork, you can clone it and ask claude/codex to install from source)

Install the Python dependencies after cloning the repository:

```bash
uv sync
```
[Back to README](../../README.md) | [中文](../zh-CN/requirements.md)

# Requirements and environment setup

## Required tools

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. [DepotDownloader](https://github.com/SteamRE/DepotDownloader), with native `DepotDownloader` available in `PATH`
3. One supported agent CLI: Claude Code, Codex, or OpenCode
4. IDA Pro 9.0+
5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
6. [idalib](https://docs.hex-rays.com/user-guide/idalib), required by `ida_analyze_bin.py`
7. Clang/LLVM, with `clang++` available in `PATH` for local tests. [llvm-msvc](https://github.com/backengineering/llvm-msvc) is recommended on Windows.
8. [GitHub CLI](https://cli.github.com/)
9. [binsync](https://github.com/HLND2T/binsync) (optional, always use the HLND2T fork, you can clone it and ask claude/codex to install from source)

Install the Python dependencies after cloning the repository:

```bash
uv sync
```

## Cross-platform self-hosted CI

The seven self-hosted workflows use `[self-hosted, cross-platform]`. Assign that custom label to the intended x64
Ubuntu or Windows runners. Each job selects one runner. Both systems use the historical `win64` Environment's
secrets and protection policies. Linux uses Bash; PowerShell is only needed on Windows. Actions require Node 24 compatibility.

Ubuntu needs licensed Linux IDA/Hex-Rays, idalib-enabled `python` and matching `idalib-mcp` on the host PATH, the
configured agent CLI, Git/GitHub CLI, native DepotDownloader, and access to the existing S3 service.
Keep IDA separate from the uv project dependency environment; consumer preflight checks its version and MCP installation.
Release construction and verification also need 7-Zip (`7z`).

C++ CI runs on GitHub-hosted `windows-latest` and `ubuntu-latest`, using the exact source/SDK checkout,
configuration and immutable snapshot. It initializes MSVC/Windows SDK or the Linux compiler and needs no
self-hosted game binaries, IDA, S3 credentials or analysis secrets.

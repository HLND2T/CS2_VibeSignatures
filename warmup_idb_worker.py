"""Warm a single IDA database via bare headless idalib (no MCP server).

This is the low-level worker spawned by :mod:`warmup_idb`. It opens one binary
with auto-analysis enabled, blocks until auto-analysis finishes, then saves and
closes the database in place so ``<binary>.i64`` is left warm next to the binary.
Because it uses bare idalib rather than idalib-mcp, many workers can run
concurrently with no MCP port to contend for; each worker process owns exactly
one database, matching idalib's one-database-per-process rule.
"""

from __future__ import annotations

import argparse
import sys

# idapro must be imported first to initialize idalib.
import idapro  # noqa: F401
import ida_auto  # noqa: F401
import ida_loader  # noqa: F401


def warm_binary(binary_path: str) -> int:
    """Open, auto-analyze, save, and close one binary. Returns an exit code.

    ``open_database`` returns 0 on success and non-zero on failure (mirrors
    ida-pro-mcp's ``IDASessionManager`` and ``trace_dump``). Saving in place with
    ``save_database(None, 0)`` matches idalib-mcp's ``idb_save`` for the current
    IDB path.
    """
    if idapro.open_database(binary_path, run_auto_analysis=True) != 0:
        print(f"warmup: failed to open database: {binary_path}", file=sys.stderr)
        return 1

    try:
        ida_auto.auto_wait()
        if not ida_loader.save_database(None, 0):
            print(f"warmup: save_database returned false: {binary_path}", file=sys.stderr)
            return 1
    finally:
        idapro.close_database()

    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", help="Path to the binary whose IDB to warm.")
    args = parser.parse_args(argv)
    return warm_binary(args.binary)


if __name__ == "__main__":
    raise SystemExit(main())

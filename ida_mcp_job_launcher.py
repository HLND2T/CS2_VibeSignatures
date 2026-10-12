#!/usr/bin/env python3
"""Launch one idalib-mcp supervisor inside a kill-on-close Windows Job."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
from pathlib import Path

from windows_job import INFINITE, Kernel32JobApi


def _watch_parent(api: Kernel32JobApi, parent_handle) -> None:
    try:
        api.wait_for_process(parent_handle, INFINITE)
    finally:
        # Process exit closes our only Job handle, including after a parent crash.
        os._exit(1)


def run(parent_pid: int, command: list[str], *, api: Kernel32JobApi | None = None, exit_code_file=None) -> int:
    """Join the Job before spawning so detached server workers inherit it."""
    if not command:
        raise ValueError("idalib-mcp command is missing")
    job_api = api or Kernel32JobApi()
    parent_handle = job_api.open_live_process(parent_pid)
    job = job_api.create_job()
    try:
        job_api.set_kill_on_close(job)
        job_api.assign_current_process(job)
        threading.Thread(target=_watch_parent, args=(job_api, parent_handle), daemon=True).start()
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, close_fds=True)
        code = child.wait()
        if exit_code_file is not None:
            # Closing our own Job can terminate this launcher before sys.exit(code).
            # Persist the actual command status before closing its process tree.
            Path(exit_code_file).write_text(str(code), encoding="utf-8")
        return code
    finally:
        job_api.close_handle(job)
        # The parent handle is released when this short-lived launcher exits.


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--exit-code-file")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        return run(args.parent_pid, command, exit_code_file=args.exit_code_file)
    except (OSError, ValueError) as exc:
        print(f"idalib-mcp Job launcher failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

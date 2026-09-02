#!/usr/bin/env python3
"""Synchronize a verified binary-only workspace into the disposable accepted-bin cache."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.legacy_yaml_cleanup import cleanup_legacy_accepted_yaml
from release_workflow_lib.sync_accepted_bin import sync_accepted_bin


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sync = commands.add_parser("sync")
    sync.add_argument("--repo-root", default=".")
    sync.add_argument("--persisted-root", required=True)
    sync.add_argument("--gamever", required=True)
    cleanup = commands.add_parser("cleanup-legacy-yaml")
    cleanup.add_argument("--repo-root", default=".")
    cleanup.add_argument("--persisted-root", required=True)
    cleanup.add_argument("--gamever", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "sync":
            result = sync_accepted_bin(
                repo_root=Path(args.repo_root),
                persisted_root=Path(args.persisted_root),
                gamever=args.gamever,
            )
        else:
            result = cleanup_legacy_accepted_yaml(
                repo_root=Path(args.repo_root),
                persisted_root=Path(args.persisted_root),
                gamever=args.gamever,
            )
    except (OSError, ReleaseWorkflowError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Push accumulated IDA symbols to every configured binary's BinSync remote.

This is a best-effort, workflow-internal step: it resolves each configured
Windows/Linux binary from the analysis config and force-pushes the IDA
artifacts already persisted in that binary's ``.i64`` database. It never fails
the surrounding workflow — a missing interpreter or an individual push failure
is reported on stderr and the script still exits 0.
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from init_gamebin import configured_binary_paths, resolve_analysis_config  # noqa: E402

# Mirror the exact imports headless_force_push.py performs, so a passing probe
# guarantees the push script can actually start in the same interpreter.
CAPABILITY_PROBE = "import idapro, binsync.controller, declib.decompilers.ida.interface"


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gamever", help="Exact GAMEVER from download.yaml")
    parser.add_argument("--python", required=True, help="Interpreter with idalib + binsync + declib")
    parser.add_argument(
        "--headless-script",
        default=str(REPOSITORY_ROOT / "headless_force_push.py"),
        help="Path to headless_force_push.py (defaults to the repo copy)",
    )
    return parser.parse_args(argv)


def probe_capability(python_exe: str) -> tuple[bool, str]:
    """Return whether ``python_exe`` can import the push script's runtime deps."""
    result = subprocess.run([python_exe, "-c", CAPABILITY_PROBE], capture_output=True, text=True, check=False)
    if result.returncode == 0:
        return True, ""
    return False, (result.stderr or result.stdout).strip()


def push_binary(python_exe: str, headless_script: str, binary_path: Path) -> int:
    """Run headless_force_push.py for one binary in its own idalib process."""
    return subprocess.run(
        [python_exe, headless_script, str(binary_path), "--push"],
        check=False,
    ).returncode


def main(argv=None) -> int:
    args = parse_args(argv)

    python_exe = shutil.which(args.python)
    if not python_exe:
        print(f"BinSync push skipped: python not found: {args.python}", file=sys.stderr)
        return 0

    if not Path(args.headless_script).is_file():
        print(f"BinSync push skipped: headless script not found: {args.headless_script}", file=sys.stderr)
        return 0

    supported, detail = probe_capability(python_exe)
    if not supported:
        print(f"BinSync push skipped: {python_exe} lacks idalib/binsync/declib", file=sys.stderr)
        if detail:
            print(detail, file=sys.stderr)
        return 0

    config_path = resolve_analysis_config(args.gamever, repo_root=REPOSITORY_ROOT)
    binaries = configured_binary_paths(REPOSITORY_ROOT, args.gamever, config_path)

    pushed = 0
    failed = 0
    for binary_path in binaries:
        code = push_binary(python_exe, args.headless_script, binary_path)
        if code == 0:
            pushed += 1
        else:
            failed += 1
            print(f"BinSync push FAILED for {binary_path.name} (exit {code})", file=sys.stderr)

    print(f"BinSync push done: {pushed} pushed, {failed} failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

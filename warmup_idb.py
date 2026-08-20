#!/usr/bin/env python3
"""Concurrently warm IDA databases for every configured binary of one GAMEVER.

The release ``analyze`` step already reuses an existing ``<binary>.i64`` to skip
IDA's initial auto-analysis pass, so warming those databases ahead of the
analysis keeps that pass off the critical path. Each binary is warmed by a
separate bare-idalib worker process (:mod:`warmup_idb_worker`) so there is no
idalib-mcp port to contend for; ``--max-concurrency`` bounds how many workers
run at once (defaulting to ``$IDB_WARMUP_MAX_CONCURRENCY``, or 2 when unset),
and each worker has a bounded timeout.

Warming is a pure optimization. Worker failures trigger bounded cleanup so the
downstream analyze step can fall back to running auto-analysis inline. Cleanup
failures are reported explicitly rather than silently treating residual files
as a safe fallback.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from analysis_config import resolve_analysis_config  # noqa: E402
from init_gamebin import iter_configured_binaries  # noqa: E402

DEFAULT_MAX_CONCURRENCY = 2
DEFAULT_WORKER_TIMEOUT_SECONDS = 30 * 60
CONCURRENCY_ENV = "IDB_WARMUP_MAX_CONCURRENCY"
INVALIDATION_MAX_ATTEMPTS = 3
INVALIDATION_RETRY_DELAY_SECONDS = 1.0

# IDA database and side files, mirroring ida_analyze_bin._ida_database_paths.
_IDB_SUFFIXES = (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til")


def _ida_database_paths(binary_path: Path) -> list[Path]:
    base = str(binary_path)
    paths = [Path(f"{base}{suffix}") for suffix in _IDB_SUFFIXES]
    for packed in (f"{base}.i64", f"{base}.idb"):
        paths.extend(Path(f"{packed}{suffix}") for suffix in (".id0", ".id1", ".id2", ".nam", ".til"))
    return paths


def _is_warm(binary_path: Path) -> bool:
    """Return True when a packed database exists and no ``.id0`` lock remains."""
    packed = [Path(f"{binary_path}{suffix}") for suffix in (".i64", ".idb")]
    lock = Path(f"{binary_path}.id0")
    return any(path.is_file() for path in packed) and not lock.exists()


def _invalidate_ida_database(binary_path: Path) -> tuple[list[str], list[str]]:
    paths = _ida_database_paths(binary_path)
    removed = []
    removed_set = set()
    last_errors = {}

    for attempt in range(INVALIDATION_MAX_ATTEMPTS):
        attempt_errors = {}
        for path in paths:
            try:
                path.unlink()
                path_text = str(path)
                if path_text not in removed_set:
                    removed.append(path_text)
                    removed_set.add(path_text)
            except FileNotFoundError:
                continue
            except OSError as exc:
                attempt_errors[path] = str(exc)

        if not attempt_errors:
            return removed, []

        last_errors = attempt_errors
        if attempt + 1 < INVALIDATION_MAX_ATTEMPTS:
            time.sleep(INVALIDATION_RETRY_DELAY_SECONDS)

    failures = [f"{path}: {error}" for path, error in last_errors.items()]
    return removed, failures


def _invalidate_after_failure(binary_path: Path) -> None:
    _removed, failures = _invalidate_ida_database(binary_path)
    if failures:
        print(
            f"warmup: database cleanup incomplete for {binary_path.name}: {'; '.join(failures)}",
            file=sys.stderr,
        )


def _parse_concurrency(raw: str | None) -> int:
    if not raw:
        return DEFAULT_MAX_CONCURRENCY
    try:
        value = int(raw.strip())
    except ValueError:
        return DEFAULT_MAX_CONCURRENCY
    return value if value >= 1 else DEFAULT_MAX_CONCURRENCY


def _warm_one(
    python_exe: str,
    worker_script: Path,
    binary_path: Path,
    timeout_seconds: int = DEFAULT_WORKER_TIMEOUT_SECONDS,
) -> bool:
    command = [python_exe, str(worker_script), str(binary_path)]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        print(
            f"warmup: worker timed out after {timeout_seconds}s for {binary_path.name}",
            file=sys.stderr,
        )
        _invalidate_after_failure(binary_path)
        return False
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"warmup: worker could not run for {binary_path.name}: {exc}", file=sys.stderr)
        _invalidate_after_failure(binary_path)
        return False

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        print(f"warmup: worker failed for {binary_path.name}: {detail}", file=sys.stderr)
        _invalidate_after_failure(binary_path)
        return False
    if not _is_warm(binary_path):
        print(f"warmup: worker reported success but no warm database for {binary_path.name}", file=sys.stderr)
        _invalidate_after_failure(binary_path)
        return False
    return True


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gamever", help="Exact GAMEVER from download.yaml")
    parser.add_argument("--python", required=True, help="Interpreter with idalib (idapro)")
    parser.add_argument(
        "--worker-script",
        default=str(REPOSITORY_ROOT / "warmup_idb_worker.py"),
        help="Path to warmup_idb_worker.py (defaults to the repo copy)",
    )
    parser.add_argument(
        "--max-concurrency",
        default=os.environ.get(CONCURRENCY_ENV),
        help=f"Max concurrent workers (default: ${CONCURRENCY_ENV} or {DEFAULT_MAX_CONCURRENCY})",
    )
    parser.add_argument(
        "--worker-timeout-seconds",
        type=int,
        default=DEFAULT_WORKER_TIMEOUT_SECONDS,
        help=f"Timeout for each worker process (default: {DEFAULT_WORKER_TIMEOUT_SECONDS} seconds)",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    python_exe = shutil.which(args.python)
    if not python_exe:
        print(f"warmup: python not found: {args.python}", file=sys.stderr)
        return 1

    worker_script = Path(args.worker_script)
    if not worker_script.is_file():
        print(f"warmup: worker script not found: {worker_script}", file=sys.stderr)
        return 1

    config_path = resolve_analysis_config(args.gamever, repo_root=REPOSITORY_ROOT)
    binaries = [
        binary_path
        for _module, _platform, binary_path in iter_configured_binaries(REPOSITORY_ROOT, args.gamever, config_path)
    ]

    pending = [binary for binary in binaries if not _is_warm(binary)]
    skipped = len(binaries) - len(pending)
    if not pending:
        print(f"warmup: all {len(binaries)} databases already warm; nothing to do.")
        return 0

    max_concurrency = _parse_concurrency(args.max_concurrency)
    if args.worker_timeout_seconds < 1:
        print("warmup: --worker-timeout-seconds must be at least 1", file=sys.stderr)
        return 1
    print(
        f"warmup: {len(binaries)} configured binaries, {skipped} already warm, "
        f"{len(pending)} to warm (max concurrency {max_concurrency}, "
        f"worker timeout {args.worker_timeout_seconds}s)"
    )

    warmed = 0
    failed = 0
    with ThreadPoolExecutor(max_workers=max_concurrency) as pool:
        futures = {
            pool.submit(_warm_one, python_exe, worker_script, binary, args.worker_timeout_seconds): binary
            for binary in pending
        }
        for future in as_completed(futures):
            binary = futures[future]
            try:
                success = future.result()
            except Exception as exc:
                print(f"warmup: unexpected worker error for {binary.name}: {exc}", file=sys.stderr)
                _invalidate_after_failure(binary)
                success = False
            if success:
                warmed += 1
                print(f"warmup: warmed {binary.name}")
            else:
                failed += 1

    print(f"warmup: done; {warmed} warmed, {failed} failed, {skipped} already warm")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

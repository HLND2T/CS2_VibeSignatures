"""
Headless BinSync state export — a standalone, GUI-free way to commit Reverse
Engineering Artifact currently present in an IDA database into a BinSync Git
project.

It is meant to run inside a **headless idalib** process (IDA 9+). idalib is a
plain Python library, so you invoke this script with the ordinary ``python``
interpreter of an environment that has ``idalib`` (``idapro``), ``binsync`` and
``declib`` installed::

    python examples/headless_force_push.py <binary> [options]

--------------------------------------------------------------------------------
Why not the GUI plugin?
--------------------------------------------------------------------------------
The BinSync IDA plugin (``BinsyncPlugin``) is a GUI plugin and is never loaded in
headless idalib — ``PLUGIN_ENTRY`` bails out unless ``IDA_IS_INTERACTIVE`` is set.
This module instead builds the same pieces the plugin would (a headless
``declib`` IDA interface plus a ``BSController``) and drives ``force_push_*``
directly. No Qt, no dialogs, no artifact watchers.

--------------------------------------------------------------------------------
Database ownership (important)
--------------------------------------------------------------------------------
idalib can only have one database open per process, and two processes cannot
open the same ``.i64`` at once (IDA holds a ``.id0`` lock). Run this script in a
*different* process than your analysis / MCP server, and only after that process
has closed the database. declib's headless interface reopens the existing
``<binary>.i64`` (or ``.idb``) next to the binary, so any renames / types /
comments your analysis already persisted are picked up automatically.

--------------------------------------------------------------------------------
Sidecar config
--------------------------------------------------------------------------------
Connection details are read from ``<binary>.binsync.json`` in the same directory
as the binary — the same schema consumed by the GUI auto-recover in
``binsync/auto_recover.py``::

    {
        "user": "HZDEV",            // optional; fallback when the OS user can't be resolved
        "remote": "https://...",    // clone source when the local repo is missing
        "repo_path": null,          // optional; default is <binary>.bsproj
        "expected_md5": "...",      // optional; skip when it mismatches the loaded binary's md5
        "force_user": false         // optional; use "user" verbatim instead of the OS user
    }

Every value can be overridden on the command line (``--user``, ``--repo``,
``--remote``) or with an explicit ``--sidecar`` path.

--------------------------------------------------------------------------------
Examples
--------------------------------------------------------------------------------
    # dry run: connect and print what would be pushed (no commit / push)
    python headless_force_push.py D:/bins/client.dll

    # commit locally while redirecting BinSync's mandatory push to an isolated sink
    python headless_force_push.py D:/bins/client.dll --push --local-only

    # also push full function headers (args + stack vars) — needs Hex-Rays
    python headless_force_push.py D:/bins/client.dll --push --local-only --use-decompilation

    # no sidecar: specify everything inline
    python headless_force_push.py D:/bins/client.dll --push --local-only \\
        --user HZDEV --repo D:/bins/client.dll.bsproj \\
        --remote https://github.com/HLND2T/CS2_VibeSignatures_binsync_14174_client.dll

Notes
--------------------------------------------------------------------------------
* Hex-Rays is usually unavailable headless; without ``--use-decompilation`` only
  function names / return types plus comments are pushed (still a full "header"
  push, but no arguments or stack variables).
* Keep everything on the main thread: ``connect(..., single_thread=True)`` skips
  BinSync's background worker threads so nothing else touches idalib off-thread.
* Direct canonical-remote push is disabled. Publication uses verified Git bundles
  in the protected hosted publisher.
* Git must be installed and reachable (BinSync uses GitPython).
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import logging
import pathlib
import re
import subprocess
import tempfile

_log = logging.getLogger("binsync.headless_force_push")
IDAInterface = None
BSController = None
ConnectionWarnings = None


def _load_runtime_dependencies() -> None:
    global IDAInterface, BSController, ConnectionWarnings
    if IDAInterface is not None:
        return
    try:
        # declib's IDA interface is Qt-free when IDA_IS_INTERACTIVE is unset —
        # unlike binsync's GUI IDABSInterface wrapper, it does not import Qt.
        from declib.decompilers.ida.interface import IDAInterface as RuntimeIDAInterface
        from binsync.controller import BSController as RuntimeBSController
        from binsync.core.client import ConnectionWarnings as RuntimeConnectionWarnings
    except ImportError as exc:  # pragma: no cover - only meaningful outside idalib
        raise SystemExit(
            "headless_force_push.py must run in an idalib (IDA 9+) environment with "
            "binsync + declib installed.\n"
            f"Import error: {exc}"
        ) from exc
    IDAInterface = RuntimeIDAInterface
    BSController = RuntimeBSController
    ConnectionWarnings = RuntimeConnectionWarnings


BINSYNC_SIDECAR_SUFFIX = ".binsync.json"
DEFAULT_REPO_SUFFIX = ".bsproj"
TRUSTED_REMOTE_RE = re.compile(r"^https://github\.com/HLND2T/CS2_VibeSignatures_binsync_[A-Za-z0-9_.-]+$")


def find_sidecar(binary_path: pathlib.Path) -> pathlib.Path:
    """Path of the sidecar config for ``binary_path`` (``<binary>.binsync.json``)."""
    return pathlib.Path(str(binary_path) + BINSYNC_SIDECAR_SUFFIX)


class SidecarConfig:
    """Parsed ``<binary>.binsync.json`` — mirrors ``binsync.auto_recover.AutoRecoverConfig``."""

    __slots__ = ("binary_path", "sidecar_path", "user", "remote", "repo_path", "expected_md5", "force_user")

    def __init__(self, binary_path: pathlib.Path, data: dict):
        self.binary_path = binary_path
        self.sidecar_path = find_sidecar(binary_path)
        self.user = data.get("user")
        self.remote = data.get("remote") or None
        self.expected_md5 = data.get("expected_md5")
        self.force_user = bool(data.get("force_user", False))

        raw_repo = data.get("repo_path")
        if raw_repo:
            repo = pathlib.Path(raw_repo)
            if not repo.is_absolute():
                repo = binary_path.parent / repo
            self.repo_path = repo
        else:
            # default mirrors the GUI auto-recover: <binary>.bsproj next to the binary
            self.repo_path = binary_path.with_suffix(DEFAULT_REPO_SUFFIX)


def resolve_user(cfg: SidecarConfig | None, cli_user: str | None) -> str:
    """Resolve the BinSync user identity: CLI > sidecar force_user > OS user > sidecar > "user"."""
    if cli_user:
        return cli_user

    if cfg is not None and cfg.force_user and cfg.user:
        return cfg.user

    try:
        os_user = getpass.getuser()
    except Exception:
        os_user = None

    return os_user or (cfg.user if cfg else None) or "user"


def build_controller(binary_path: pathlib.Path) -> BSController:
    """Build a headless BinSync controller on top of a headless IDA interface.

    ``IDAInterface(headless=True, ...)`` calls ``idapro.open_database`` itself,
    reopening the existing ``<binary>.i64`` when one is present.
    """
    _load_runtime_dependencies()
    deci = IDAInterface(headless=True, binary_path=str(binary_path))
    return BSController(decompiler_interface=deci, headless=True)


def connect_controller(controller: BSController, user: str, repo: pathlib.Path, remote: str | None) -> None:
    """Connect to an existing project, or clone it from ``remote`` when missing.

    ``single_thread=True`` keeps BinSync from spawning background worker threads
    (idalib requires all IDA API access to happen on the main thread).
    """
    if repo.exists():
        _log.info("Connecting to existing project %s as %s", repo, user)
        warnings = controller.connect(user, str(repo), init_repo=False, remote_url=None, single_thread=True)
    elif remote:
        _log.info("Cloning %s from %s as %s", repo, remote, user)
        warnings = controller.connect(user, str(repo), init_repo=False, remote_url=remote, single_thread=True)
    else:
        raise SystemExit(f"BinSync repo {repo} does not exist and no --remote / sidecar remote is set.")

    if ConnectionWarnings.HASH_MISMATCH in warnings:
        _log.warning("Repository binary hash does not match the loaded binary (md5 mismatch).")


def collect_artifacts(controller: BSController) -> dict[str, list]:
    """Enumerate every artifact type straight from the decompiler (not the BS State)."""
    deci = controller.deci
    return {
        "functions": list(deci.functions.keys()),
        "globals": list(deci.global_vars.keys()),
        "types": list(deci.structs.keys()) + list(deci.enums.keys()) + list(deci.typedefs.keys()),
        "segments": list(deci.segments.keys()),
    }


def force_push_all(controller: BSController, arts: dict[str, list], use_decompilation: bool = False) -> None:
    """Force push every collected artifact in a single commit + push."""
    controller.force_push_all(
        arts["functions"],
        arts["globals"],
        arts["types"],
        arts["segments"],
        use_decompilation=use_decompilation,
    )


def force_push_selected(
    controller: BSController, func_addrs: list[int], global_addrs: list[int], use_decompilation: bool = False
) -> None:
    """Force push only the listed functions + globals (no types or segments)."""
    controller.force_push_all(
        func_addrs,
        global_addrs,
        [],
        [],
        use_decompilation=use_decompilation,
    )


def load_manifest(artifacts_file: str) -> dict[str, list]:
    """Load a push manifest ``{"functions": [...], "globals": [...]}`` (addrs in lifted/RVA form)."""
    data = json.loads(pathlib.Path(artifacts_file).read_text(encoding="utf-8"))
    return {
        "functions": list(data.get("functions", [])),
        "globals": list(data.get("globals", [])),
    }


def print_summary(arts: dict[str, list]) -> None:
    print("BinSync force push — collected artifacts:")
    print(f"  functions : {len(arts['functions'])}")
    print(f"  globals   : {len(arts['globals'])}")
    print(f"  types     : {len(arts['types'])} (structs + enums + typedefs)")
    print(f"  segments  : {len(arts['segments'])}")


def _git(arguments: list[str], cwd: pathlib.Path | None = None) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise SystemExit(detail or f"git {' '.join(arguments)} failed with exit {result.returncode}")
    return result.stdout.strip()


def _remote_heads(remote: str) -> dict[str, str]:
    output = _git(["ls-remote", "--heads", "--refs", remote])
    heads = {}
    for line in output.splitlines():
        commit, ref = line.split("\t", 1)
        if ref in heads or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise SystemExit(f"invalid remote ref response from {remote}: {line!r}")
        heads[ref] = commit
    return heads


@contextlib.contextmanager
def local_only_remote(repo: pathlib.Path, remote: str):
    """Redirect BinSync's mandatory push to a temporary bare sink and prove no remote drift."""
    if not TRUSTED_REMOTE_RE.fullmatch(remote):
        raise SystemExit(f"local-only BinSync export requires a canonical public remote: {remote!r}")
    original = _git(["remote", "get-url", "origin"], cwd=repo)
    if original != remote:
        raise SystemExit(f"local BinSync origin differs from the canonical remote: {repo}")
    before = _remote_heads(remote)
    with tempfile.TemporaryDirectory(prefix="binsync-local-sink-") as temporary:
        sink = pathlib.Path(temporary) / "sink.git"
        _git(["clone", "--bare", "--no-tags", remote, str(sink)])
        _git(["remote", "set-url", "origin", str(sink)], cwd=repo)
        try:
            yield
        finally:
            _git(["remote", "set-url", "origin", remote], cwd=repo)
            after = _remote_heads(remote)
            if after != before:
                raise SystemExit(f"local-only BinSync export changed remote refs for {remote}")


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="headless_force_push.py",
        description="Force push all IDA artifacts into a BinSync project (headless idalib).",
    )
    parser.add_argument("binary", help="Path to the original binary (used to open the DB and locate the sidecar).")
    parser.add_argument(
        "--push",
        action="store_true",
        help="Commit through --local-only. Without this flag the command is a dry run.",
    )
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="Commit through an isolated local bare sink and prove the canonical remote did not change.",
    )
    parser.add_argument("--user", help="Override the BinSync user identity.")
    parser.add_argument("--repo", help="Override the local BinSync repo path (default <binary>.bsproj).")
    parser.add_argument("--remote", help="Override the remote URL to clone when the repo is missing.")
    parser.add_argument("--sidecar", help="Explicit sidecar path (default <binary>.binsync.json).")
    parser.add_argument(
        "--use-decompilation",
        action="store_true",
        help="Also push function args + stack vars (requires Hex-Rays; usually unavailable headless).",
    )
    parser.add_argument(
        "--artifacts-file",
        help='JSON manifest {"functions": [...], "globals": [...]} restricting the push to those '
        "lifted/RVA addresses. Types and segments are skipped when a manifest is provided.",
    )
    parser.add_argument(
        "--ignore-md5",
        action="store_true",
        help="Skip the sidecar expected_md5 sanity check.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")

    binary_path = pathlib.Path(args.binary).resolve()
    if not binary_path.exists():
        raise SystemExit(f"Binary not found: {binary_path}")

    sidecar_path = pathlib.Path(args.sidecar) if args.sidecar else find_sidecar(binary_path)
    cfg = None
    if sidecar_path.exists():
        try:
            cfg = SidecarConfig(binary_path, json.loads(sidecar_path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            raise SystemExit(f"Failed to read sidecar {sidecar_path}: {exc}") from exc
        _log.info("Loaded sidecar %s", sidecar_path)
    else:
        _log.info("No sidecar at %s; using command-line args only.", sidecar_path)

    user = resolve_user(cfg, args.user)

    if args.repo:
        repo = pathlib.Path(args.repo)
        if not repo.is_absolute():
            repo = binary_path.parent / repo
    elif cfg is not None:
        repo = cfg.repo_path
    else:
        repo = binary_path.with_suffix(DEFAULT_REPO_SUFFIX)

    remote = args.remote or (cfg.remote if cfg else None)
    if args.push and not args.local_only:
        raise SystemExit("direct BinSync remote publication is disabled; use the protected bundle publisher")
    if args.local_only and (not args.push or remote is None or not repo.is_dir()):
        raise SystemExit("--local-only requires --push, an existing local repo, and a canonical remote")

    def export() -> None:
        controller = build_controller(binary_path)
        try:
            # optional md5 sanity check (mirrors binsync/auto_recover.py)
            if cfg is not None and cfg.expected_md5 and not args.ignore_md5:
                current_md5 = controller.deci.binary_hash
                if current_md5 != cfg.expected_md5:
                    raise SystemExit(
                        f"md5 mismatch for {binary_path.name}: expected {cfg.expected_md5}, got {current_md5}"
                    )

            connect_controller(controller, user, repo, remote)
            if args.artifacts_file:
                manifest = load_manifest(args.artifacts_file)
                func_addrs = manifest["functions"]
                global_addrs = manifest["globals"]
                print("BinSync force push — selected artifacts (from manifest):")
                print(f"  functions : {len(func_addrs)}")
                print(f"  globals   : {len(global_addrs)}")
                if not args.push:
                    _log.info("Dry run: nothing committed/pushed. Re-run with --push to apply.")
                else:
                    force_push_selected(controller, func_addrs, global_addrs, use_decompilation=args.use_decompilation)
                    _log.info("Local BinSync commit complete." if args.local_only else "Force push complete.")
            else:
                arts = collect_artifacts(controller)
                print_summary(arts)
                if not args.push:
                    _log.info("Dry run: nothing committed/pushed. Re-run with --push to apply.")
                else:
                    force_push_all(controller, arts, use_decompilation=args.use_decompilation)
                    _log.info("Local BinSync commit complete." if args.local_only else "Force push complete.")
        finally:
            controller.shutdown()

    if args.local_only:
        with local_only_remote(repo, remote):
            export()
    else:
        export()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

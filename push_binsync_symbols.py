#!/usr/bin/env python3
"""Prepare credential-free BinSync commits and publication bundles locally.

Each configured Windows/Linux binary is resolved from the analysis config and
exported from the IDA artifacts already persisted in that binary's ``.i64``
database. The headless exporter redirects BinSync's mandatory push to an isolated
local sink. This command never publishes canonical remote refs; the protected
hosted publisher consumes the resulting verified Git bundles.
"""

import argparse
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from init_gamebin import (  # noqa: E402
    BINSYNC_ROOT_BRANCH,
    GITHUB_OWNER,
    InitGamebinError,
    expected_sidecar,
    file_md5,
    iter_configured_binaries,
    load_yaml_document,
    resolve_analysis_config,
    run_command,
    validate_local_binsync_repo,
    validate_sidecar,
    write_sidecar_atomic,
)
from binsync_candidate import BinSyncCandidateError, _digest, _remote_heads, build_candidate  # noqa: E402
from release_workflow_lib.hashing import write_canonical_json  # noqa: E402

# Symbol categories that map to a BinSync function vs. global-variable artifact.
FUNCTION_CATEGORIES = frozenset({"func", "vfunc"})
GLOBAL_CATEGORIES = frozenset({"gv"})

# Mirror the exact imports headless_force_push.py performs, so a passing probe
# guarantees the push script can actually start in the same interpreter.
CAPABILITY_PROBE = "import idapro, binsync.controller, declib.decompilers.ida.interface"


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gamever", help="Exact GAMEVER from download.yaml")
    parser.add_argument(
        "--prepare-only", action="store_true", help="Create local commits and bundles without remote writes"
    )
    parser.add_argument(
        "--no-publication-candidate",
        action="store_true",
        help="Bootstrap-only: validate local BinSync export without producing reusable publication bundles",
    )
    parser.add_argument("--candidate-dir", help="Fresh output directory for the internal publication candidate")
    parser.add_argument("--artifactdir", default="bin_artifacts", help="Validated per-symbol artifact root")
    parser.add_argument("--preparation", help="Verified release rebuild preparation JSON")
    parser.add_argument("--release-version", help="Immutable release version bound into the candidate")
    parser.add_argument("--build-id", help="Workflow run/attempt build identity")
    parser.add_argument("--ida-runtime-identity", help="Exact IDA runtime identity")
    parser.add_argument("--actions-artifact-name", help="Internal Actions Artifact name")
    parser.add_argument("--binsync-user", default="release-automation", help="Dedicated local publication branch user")
    parser.add_argument("--python", default=sys.executable, help="Interpreter with idalib + binsync + declib")
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


def push_binary(python_exe: str, headless_script: str, binary_path: Path, manifest_path: Path) -> int:
    """Export one binary through a local-only BinSync sink in its own idalib process."""
    cmd = [python_exe, headless_script, str(binary_path), "--push", "--local-only"]
    if manifest_path is not None:
        cmd += ["--artifacts-file", str(manifest_path)]
    return subprocess.run(cmd, check=False).returncode


def _pe_first_section_rva(data: bytes) -> int:
    """Return the RVA (offset from the image base) of the first PE section.

    declib's ``binary_base_addr`` is ``get_first_segment_base()`` -- the VA of
    IDA's first segment, which for a PE is the first (lowest-address) section,
    i.e. ``image_base + <section RVA>`` (0x1000 for ``.text`` in these game
    binaries). This is the address-space offset declib subtracts when lifting.
    """
    if data[:2] != b"MZ":
        raise ValueError("not a PE (missing MZ signature)")
    if len(data) < 0x40:
        raise ValueError("truncated DOS header")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\x00\x00":
        raise ValueError("invalid PE signature")
    num_sections = struct.unpack_from("<H", data, pe + 6)[0]
    size_opt = struct.unpack_from("<H", data, pe + 20)[0]
    sec_tbl = pe + 24 + size_opt
    if num_sections == 0:
        raise ValueError("PE has no sections")
    first_rva = None
    for index in range(num_sections):
        off = sec_tbl + index * 40
        if off + 40 > len(data):
            raise ValueError("truncated PE section table")
        rva = struct.unpack_from("<I", data, off + 12)[0]
        if first_rva is None or rva < first_rva:
            first_rva = rva
    if first_rva is None:
        raise ValueError("PE has no sections")
    return first_rva


def _first_segment_lift_bias(binary_path: Path) -> int:
    """Address delta between a YAML ``*_rva`` and BinSync's lifted key.

    ``{symbol}.{platform}.yaml`` stores ``func_rva = func_va - image_base`` (the
    PE image base, 0x180000000 for these; 0 for ELF). BinSync's declib interface
    keys functions/globals by ``func_va - get_first_segment_base()``, where the
    "first segment" is the *lowest-address* IDA segment -- ``.text`` for a PE,
    which starts at ``image_base + first_section_rva``. The two conventions
    differ by the first section's RVA on Windows and coincide on Linux (these
    ELF shared objects load at vaddr 0, so the first segment base is 0):

        windows:  declib key == func_rva - 0x1000   (.text at RVA 0x1000)
        linux:    declib key == func_rva

    Return the amount to subtract from a YAML ``*_rva`` so the manifest matches
    declib's lifted keys, i.e. BinSync can find the function/global by address.
    """
    data = binary_path.read_bytes()
    if data[:4] == b"\x7fELF":
        # ELF shared objects in this repo load at vaddr 0; YAML rva == func_va
        # == declib's lifted key already.
        return 0
    if data[:2] == b"MZ":
        return _pe_first_section_rva(data)
    raise ValueError(f"unsupported binary format for lift bias: {binary_path}")


def collect_manifest_symbols(
    root: Path,
    gamever: str,
    config_path: Path,
    artifact_root: Path | None = None,
) -> dict[str, dict[str, list[int]]]:
    """Map ``(module, platform) -> {"functions": [rva, ...], "globals": [rva, ...]}``.

    Only ``func``/``vfunc`` and ``gv`` symbols explicitly declared under each
    module's ``symbols:`` are selected. The target address is read from the
    generated ``{symbol}.{platform}.yaml`` (``func_rva`` for functions, ``gv_rva``
    for globals). The YAML ``*_rva`` is relative to the PE image base on Windows
    and to vaddr 0 on Linux; BinSync's declib key is relative to the first
    (lowest-address) IDA segment, so the ``*_rva`` is adjusted by the first
    section's RVA on Windows (0x1000 here) before the manifest is built.
    Types, segments, and undeclared functions/globals are deliberately excluded.
    """
    document = load_yaml_document(config_path, "analysis config")
    modules = document.get("modules") or []
    manifest: dict[str, dict[str, list[int]]] = {}
    artifact_game_root = (artifact_root or (root / "bin_artifacts")) / gamever

    for module_name, platform, binary_path in iter_configured_binaries(root, gamever, config_path):
        module_dir = artifact_game_root / module_name
        try:
            lift_bias = _first_segment_lift_bias(binary_path)
        except ValueError as exc:
            print(
                f"BinSync push skipped (unsupported binary): {binary_path.name}: {exc}",
                file=sys.stderr,
            )
            continue
        functions: list[int] = []
        globals: list[int] = []

        for module in modules:
            if module.get("name") != module_name:
                continue
            for symbol in module.get("symbols") or []:
                category = symbol.get("category")
                symbol_name = symbol.get("name")
                if not isinstance(symbol_name, str) or category not in FUNCTION_CATEGORIES | GLOBAL_CATEGORIES:
                    continue
                symbol_platform = symbol.get("platform")
                if symbol_platform and symbol_platform != platform:
                    continue

                yaml_path = module_dir / f"{symbol_name}.{platform}.yaml"
                try:
                    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
                except (OSError, yaml.YAMLError):
                    continue

                key = "func_rva" if category in FUNCTION_CATEGORIES else "gv_rva"
                raw = data.get(key)
                try:
                    addr = int(str(raw), 0)
                except (TypeError, ValueError):
                    continue
                # Convert the YAML rva (relative to image base / vaddr 0) to the
                # declib lifted key (relative to the first IDA segment) so BinSync
                # finds the artifact by address. No-op on Linux (bias 0).
                addr -= lift_bias
                (functions if category in FUNCTION_CATEGORIES else globals).append(addr)

        manifest[f"{module_name}/{platform}"] = {
            "functions": sorted(set(functions)),
            "globals": sorted(set(globals)),
        }

    return manifest


def build_manifest(entries: dict[str, list]) -> Path:
    """Write a temp JSON manifest and return its path."""
    fd, path = tempfile.mkstemp(prefix="binsync_manifest_", suffix=".json")
    with open(fd, "w", encoding="utf-8") as handle:
        json.dump(entries, handle)
    return Path(path)


def _git_result(arguments: list[str], cwd: Path, *, allowed=(0,)):
    try:
        return run_command(arguments, cwd, allowed=allowed, capture=True, label=" ".join(arguments[:2]))
    except InitGamebinError as exc:
        raise RuntimeError(str(exc)) from exc


def _prepare_local_repository(binary_path: Path, gamever: str, user: str) -> tuple[str, str]:
    binary_md5 = file_md5(binary_path)
    repo_name, remote_url, repo_path, _default_sidecar = expected_sidecar(binary_path, binary_md5, gamever, user)
    sidecar_path = Path(f"{binary_path}.binsync.json")
    sidecar_data = {
        "user": user,
        "remote": remote_url,
        "repo_path": repo_path.name,
        "expected_md5": binary_md5,
        "force_user": True,
        "auto_clone": False,
        "auto_sync_all": False,
    }
    if not repo_path.exists():
        _git_result(["git", "clone", "--no-tags", remote_url, str(repo_path)], binary_path.parent)
    exists, locked = validate_local_binsync_repo(repo_path, binary_md5, repo_name)
    if not exists or locked:
        state = "missing" if not exists else "locked"
        raise RuntimeError(f"local BinSync repository is {state}: {repo_path}")

    user_ref = f"refs/heads/binsync/{user}"
    remote_user_ref = f"refs/remotes/origin/binsync/{user}"
    ref_check = _git_result(["git", "check-ref-format", user_ref], repo_path, allowed=(0, 1))
    if ref_check.returncode:
        raise RuntimeError(f"invalid dedicated BinSync publication user: {user!r}")
    local_exists = _git_result(["git", "show-ref", "--verify", "--quiet", user_ref], repo_path, allowed=(0, 1))
    if local_exists.returncode == 0:
        _git_result(["git", "switch", f"binsync/{user}"], repo_path)
    else:
        remote_exists = _git_result(
            ["git", "show-ref", "--verify", "--quiet", remote_user_ref], repo_path, allowed=(0, 1)
        )
        start = remote_user_ref if remote_exists.returncode == 0 else f"refs/heads/{BINSYNC_ROOT_BRANCH}"
        _git_result(["git", "switch", "--create", f"binsync/{user}", start], repo_path)

    if validate_sidecar(sidecar_path, sidecar_data):
        pass
    else:
        write_sidecar_atomic(sidecar_path, sidecar_data)
    return f"{GITHUB_OWNER}__{repo_name}", remote_url


def prepare_local_repositories(root: Path, gamever: str, config_path: Path, user: str) -> dict[str, dict]:
    """Clone allowlisted public remotes read-only and select one dedicated local user ref."""
    snapshots = {}
    for _module, _platform, binary_path in iter_configured_binaries(root, gamever, config_path):
        repository_id, remote_url = _prepare_local_repository(binary_path, gamever, user)
        snapshots[repository_id] = {"remote_url": remote_url, "heads": _remote_heads(remote_url)}
    return snapshots


def assert_remote_refs_unchanged(snapshots: dict[str, dict]) -> str:
    for repository_id, snapshot in snapshots.items():
        if _remote_heads(snapshot["remote_url"]) != snapshot["heads"]:
            raise RuntimeError(f"local BinSync preparation changed canonical remote refs: {repository_id}")
    evidence = [
        {"repository_id": repository_id, "remote_url": value["remote_url"], "heads": value["heads"]}
        for repository_id, value in sorted(snapshots.items())
    ]
    return _digest("binsync-local-only-remote-refs:v1", evidence)


def write_bootstrap_local_evidence(
    candidate_dir: str | Path,
    gamever: str,
    snapshots: dict[str, dict],
    remote_refs_digest: str,
) -> None:
    root = Path(candidate_dir)
    if root.exists():
        raise RuntimeError(f"bootstrap local evidence root must be fresh: {root}")
    repositories = [
        {
            "repository_id": repository_id,
            "remote_url": value["remote_url"],
            "remote_refs_sha256": _digest("binsync-remote-ref-set:v1", value["heads"]),
        }
        for repository_id, value in sorted(snapshots.items())
    ]
    document = {
        "schema_version": 1,
        "game_version": str(gamever),
        "binsync_mode": "bootstrap-local-only",
        "remote_refs_before_sha256": remote_refs_digest,
        "remote_refs_after_sha256": remote_refs_digest,
        "repositories": repositories,
    }
    document["evidence_sha256"] = _digest("binsync-bootstrap-local-evidence:v1", document)
    write_canonical_json(root / "local-evidence.json", document)


def main(argv=None) -> int:
    args = parse_args(argv)

    if not args.prepare_only:
        print(
            "Direct BinSync publication is disabled; use --prepare-only and the protected publisher.", file=sys.stderr
        )
        return 2
    required = {"candidate-dir": args.candidate_dir}
    if not args.no_publication_candidate:
        required.update(
            {
                "preparation": args.preparation,
                "release-version": args.release_version,
                "build-id": args.build_id,
                "ida-runtime-identity": args.ida_runtime_identity,
                "actions-artifact-name": args.actions_artifact_name,
            }
        )
    missing = [name for name, value in required.items() if not value]
    if missing:
        print("BinSync prepare failed: missing " + ", ".join(missing), file=sys.stderr)
        return 2

    python_exe = shutil.which(args.python)
    if not python_exe:
        print(f"BinSync push failed: python not found: {args.python}", file=sys.stderr)
        return 1

    if not Path(args.headless_script).is_file():
        print(f"BinSync push failed: headless script not found: {args.headless_script}", file=sys.stderr)
        return 1

    supported, detail = probe_capability(python_exe)
    if not supported:
        print(f"BinSync push failed: {python_exe} lacks idalib/binsync/declib", file=sys.stderr)
        if detail:
            print(detail, file=sys.stderr)
        return 1

    config_path = resolve_analysis_config(args.gamever, repo_root=REPOSITORY_ROOT)
    artifact_root = Path(args.artifactdir).resolve()
    try:
        remote_snapshots = prepare_local_repositories(
            REPOSITORY_ROOT,
            args.gamever,
            config_path,
            args.binsync_user,
        )
        manifests = collect_manifest_symbols(REPOSITORY_ROOT, args.gamever, config_path, artifact_root)
    except (BinSyncCandidateError, InitGamebinError, OSError, RuntimeError, ValueError) as exc:
        print(f"BinSync prepare failed: {exc}", file=sys.stderr)
        return 1

    pushed = 0
    failed = 0
    for module_name, platform, binary_path in iter_configured_binaries(REPOSITORY_ROOT, args.gamever, config_path):
        entries = manifests.get(f"{module_name}/{platform}")
        if entries is None or not (entries["functions"] or entries["globals"]):
            print(f"BinSync prepare skipped (no declared symbols): {binary_path.name}", file=sys.stderr)
            continue
        manifest_path = build_manifest(entries)
        try:
            code = push_binary(python_exe, args.headless_script, binary_path, manifest_path)
        finally:
            manifest_path.unlink(missing_ok=True)
        if code == 0:
            pushed += 1
        else:
            failed += 1
            print(f"BinSync local prepare FAILED for {binary_path.name} (exit {code})", file=sys.stderr)

    try:
        remote_refs_digest = assert_remote_refs_unchanged(remote_snapshots)
        if failed:
            raise RuntimeError(f"{failed} local BinSync exports failed")
        if args.no_publication_candidate:
            write_bootstrap_local_evidence(
                args.candidate_dir,
                args.gamever,
                remote_snapshots,
                remote_refs_digest,
            )
        else:
            build_candidate(
                repo_root=REPOSITORY_ROOT,
                preparation=args.preparation,
                candidate_root=args.candidate_dir,
                release_version=args.release_version,
                build_id=args.build_id,
                ida_runtime_identity=args.ida_runtime_identity,
                actions_artifact_name=args.actions_artifact_name,
            )
    except (BinSyncCandidateError, OSError, RuntimeError) as exc:
        print(f"BinSync candidate build failed: {exc}", file=sys.stderr)
        return 1
    print(f"BinSync local prepare done: {pushed} updated, {failed} failed; candidate={args.candidate_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

import argparse
import io
import subprocess
import tarfile
import traceback
from pathlib import Path

from analysis_config import AnalysisConfigError, resolve_analysis_config
from gamesymbol_snapshot_lib.errors import SnapshotConfigError, SnapshotMismatchError
from gamesymbol_snapshot_lib.config import LATEST_CONFIG_DIGEST_VERSION, load_contract
from gamesymbol_snapshot_lib.model import ChangedPath, SnapshotContext
from gamesymbol_snapshot_lib.operations import load_snapshot_context
from gamesymbol_snapshot_lib.paths import ensure_real_tree, path_from_key
from gamesymbol_snapshot_lib.pr_validation import build_invalidation_plan, required_source_index_sides


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Invalidate PR-affected game-symbol outputs")
    parser.add_argument("invalidate", nargs="?", default="invalidate")
    parser.add_argument("-gamever", required=True)
    parser.add_argument("-bindir", default="bin")
    parser.add_argument("-baseconfigyaml", required=True)
    parser.add_argument("-basesnapshot", required=True)
    parser.add_argument(
        "-headconfigyaml",
        default=None,
        help="Head analysis config; defaults to configs/<GAMEVER>.yaml",
    )
    parser.add_argument("-headsnapshot")
    parser.add_argument("-baseref", default="HEAD^1")
    parser.add_argument("-headref", default="HEAD")
    parser.add_argument("-debug", action="store_true")
    return parser.parse_args(argv)


def _decode_git_field(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnapshotConfigError(f"Git returned a non-UTF-8 path: {exc}") from exc


def _parse_changed_paths(raw: bytes) -> list[ChangedPath]:
    fields = raw.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    changes = []
    index = 0
    while index < len(fields):
        status_token = _decode_git_field(fields[index])
        index += 1
        status = status_token[:1]
        if status not in {"A", "M", "D", "R", "C"}:
            raise SnapshotConfigError(f"error[unsupported_git_status]: {status_token}")
        required_paths = 2 if status in {"R", "C"} else 1
        if index + required_paths > len(fields):
            raise SnapshotConfigError(f"malformed git diff --name-status record for {status_token}")
        paths = [_decode_git_field(value) for value in fields[index : index + required_paths]]
        index += required_paths
        if status == "A":
            changes.append(ChangedPath(status, None, paths[0]))
        elif status == "D":
            changes.append(ChangedPath(status, paths[0], None))
        elif status == "M":
            changes.append(ChangedPath(status, paths[0], paths[0]))
        else:
            changes.append(ChangedPath(status, paths[0], paths[1]))
    return changes


def _changed_paths(base_ref: str, head_ref: str, repo_root: Path) -> list[ChangedPath]:
    result = subprocess.run(
        ["git", "diff", "--name-status", "-M", "-z", base_ref, head_ref, "--"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise SnapshotConfigError(stderr or "git diff --name-status failed")
    return _parse_changed_paths(result.stdout)


def _revision_sources(ref: str, repo_root: Path) -> dict[str, str]:
    result = subprocess.run(
        ["git", "archive", "--format=tar", ref, "--", "ida_preprocessor_scripts/*.py"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise SnapshotConfigError(stderr or f"git archive failed for {ref}")
    sources = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
            for member in sorted(archive.getmembers(), key=lambda item: item.name):
                if not member.isfile() or not member.name.endswith(".py"):
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                try:
                    sources[member.name.replace("\\", "/")] = extracted.read().decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise SnapshotConfigError(f"non-UTF-8 analysis source at {ref}:{member.name}") from exc
    except tarfile.TarError as exc:
        raise SnapshotConfigError(f"unable to read analysis sources from {ref}: {exc}") from exc
    return sources


def _delete_paths(contract, paths: frozenset[str]) -> int:
    ensure_real_tree(contract.game_root.parent, contract.game_root)
    deleted = 0
    for key in sorted(paths):
        target = path_from_key(contract.game_root, key)
        if target.is_file():
            target.unlink()
            deleted += 1
    return deleted


def _load_head_context(snapshot_path, config_path, game_version, bindir, base: SnapshotContext) -> SnapshotContext:
    try:
        return load_snapshot_context(snapshot_path, config_path, game_version, bindir)
    except SnapshotMismatchError as exc:
        if exc.reason != "config_digest_mismatch":
            raise
        print("Head snapshot config is stale; using the trusted base snapshot payload for invalidation")
        contract = load_contract(config_path, game_version, bindir, LATEST_CONFIG_DIGEST_VERSION)
        return SnapshotContext(base.document, base.raw_bytes, contract)


def _run(args) -> None:
    repo_root = Path.cwd()
    head_snapshot = args.headsnapshot or f"gamesymbols/{args.gamever}.yaml"
    args.headconfigyaml = str(resolve_analysis_config(args.gamever, args.headconfigyaml))
    print(f"Head analysis config: {args.headconfigyaml}")
    base = load_snapshot_context(args.basesnapshot, args.baseconfigyaml, args.gamever, args.bindir)
    head = _load_head_context(head_snapshot, args.headconfigyaml, args.gamever, args.bindir, base)
    changes = _changed_paths(args.baseref, args.headref, repo_root)
    needs_base_sources, needs_head_sources = required_source_index_sides(changes)
    base_sources = _revision_sources(args.baseref, repo_root) if needs_base_sources else {}
    head_sources = _revision_sources(args.headref, repo_root) if needs_head_sources else {}
    plan = build_invalidation_plan(
        base.contract,
        head.contract,
        base.document,
        head.document,
        changes,
        repo_root,
        base_sources=base_sources,
        head_sources=head_sources,
    )
    deleted = _delete_paths(head.contract, plan.paths)
    for reason in plan.reasons:
        print(f"  {reason}")
    for path in sorted(plan.paths):
        print(f"  invalidate: {path}")
    print(f"Invalidated {len(plan.paths)} path(s); deleted {deleted} existing YAML file(s)")


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        _run(args)
    except SnapshotMismatchError as exc:
        print(f"Error: {exc}")
        if args.debug:
            traceback.print_exc()
        return 1
    except (AnalysisConfigError, SnapshotConfigError) as exc:
        print(f"Error: {exc}")
        if args.debug:
            traceback.print_exc()
        return 2
    return 0

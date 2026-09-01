#!/usr/bin/env python3
"""Prepare and verify a fresh release rebuild against source-owned Git artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from bin_artifact_contract import ArtifactContractError, build_game_artifact_inventory
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotConfigError, SnapshotMismatchError
from gamesymbol_snapshot_lib.operations import collect_binary_metadata
from gamesymbol_snapshot_lib.paths import is_reparse_point


PREPARATION_SCHEMA_VERSION = 1
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ReleaseArtifactRebuildError(RuntimeError):
    """Release artifact preflight or exact rebuild verification failed closed."""


def _canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def _digest(label: str, value: object) -> str:
    raw = f"source-artifact-release-{label}:v1\n".encode() + _canonical_json_bytes(value)
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _git(repo_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ReleaseArtifactRebuildError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def _checkout_artifact_digest(root: Path) -> str:
    items = []
    if root.exists():
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            for directory in directories:
                path = current_path / directory
                if is_reparse_point(path):
                    raise ReleaseArtifactRebuildError(f"source artifact checkout traverses a link: {path}")
            for filename in files:
                path = current_path / filename
                if is_reparse_point(path):
                    raise ReleaseArtifactRebuildError(f"source artifact checkout contains a link: {path}")
                raw = path.read_bytes()
                items.append({"path": path.relative_to(root).as_posix(), "size": len(raw), "sha256": _sha256(raw)})
    return _digest("checkout-inventory", sorted(items, key=lambda item: item["path"]))


def _sdk_gitlink(repo_root: Path, source_sha: str) -> str:
    fields = _git(repo_root, "ls-tree", source_sha, "--", "hl2sdk_cs2").split()
    if len(fields) < 3 or fields[0] != "160000" or fields[1] != "commit" or not SHA_RE.fullmatch(fields[2]):
        raise ReleaseArtifactRebuildError("release source must bind the hl2sdk_cs2 gitlink")
    return fields[2]


def prepare_release_rebuild(
    *,
    repo_root: str | Path,
    source_sha: str,
    game_version: str,
    binary_root: str | Path,
    staging_root: str | Path,
) -> dict:
    repo_root = Path(repo_root).resolve()
    source_sha = source_sha.lower()
    if not SHA_RE.fullmatch(source_sha) or _git(repo_root, "rev-parse", "HEAD").lower() != source_sha:
        raise ReleaseArtifactRebuildError("release checkout does not match the immutable source SHA")
    staging_root = Path(os.path.abspath(staging_root))
    if staging_root == repo_root or repo_root in staging_root.parents:
        raise ReleaseArtifactRebuildError("release rebuild staging root must be outside the source checkout")
    if staging_root.exists():
        raise ReleaseArtifactRebuildError(f"release rebuild staging root already exists: {staging_root}")
    staging_root.mkdir(parents=True)
    actual_root = staging_root / "actual-bin-artifacts"
    actual_root.mkdir()
    execution_report = staging_root / "force-all-execution.json"
    config_path = repo_root / "configs" / f"{game_version}.yaml"
    artifact_root = repo_root / "bin_artifacts"
    binary_root = Path(binary_root).resolve()
    try:
        expected = build_game_artifact_inventory(
            repo_root=repo_root,
            config_path=config_path,
            game_version=game_version,
            artifact_root=artifact_root,
            require_tracked=True,
        )
        contract = load_contract(config_path, game_version, binary_root, artifactdir=artifact_root)
        binaries = collect_binary_metadata(contract)
    except (ArtifactContractError, SnapshotConfigError, SnapshotMismatchError, OSError) as exc:
        raise ReleaseArtifactRebuildError(f"release source artifact preflight failed: {exc}") from exc
    expected_files = [item.to_dict() for item in expected.files]
    command = [
        "uv",
        "run",
        "ida_analyze_bin.py",
        "-gamever",
        str(game_version),
        "-configyaml",
        str(config_path),
        "-bindir",
        str(binary_root),
        "-artifactdir",
        str(actual_root),
        "-oldartifactdir",
        str(artifact_root),
        "-require_warm_idb",
        "-force_all",
        "-execution_report",
        str(execution_report),
        "-rename",
        "-debug",
    ]
    document = {
        "schema_version": PREPARATION_SCHEMA_VERSION,
        "source_sha": source_sha,
        "source_tree_sha": _git(repo_root, "rev-parse", f"{source_sha}^{{tree}}"),
        "game_version": str(game_version),
        "config_sha256": contract.config_sha256,
        "sdk_gitlink_sha": _sdk_gitlink(repo_root, source_sha),
        "binary_inventory": binaries,
        "binary_inventory_sha256": _digest("binary-inventory", binaries),
        "expected_artifact_root": str(artifact_root),
        "expected_artifact_inventory_sha256": expected.inventory_sha256,
        "expected_files": expected_files,
        "source_checkout_artifact_sha256": _checkout_artifact_digest(artifact_root),
        "actual_artifact_root": str(actual_root),
        "execution_report": str(execution_report),
        "analysis_command": command,
    }
    document["preparation_sha256"] = _digest("rebuild-preparation", document)
    _atomic_write(staging_root / "release-rebuild-preparation.json", _canonical_json_bytes(document))
    return document


def load_release_rebuild_preparation(path: str | Path) -> dict:
    path = Path(path)
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseArtifactRebuildError(f"unable to load release rebuild preparation: {exc}") from exc
    if raw != _canonical_json_bytes(document):
        raise ReleaseArtifactRebuildError("release rebuild preparation is not canonical JSON")
    if not isinstance(document, dict) or document.get("schema_version") != PREPARATION_SCHEMA_VERSION:
        raise ReleaseArtifactRebuildError("release rebuild preparation schema is invalid")
    digest = document.get("preparation_sha256")
    unsigned = dict(document)
    unsigned.pop("preparation_sha256", None)
    if digest != _digest("rebuild-preparation", unsigned):
        raise ReleaseArtifactRebuildError("release rebuild preparation digest mismatch")
    return document


def _load_execution_report(path: Path, preparation: dict) -> dict:
    try:
        raw = path.read_bytes()
        report = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseArtifactRebuildError(f"unable to load force-all execution report: {exc}") from exc
    if raw != _canonical_json_bytes(report):
        raise ReleaseArtifactRebuildError("force-all execution report is not canonical JSON")
    digest = report.get("execution_sha256")
    unsigned = dict(report)
    unsigned.pop("execution_sha256", None)
    digest_payload = b"source2-force-all-execution:v1\n" + _canonical_json_bytes(unsigned)
    expected_digest = f"sha256:{hashlib.sha256(digest_payload).hexdigest()}"
    if digest != expected_digest:
        raise ReleaseArtifactRebuildError("force-all execution report digest mismatch")
    if (
        report.get("valid") is not True
        or report.get("force_all") is not True
        or report.get("rename") is not True
        or report.get("required_warm_idb") is not True
        or report.get("game_version") != preparation["game_version"]
        or Path(report.get("artifact_root", "")).resolve() != Path(preparation["actual_artifact_root"]).resolve()
    ):
        raise ReleaseArtifactRebuildError("force-all execution report does not prove the required release run")
    return report


def verify_release_rebuild(*, repo_root: str | Path, preparation: dict | str | Path) -> dict:
    preparation = load_release_rebuild_preparation(preparation) if isinstance(preparation, (str, Path)) else preparation
    repo_root = Path(repo_root).resolve()
    if _git(repo_root, "rev-parse", "HEAD").lower() != preparation["source_sha"]:
        raise ReleaseArtifactRebuildError("release source checkout drifted before rebuild verification")
    if _checkout_artifact_digest(repo_root / "bin_artifacts") != preparation["source_checkout_artifact_sha256"]:
        raise ReleaseArtifactRebuildError("source-owned artifacts changed during release rebuild")
    execution = _load_execution_report(Path(preparation["execution_report"]), preparation)
    try:
        actual = build_game_artifact_inventory(
            repo_root=repo_root,
            config_path=repo_root / "configs" / f"{preparation['game_version']}.yaml",
            game_version=preparation["game_version"],
            artifact_root=preparation["actual_artifact_root"],
            require_tracked=False,
        )
    except ArtifactContractError as exc:
        raise ReleaseArtifactRebuildError(f"fresh release artifact contract failed: {exc}") from exc
    actual_files = {item.path: item.to_dict() for item in actual.files}
    expected_files = {item["path"]: item for item in preparation["expected_files"]}
    if actual_files != expected_files:
        changed = sorted(
            path
            for path in set(actual_files) | set(expected_files)
            if actual_files.get(path) != expected_files.get(path)
        )
        raise ReleaseArtifactRebuildError(
            "fresh release artifacts differ from immutable Git truth:\n" + "\n".join(f"  {path}" for path in changed)
        )
    if actual.inventory_sha256 != preparation["expected_artifact_inventory_sha256"]:
        raise ReleaseArtifactRebuildError("fresh release aggregate artifact inventory digest mismatch")
    result = {
        "schema_version": 1,
        "source_sha": preparation["source_sha"],
        "game_version": preparation["game_version"],
        "preparation_sha256": preparation["preparation_sha256"],
        "execution_sha256": execution["execution_sha256"],
        "artifact_inventory_sha256": actual.inventory_sha256,
        "file_count": actual.file_count,
    }
    result["verification_sha256"] = _digest("rebuild-verification", result)
    return result


def load_release_rebuild_verification(path: str | Path) -> dict:
    path = Path(path)
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseArtifactRebuildError(f"unable to load release rebuild verification: {exc}") from exc
    if raw != _canonical_json_bytes(document):
        raise ReleaseArtifactRebuildError("release rebuild verification is not canonical JSON")
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ReleaseArtifactRebuildError("release rebuild verification schema is invalid")
    digest = document.get("verification_sha256")
    unsigned = dict(document)
    unsigned.pop("verification_sha256", None)
    if digest != _digest("rebuild-verification", unsigned):
        raise ReleaseArtifactRebuildError("release rebuild verification digest mismatch")
    return document


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--repo-root", default=".")
    prepare.add_argument("--source-sha", required=True)
    prepare.add_argument("--gamever", required=True)
    prepare.add_argument("--binary-root", default="bin")
    prepare.add_argument("--staging-root", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--repo-root", default=".")
    verify.add_argument("--preparation", required=True)
    verify.add_argument("--output")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare_release_rebuild(
                repo_root=args.repo_root,
                source_sha=args.source_sha,
                game_version=args.gamever,
                binary_root=args.binary_root,
                staging_root=args.staging_root,
            )
        else:
            result = verify_release_rebuild(repo_root=args.repo_root, preparation=args.preparation)
            if args.output:
                _atomic_write(Path(args.output), _canonical_json_bytes(result))
    except (OSError, UnicodeError, ReleaseArtifactRebuildError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

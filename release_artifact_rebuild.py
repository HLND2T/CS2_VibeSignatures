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

from binary_lock import BinaryLockError, load_binary_lock_from_revision
from artifact_diagnostics import (
    MAX_LOG_CHARACTERS,
    DiagnosticContext,
    append_failure_diagnostics,
    collect_failure_bundle,
    external_staging,
    read_artifact_bytes,
    safe_component,
)
from bin_artifact_contract import ArtifactContractError, _git_blob_entries, build_game_artifact_inventory
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotConfigError, SnapshotMismatchError
from gamesymbol_snapshot_lib.operations import collect_binary_metadata
from gamesymbol_snapshot_lib.paths import is_reparse_point


PREPARATION_SCHEMA_VERSION = 2
TRACKED_BINDING_SCHEMA_VERSION = 1
TRACKED_BINDING_MODE = "tracked"
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


def _git_blob(repo_root: Path, revision: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "cat-file", "blob", f"{revision}:{path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseArtifactRebuildError(detail or f"unable to read source Git blob: {path}")
    return result.stdout


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
            git_revision=source_sha,
        )
        contract = load_contract(config_path, game_version, binary_root, artifactdir=artifact_root)
        binary_lock = load_binary_lock_from_revision(
            repo_root=repo_root,
            revision=source_sha,
            game_version=str(game_version),
            download_payload=_git_blob(repo_root, source_sha, "download.yaml"),
            binary_targets=contract.binary_targets,
        )
        binaries = collect_binary_metadata(contract)
        if binaries != binary_lock.document["binaries"]:
            raise ReleaseArtifactRebuildError("release binary identity mismatch with source-owned lock")
    except (ArtifactContractError, BinaryLockError, SnapshotConfigError, SnapshotMismatchError, OSError) as exc:
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
        "binary_lock_sha256": binary_lock.sha256,
        "binary_inventory": binaries,
        "binary_inventory_sha256": _digest("binary-inventory", binaries),
        "expected_artifact_root": str(artifact_root),
        "expected_artifact_inventory_sha256": expected.inventory_sha256,
        "expected_files": expected_files,
        "source_checkout_artifact_sha256": _checkout_artifact_digest(artifact_root / str(game_version)),
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
    digest_payload = b"source2-force-all-execution:v2\n" + _canonical_json_bytes(unsigned)
    expected_digest = f"sha256:{hashlib.sha256(digest_payload).hexdigest()}"
    if digest != expected_digest:
        raise ReleaseArtifactRebuildError("force-all execution report digest mismatch")
    if (
        report.get("schema_version") != 2
        or report.get("valid") is not True
        or report.get("force_all") is not True
        or report.get("rename") is not True
        or report.get("required_warm_idb") is not True
        or report.get("game_version") != preparation["game_version"]
        or "prior_gamever" not in report
        or Path(report.get("artifact_root", "")).resolve() != Path(preparation["actual_artifact_root"]).resolve()
    ):
        raise ReleaseArtifactRebuildError("force-all execution report does not prove the required release run")
    return report


def _verify_release_rebuild(*, repo_root: str | Path, preparation: dict | str | Path) -> dict:
    preparation = load_release_rebuild_preparation(preparation) if isinstance(preparation, (str, Path)) else preparation
    repo_root = Path(repo_root).resolve()
    if _git(repo_root, "rev-parse", "HEAD").lower() != preparation["source_sha"]:
        raise ReleaseArtifactRebuildError("release source checkout drifted before rebuild verification")
    try:
        game_version = preparation["game_version"]
        config_path = repo_root / "configs" / f"{game_version}.yaml"
        expected = build_game_artifact_inventory(
            repo_root=repo_root,
            config_path=config_path,
            game_version=game_version,
            artifact_root=repo_root / "bin_artifacts",
            require_tracked=True,
            git_revision=preparation["source_sha"],
        )
        contract = load_contract(
            config_path,
            game_version,
            repo_root / "bin",
            artifactdir=repo_root / "bin_artifacts",
        )
        binary_lock = load_binary_lock_from_revision(
            repo_root=repo_root,
            revision=preparation["source_sha"],
            game_version=game_version,
            download_payload=_git_blob(repo_root, preparation["source_sha"], "download.yaml"),
            binary_targets=contract.binary_targets,
        )
        binaries = collect_binary_metadata(contract)
    except (ArtifactContractError, BinaryLockError, SnapshotConfigError, SnapshotMismatchError, OSError) as exc:
        raise ReleaseArtifactRebuildError(f"release source artifact verification failed: {exc}") from exc
    if (
        binary_lock.sha256 != preparation.get("binary_lock_sha256")
        or binary_lock.document["binaries"] != preparation.get("binary_inventory")
        or binaries != binary_lock.document["binaries"]
    ):
        raise ReleaseArtifactRebuildError("release binary identity mismatch with source-owned lock")
    expected_files_now = [item.to_dict() for item in expected.files]
    if (
        expected.inventory_sha256 != preparation["expected_artifact_inventory_sha256"]
        or expected_files_now != preparation["expected_files"]
    ):
        raise ReleaseArtifactRebuildError("immutable Git artifact inventory differs from rebuild preparation")
    checkout_game_root = repo_root / "bin_artifacts" / str(preparation["game_version"])
    if _checkout_artifact_digest(checkout_game_root) != preparation["source_checkout_artifact_sha256"]:
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
        raise ReleaseArtifactRebuildError("fresh release artifacts differ from immutable Git truth:")
    if actual.inventory_sha256 != preparation["expected_artifact_inventory_sha256"]:
        raise ReleaseArtifactRebuildError("fresh release aggregate artifact inventory digest mismatch")
    result = {
        "schema_version": 1,
        "source_sha": preparation["source_sha"],
        "game_version": preparation["game_version"],
        "preparation_sha256": preparation["preparation_sha256"],
        "binary_lock_sha256": preparation["binary_lock_sha256"],
        "execution_sha256": execution["execution_sha256"],
        "artifact_inventory_sha256": actual.inventory_sha256,
        "file_count": actual.file_count,
    }
    result["verification_sha256"] = _digest("rebuild-verification", result)
    return result


def verify_release_rebuild(*, repo_root: str | Path, preparation: dict | str | Path) -> dict:
    try:
        return _verify_release_rebuild(repo_root=repo_root, preparation=preparation)
    except Exception as exc:
        detail = append_failure_diagnostics(
            str(exc),
            lambda: release_diagnostic_context(Path(repo_root), preparation),
            max_characters=MAX_LOG_CHARACTERS,
        )
        raise ReleaseArtifactRebuildError(detail) from exc


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


def bind_tracked_artifacts(*, repo_root: str | Path, preparation: dict | str | Path) -> dict:
    """Bind the tracked source-owned artifact tree as the release's source truth.

    Manual, protected emergency path: it proves the published artifacts are exactly
    the tracked ``bin_artifacts/<GAMEVER>`` at the immutable source SHA, but it does
    not prove a fresh rebuild reproduces them.
    """
    preparation = load_release_rebuild_preparation(preparation) if isinstance(preparation, (str, Path)) else preparation
    repo_root = Path(repo_root).resolve()
    if _git(repo_root, "rev-parse", "HEAD").lower() != preparation["source_sha"]:
        raise ReleaseArtifactRebuildError("release source checkout drifted before tracked artifact binding")
    try:
        game_version = preparation["game_version"]
        config_path = repo_root / "configs" / f"{game_version}.yaml"
        tracked = build_game_artifact_inventory(
            repo_root=repo_root,
            config_path=config_path,
            game_version=game_version,
            artifact_root=repo_root / "bin_artifacts",
            require_tracked=True,
            git_revision=preparation["source_sha"],
        )
        contract = load_contract(
            config_path,
            game_version,
            repo_root / "bin",
            artifactdir=repo_root / "bin_artifacts",
        )
        binary_lock = load_binary_lock_from_revision(
            repo_root=repo_root,
            revision=preparation["source_sha"],
            game_version=game_version,
            download_payload=_git_blob(repo_root, preparation["source_sha"], "download.yaml"),
            binary_targets=contract.binary_targets,
        )
        binaries = collect_binary_metadata(contract)
    except (ArtifactContractError, BinaryLockError, SnapshotConfigError, SnapshotMismatchError, OSError) as exc:
        raise ReleaseArtifactRebuildError(f"tracked source artifact binding failed: {exc}") from exc
    if (
        binary_lock.sha256 != preparation.get("binary_lock_sha256")
        or binary_lock.document["binaries"] != preparation.get("binary_inventory")
        or binaries != binary_lock.document["binaries"]
    ):
        raise ReleaseArtifactRebuildError("release binary identity mismatch with source-owned lock")
    tracked_files_now = [item.to_dict() for item in tracked.files]
    if (
        tracked.inventory_sha256 != preparation["expected_artifact_inventory_sha256"]
        or tracked_files_now != preparation["expected_files"]
    ):
        raise ReleaseArtifactRebuildError("tracked artifact inventory differs from rebuild preparation")
    checkout_game_root = repo_root / "bin_artifacts" / str(game_version)
    if _checkout_artifact_digest(checkout_game_root) != preparation["source_checkout_artifact_sha256"]:
        raise ReleaseArtifactRebuildError("tracked source artifacts changed before binding")
    result = {
        "schema_version": TRACKED_BINDING_SCHEMA_VERSION,
        "binding_mode": TRACKED_BINDING_MODE,
        "source_sha": preparation["source_sha"],
        "game_version": game_version,
        "preparation_sha256": preparation["preparation_sha256"],
        "binary_lock_sha256": preparation["binary_lock_sha256"],
        "artifact_inventory_sha256": tracked.inventory_sha256,
        "file_count": tracked.file_count,
    }
    result["verification_sha256"] = _digest("tracked-artifact-binding", result)
    return result


def load_tracked_artifact_binding(path: str | Path) -> dict:
    path = Path(path)
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseArtifactRebuildError(f"unable to load tracked artifact binding: {exc}") from exc
    if raw != _canonical_json_bytes(document):
        raise ReleaseArtifactRebuildError("tracked artifact binding is not canonical JSON")
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != TRACKED_BINDING_SCHEMA_VERSION
        or document.get("binding_mode") != TRACKED_BINDING_MODE
    ):
        raise ReleaseArtifactRebuildError("tracked artifact binding schema is invalid")
    digest = document.get("verification_sha256")
    unsigned = dict(document)
    unsigned.pop("verification_sha256", None)
    if digest != _digest("tracked-artifact-binding", unsigned):
        raise ReleaseArtifactRebuildError("tracked artifact binding digest mismatch")
    return document


def collect_failure_diagnostics(*, repo_root: Path, preparation_path: Path, destination: Path, error: str) -> None:
    collect_failure_bundle(
        repo_root=repo_root,
        staging=preparation_path.absolute().parent,
        destination=destination,
        error=error,
        phase="verify",
        load_context=lambda: release_diagnostic_context(repo_root, preparation_path),
    )


def release_diagnostic_context(repo_root: Path, preparation: dict | str | Path) -> DiagnosticContext:
    staging = (
        Path(preparation["actual_artifact_root"]).parent
        if isinstance(preparation, dict)
        else Path(preparation).absolute().parent
    )
    staging = external_staging(repo_root, staging)
    context = DiagnosticContext(
        actual_root=staging / "actual-bin-artifacts",
        evidence={
            "release-rebuild-preparation.json": _canonical_json_bytes(preparation)
            if isinstance(preparation, dict)
            else Path(preparation),
            "force-all-execution.json": staging / "force-all-execution.json",
        },
        metadata={"expected_source": "release source Git blob", "preparation_valid": False},
    )
    try:
        if isinstance(preparation, dict):
            document = preparation
        else:
            raw, read_error = read_artifact_bytes(Path(preparation))
            if raw is None:
                raise ReleaseArtifactRebuildError(f"diagnostic preparation unavailable: {read_error or 'missing'}")
            context.evidence["release-rebuild-preparation.json"] = raw
            document = json.loads(raw.decode("utf-8"))
            if raw != _canonical_json_bytes(document):
                raise ReleaseArtifactRebuildError("diagnostic preparation is not canonical JSON")
        unsigned = dict(document)
        digest = unsigned.pop("preparation_sha256", None)
        if document.get("schema_version") != PREPARATION_SCHEMA_VERSION or digest != _digest(
            "rebuild-preparation", unsigned
        ):
            raise ReleaseArtifactRebuildError("diagnostic preparation schema or digest mismatch")
        source_sha = document["source_sha"]
        if not isinstance(source_sha, str) or not SHA_RE.fullmatch(source_sha):
            raise ReleaseArtifactRebuildError("invalid diagnostic source SHA")
        gamever = safe_component(document["game_version"])
        context.game_versions = (gamever,)
        context.metadata.update(
            source_sha=source_sha,
            game_version=gamever,
            preparation_sha256=digest,
            preparation_valid=True,
            execution_strategy="fresh-full-v1",
        )
        context.expected = _git_blob_entries(repo_root, f"bin_artifacts/{gamever}/", source_sha)
        if Path(os.path.abspath(document["actual_artifact_root"])) != context.actual_root:
            raise ReleaseArtifactRebuildError("diagnostic actual root is not preparation-local")
    except Exception as exc:
        context.errors.append(str(exc))
    return context


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
    verify.add_argument("--diagnostics-dir", help="Fresh checkout-external directory for failure evidence")
    bind = subparsers.add_parser("bind-tracked")
    bind.add_argument("--repo-root", default=".")
    bind.add_argument("--preparation", required=True)
    bind.add_argument("--output")
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
        elif args.command == "bind-tracked":
            result = bind_tracked_artifacts(repo_root=args.repo_root, preparation=args.preparation)
            if args.output:
                _atomic_write(Path(args.output), _canonical_json_bytes(result))
        else:
            result = verify_release_rebuild(repo_root=args.repo_root, preparation=args.preparation)
            if args.output:
                _atomic_write(Path(args.output), _canonical_json_bytes(result))
    except Exception as exc:
        # The CLI failure boundary also captures malformed or incomplete evidence.
        print(f"Error: {exc}", file=sys.stderr)
        if args.command == "verify" and getattr(args, "diagnostics_dir", None):
            try:
                collect_failure_diagnostics(
                    repo_root=Path(args.repo_root),
                    preparation_path=Path(args.preparation),
                    destination=Path(args.diagnostics_dir),
                    error=f"Error: {exc}",
                )
            except Exception as diagnostic_error:
                # Best-effort evidence must never replace the verification failure.
                print(f"Failure diagnostics unavailable: {diagnostic_error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

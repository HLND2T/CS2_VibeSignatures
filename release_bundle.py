#!/usr/bin/env python3
"""Build and hosted-verify an immutable source-owned Release bundle."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from bin_artifact_contract import ArtifactContractError, build_game_artifact_inventory
from binsync_candidate import BinSyncCandidateError, verify_candidate as verify_binsync_candidate
from gamedata_candidate import (
    GamedataCandidateError,
    build_candidate as build_gamedata_candidate,
    compare_gamedata_inventory,
    guard_candidate,
)
from gamedata_contract import (
    GamedataContractError,
    discover_generator_modules,
    gamedata_manifest_sha256,
    generator_contract_sha256,
    validate_output_tree,
)
from gamesymbol_metadata import MetadataGenerationError, generate_metadata
from gamesymbol_snapshot_lib.config import SnapshotConfigError, load_contract
from gamesymbol_snapshot_lib.errors import SnapshotMismatchError
from gamesymbol_snapshot_lib.operations import collect_actual_files, load_snapshot_for_contract
from release_artifact_rebuild import (
    ReleaseArtifactRebuildError,
    load_release_rebuild_preparation,
    load_release_rebuild_verification,
)
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    file_inventory,
    inventory_sha256,
    load_json_object,
    normalized_relative_path,
    reject_reparse_points,
    sha256_bytes,
    sha256_file,
    write_canonical_json,
)
from release_workflow_lib.sevenzip import listed_archive_files

BUNDLE_SCHEMA_VERSION = 1
CPP_SDK_REF = "source-gitlink"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,240}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
BUILD_ID_RE = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_REPOSITORY = "HLND2T/CS2_VibeSignatures"
PRODUCER_CONTRACT_PATHS = (
    "analysis_output_contract.py",
    "bin_artifact_contract.py",
    "gamesymbol_snapshot_lib/config.py",
    "ida_analyze_bin.py",
    "ida_analyze_util.py",
)


class ReleaseBundleError(Exception):
    """Raised when a Release bundle cannot be built or verified safely."""


def _git(cwd: Path, *arguments: str, binary: bool = False) -> str | bytes:
    result = subprocess.run(
        ["git", "-C", str(cwd), *arguments],
        capture_output=True,
        text=not binary,
        check=False,
    )
    if result.returncode:
        stderr = result.stderr.decode(errors="replace") if binary else result.stderr
        stdout = result.stdout.decode(errors="replace") if binary else result.stdout
        detail = (stderr or stdout or "").strip()
        raise ReleaseBundleError(detail or f"git {' '.join(arguments)} failed")
    return result.stdout if binary else result.stdout.strip()


def _digest(domain: str, value: object) -> str:
    payload = domain.encode("ascii") + b"\n" + canonical_json_bytes(value)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _release_rebuild_digest(label: str, value: object) -> str:
    payload = f"source-artifact-release-{label}:v1\n".encode("ascii") + canonical_json_bytes(value)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _source_blob(repo_root: Path, source_sha: str, path: str) -> bytes:
    normalized_relative_path(path)
    value = _git(repo_root, "cat-file", "blob", f"{source_sha}:{path}", binary=True)
    assert isinstance(value, bytes)
    return value


def _copy_file(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ReleaseBundleError(f"Release input must be a regular file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _copy_tree(source: Path, destination: Path) -> list[dict]:
    try:
        inventory = file_inventory(source)
    except ReleaseWorkflowError as exc:
        raise ReleaseBundleError(str(exc)) from exc
    for item in inventory:
        _copy_file(source / PurePosixPath(item["path"]), destination / PurePosixPath(item["path"]))
    return inventory


def _sdk_inventory(sdk_root: Path, expected_sha: str) -> list[dict]:
    if str(_git(sdk_root, "rev-parse", f"{expected_sha}^{{commit}}")).lower() != expected_sha:
        raise ReleaseBundleError("selected C++ SDK commit is unavailable")
    raw = _git(sdk_root, "ls-tree", "-r", "-z", expected_sha, binary=True)
    assert isinstance(raw, bytes)
    inventory = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        relative = os.fsdecode(raw_path).replace("\\", "/")
        relative = normalized_relative_path(relative)
        if mode not in {"100644", "100755"} or object_type != "blob":
            raise ReleaseBundleError(f"SDK tracked path must be a regular blob: {relative}")
        raw_blob = _git(sdk_root, "cat-file", "blob", object_id, binary=True)
        assert isinstance(raw_blob, bytes)
        inventory.append({"path": relative, "size": len(raw_blob), "sha256": sha256_bytes(raw_blob)})
    inventory.sort(key=lambda item: item["path"])
    if not inventory:
        raise ReleaseBundleError("SDK tracked inventory is empty")
    return inventory


def _copy_sdk(sdk_root: Path, sdk_sha: str, destination: Path, inventory: list[dict]) -> None:
    for item in inventory:
        raw = _git(sdk_root, "cat-file", "blob", f"{sdk_sha}:{item['path']}", binary=True)
        assert isinstance(raw, bytes)
        target = destination / PurePosixPath(item["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


def _binary_records(binary_inventory: dict) -> list[dict]:
    records = []
    for module in sorted(binary_inventory):
        for platform in sorted(binary_inventory[module]):
            metadata = binary_inventory[module][platform]
            records.append({"module": module, "platform": platform, **metadata})
    if not records:
        raise ReleaseBundleError("release binary inventory is empty")
    return records


def _binary_archive_inventory(game_version: str, binary_inventory: dict) -> list[dict]:
    return sorted(
        (
            {
                "path": f"bin/{game_version}/{record['module']}/{PurePosixPath(record['path']).name}",
                "size": record["size"],
                "sha256": record["sha256"],
            }
            for record in _binary_records(binary_inventory)
        ),
        key=lambda item: item["path"],
    )


def _copy_binaries(repo_root: Path, game_version: str, records: list[dict], destination: Path) -> None:
    for record in records:
        binary_name = PurePosixPath(record["path"]).name
        source = repo_root / "bin" / game_version / record["module"] / binary_name
        if not source.is_file() or source.stat().st_size != record["size"] or sha256_file(source) != record["sha256"]:
            raise ReleaseBundleError(f"release binary identity mismatch: {source}")
        _copy_file(source, destination / "bin" / game_version / record["module"] / binary_name)


def _create_archive(source_root: Path, archive_path: Path) -> None:
    inventory = file_inventory(source_root)
    if not inventory:
        raise ReleaseBundleError(f"archive source is empty: {source_root}")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    list_path = source_root.parent / f"{archive_path.name}.files.txt"
    list_path.write_text("".join(f"{item['path']}\n" for item in inventory), encoding="utf-8", newline="\n")
    command = [
        "7z",
        "a",
        "-t7z",
        "-mx=9",
        "-mmt=off",
        "-mtc=off",
        "-mtm=off",
        "-mta=off",
        "-scsUTF-8",
        str(archive_path.resolve()),
        f"@{list_path.resolve()}",
    ]
    try:
        result = subprocess.run(command, cwd=source_root, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise ReleaseBundleError(f"unable to create 7z archive: {exc}") from exc
    finally:
        list_path.unlink(missing_ok=True)
    if result.returncode:
        raise ReleaseBundleError((result.stderr or result.stdout).strip() or "7z archive creation failed")


def _listed_archive_files(output: str) -> list[dict]:
    try:
        return listed_archive_files(output)
    except ReleaseWorkflowError as exc:
        raise ReleaseBundleError(str(exc)) from exc


def _extract_archive(archive_path: Path, destination: Path, expected: list[dict]) -> None:
    try:
        listing = subprocess.run(
            ["7z", "l", "-slt", "-ba", str(archive_path.resolve())],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise ReleaseBundleError(f"unable to inspect 7z archive: {exc}") from exc
    if listing.returncode:
        raise ReleaseBundleError((listing.stderr or listing.stdout).strip() or "7z archive listing failed")
    expected_listing = sorted(
        ({"path": item["path"], "size": item["size"]} for item in expected),
        key=lambda item: item["path"],
    )
    if _listed_archive_files(listing.stdout) != expected_listing:
        raise ReleaseBundleError(f"Release archive listed inventory mismatch: {archive_path.name}")
    destination.mkdir()
    try:
        result = subprocess.run(
            ["7z", "x", "-y", f"-o{destination}", str(archive_path.resolve())],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise ReleaseBundleError(f"unable to extract 7z archive: {exc}") from exc
    if result.returncode:
        raise ReleaseBundleError((result.stderr or result.stdout).strip() or "7z archive extraction failed")


def _producer_contract(repo_root: Path, source_sha: str) -> dict:
    files = []
    for path in PRODUCER_CONTRACT_PATHS:
        raw = _source_blob(repo_root, source_sha, path)
        files.append({"path": path, "size": len(raw), "sha256": sha256_bytes(raw)})
    return {"files": files, "digest": _digest("source2-producer-contract:v1", files)}


def _binsync_target_state(manifest: dict) -> dict:
    repositories = [
        {
            "repository_id": repository["repository_id"],
            "owner": repository["owner"],
            "name": repository["name"],
            "refs": [{"ref": item["ref"], "commit": item["candidate_commit"]} for item in repository["refs"]],
        }
        for repository in manifest["repositories"]
    ]
    return {
        "candidate_publication_digest": manifest["publication_digest"],
        "repositories": repositories,
        "target_state_digest": _digest("binsync-intended-remote-state:v1", repositories),
    }


def _validate_snapshot(snapshot: Path, contract) -> dict:
    try:
        document, _raw = load_snapshot_for_contract(snapshot, contract, require_canonical=True)
        actual_files = collect_actual_files(contract, strict=True)
    except SnapshotMismatchError as exc:
        raise ReleaseBundleError(str(exc)) from exc
    if document["files"] != actual_files:
        raise ReleaseBundleError("release snapshot payload differs from the validated artifact tree")
    return document


def build_release_bundle(
    *,
    repo_root: str | Path,
    bundle_root: str | Path,
    repository: str,
    release_version: str,
    build_id: str,
    preparation: str | Path,
    rebuild_verification: str | Path,
    snapshot: str | Path,
    metadata: str | Path,
    gamedata_candidate_root: str | Path,
    gamedata_session: str | Path,
    cpp_validation_log: str | Path,
    binsync_candidate_root: str | Path,
    ida_runtime_identity: str,
    warm_idb_generation: str,
    warm_idb_cache_key: str,
    actions_artifact_name: str,
    cpp_sdk_ref: str,
    cpp_sdk_sha: str,
) -> dict:
    """Assemble deterministic public payloads and a canonical Release manifest."""
    repo_root = Path(repo_root).resolve()
    bundle_root = Path(os.path.abspath(bundle_root))
    if repository != ALLOWED_REPOSITORY:
        raise ReleaseBundleError(f"repository is not allowlisted: {repository}")
    if bundle_root.exists():
        raise ReleaseBundleError(f"Release bundle root must be fresh: {bundle_root}")
    if not ARTIFACT_NAME_RE.fullmatch(actions_artifact_name):
        raise ReleaseBundleError("Release Actions Artifact name is invalid")
    try:
        preparation_document = load_release_rebuild_preparation(preparation)
        verification = load_release_rebuild_verification(rebuild_verification)
    except ReleaseArtifactRebuildError as exc:
        raise ReleaseBundleError(str(exc)) from exc
    source_sha = preparation_document["source_sha"]
    game_version = preparation_document["game_version"]
    if not VERSION_RE.fullmatch(release_version) or not BUILD_ID_RE.fullmatch(build_id):
        raise ReleaseBundleError("Release version or build ID is invalid")
    if str(_git(repo_root, "rev-parse", "HEAD")).lower() != source_sha:
        raise ReleaseBundleError("Release bundle checkout does not match the immutable source SHA")
    if (
        verification["source_sha"] != source_sha
        or verification["game_version"] != game_version
        or verification["preparation_sha256"] != preparation_document["preparation_sha256"]
        or verification["artifact_inventory_sha256"] != preparation_document["expected_artifact_inventory_sha256"]
    ):
        raise ReleaseBundleError("Release rebuild verification does not bind the preparation")

    actual_artifact_root = Path(preparation_document["actual_artifact_root"])
    config_path = repo_root / "configs" / f"{game_version}.yaml"
    try:
        artifact_inventory = build_game_artifact_inventory(
            repo_root=repo_root,
            config_path=config_path,
            game_version=game_version,
            artifact_root=actual_artifact_root,
            require_tracked=False,
        )
        contract = load_contract(
            config_path,
            game_version,
            repo_root / "bin",
            artifactdir=actual_artifact_root,
        )
    except (ArtifactContractError, SnapshotConfigError) as exc:
        raise ReleaseBundleError(str(exc)) from exc
    snapshot = Path(snapshot).resolve()
    snapshot_document = _validate_snapshot(snapshot, contract)
    metadata = Path(metadata).resolve()
    if not metadata.is_file():
        raise ReleaseBundleError(f"release metadata is missing: {metadata}")

    try:
        gamedata_evidence = guard_candidate(gamedata_session)
    except GamedataCandidateError as exc:
        raise ReleaseBundleError(str(exc)) from exc
    gamedata_candidate_root = Path(gamedata_candidate_root).resolve()
    gamedata_root = gamedata_candidate_root / "gamedata" / game_version
    if Path(gamedata_evidence["candidate_root"]).resolve() != gamedata_candidate_root:
        raise ReleaseBundleError("gamedata session candidate root mismatch")
    gamedata_files = file_inventory(gamedata_root)
    gamedata_session_files = gamedata_evidence["files"]
    expected_relative_gamedata = [
        {**item, "path": item["path"].removeprefix(f"gamedata/{game_version}/")} for item in gamedata_session_files
    ]
    if gamedata_files != expected_relative_gamedata:
        raise ReleaseBundleError("gamedata session inventory does not match the candidate root")
    cpp_validation_log = Path(cpp_validation_log).resolve()
    if not cpp_validation_log.is_file() or cpp_validation_log.stat().st_size == 0:
        raise ReleaseBundleError("C++ validation evidence is missing")

    binsync_candidate_root = Path(binsync_candidate_root).resolve()
    try:
        binsync_verified = verify_binsync_candidate(
            candidate_root=binsync_candidate_root,
            repo_root=repo_root,
            expected_source_sha=source_sha,
            expected_game_version=game_version,
            expected_release_version=release_version,
            expected_build_id=build_id,
            expected_ida_runtime_identity=ida_runtime_identity,
            expected_actions_artifact_name=load_json_object(binsync_candidate_root / "manifest.json")[
                "actions_artifact_name"
            ],
        )
        binsync_manifest = load_json_object(binsync_candidate_root / "manifest.json")
    except (BinSyncCandidateError, ReleaseWorkflowError) as exc:
        raise ReleaseBundleError(str(exc)) from exc
    if binsync_verified["publication_digest"] != binsync_manifest["publication_digest"]:
        raise ReleaseBundleError("BinSync candidate verification digest mismatch")

    if (
        cpp_sdk_ref != CPP_SDK_REF
        or not SHA_RE.fullmatch(cpp_sdk_sha)
        or cpp_sdk_sha != preparation_document["sdk_gitlink_sha"]
    ):
        raise ReleaseBundleError("selected C++ SDK must equal the immutable source gitlink")
    sdk_root = repo_root / "hl2sdk_cs2"
    sdk_files = _sdk_inventory(sdk_root, cpp_sdk_sha)
    binary_records = _binary_records(preparation_document["binary_inventory"])
    bundle_root.mkdir(parents=True)
    snapshot_target = bundle_root / "gamesymbols" / f"{game_version}.yaml"
    metadata_target = bundle_root / "gamesymbols" / f"{game_version}.metadata.yaml"
    _copy_file(snapshot, snapshot_target)
    _copy_file(metadata, metadata_target)
    _copy_tree(gamedata_root, bundle_root / "gamedata" / game_version)

    with tempfile.TemporaryDirectory(prefix="release-archive-staging-") as temporary:
        temporary_root = Path(temporary)
        gamedata_archive_root = temporary_root / "gamedata"
        gamebin_archive_root = temporary_root / "gamebin"
        archive_config = gamedata_archive_root / "configs" / f"{game_version}.yaml"
        archive_config.parent.mkdir(parents=True, exist_ok=True)
        archive_config.write_bytes(_source_blob(repo_root, source_sha, f"configs/{game_version}.yaml"))
        _copy_tree(actual_artifact_root / game_version, gamedata_archive_root / "bin_artifacts" / game_version)
        _copy_file(snapshot, gamedata_archive_root / "gamesymbols" / f"{game_version}.yaml")
        _copy_file(metadata, gamedata_archive_root / "gamesymbols" / f"{game_version}.metadata.yaml")
        _copy_tree(gamedata_root, gamedata_archive_root / "gamedata" / game_version)
        _copy_sdk(sdk_root, cpp_sdk_sha, gamedata_archive_root / "hl2sdk_cs2", sdk_files)
        _copy_binaries(repo_root, game_version, binary_records, gamedata_archive_root)
        _copy_binaries(repo_root, game_version, binary_records, gamebin_archive_root)
        gamedata_archive_inventory = file_inventory(gamedata_archive_root)
        gamebin_archive_inventory = file_inventory(gamebin_archive_root)
        gamedata_archive = bundle_root / "archives" / f"gamedata-{game_version}.7z"
        gamebin_archive = bundle_root / "archives" / f"gamebin-{game_version}.7z"
        _create_archive(gamedata_archive_root, gamedata_archive)
        _create_archive(gamebin_archive_root, gamebin_archive)

    public_paths = [
        f"gamesymbols/{game_version}.yaml",
        f"gamesymbols/{game_version}.metadata.yaml",
        f"archives/gamedata-{game_version}.7z",
        f"archives/gamebin-{game_version}.7z",
    ]
    public_assets = [
        {
            "path": path,
            "name": PurePosixPath(path).name,
            "size": (bundle_root / PurePosixPath(path)).stat().st_size,
            "sha256": sha256_file(bundle_root / PurePosixPath(path)),
        }
        for path in public_paths
    ]
    producer_contract = _producer_contract(repo_root, source_sha)
    manifest_name = f"release-manifest-{release_version}.json"
    checksums_name = f"SHA256SUMS-{release_version}.txt"
    manifest = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "repository": repository,
        "release_version": release_version,
        "game_version": game_version,
        "build_id": build_id,
        "actions_artifact_name": actions_artifact_name,
        "source_sha": source_sha,
        "source_subject": str(_git(repo_root, "show", "-s", "--format=%s", source_sha)),
        "download_sha256": f"sha256:{sha256_bytes(_source_blob(repo_root, source_sha, 'download.yaml'))}",
        "config_sha256": preparation_document["config_sha256"],
        "sdk_gitlink_sha": preparation_document["sdk_gitlink_sha"],
        "cpp_sdk": {"ref": cpp_sdk_ref, "sha": cpp_sdk_sha},
        "sdk_files": sdk_files,
        "sdk_inventory_sha256": inventory_sha256(sdk_files),
        "binary_inventory": preparation_document["binary_inventory"],
        "binary_inventory_sha256": preparation_document["binary_inventory_sha256"],
        "artifact_inventory_sha256": artifact_inventory.inventory_sha256,
        "producer_contract": producer_contract,
        "ida_runtime_identity": ida_runtime_identity,
        "warm_idb_generation": warm_idb_generation,
        "warm_idb_cache_key": warm_idb_cache_key,
        "full_rebuild": verification,
        "snapshot": {
            "path": public_paths[0],
            "sha256": sha256_file(snapshot_target),
            "file_count": snapshot_document["file_count"],
        },
        "metadata": {"path": public_paths[1], "sha256": sha256_file(metadata_target)},
        "gamedata": {
            "path": f"gamedata/{game_version}",
            "files": gamedata_session_files,
            "manifest_sha256": gamedata_evidence["gamedata_manifest_sha256"],
            "generator_contract_sha256": gamedata_evidence["generator_contract_sha256"],
        },
        "cpp_validation_sha256": sha256_file(cpp_validation_log),
        "binsync": _binsync_target_state(binsync_manifest),
        "archives": {
            f"archives/gamedata-{game_version}.7z": {
                "files": gamedata_archive_inventory,
                "inventory_sha256": inventory_sha256(gamedata_archive_inventory),
            },
            f"archives/gamebin-{game_version}.7z": {
                "files": gamebin_archive_inventory,
                "inventory_sha256": inventory_sha256(gamebin_archive_inventory),
            },
        },
        "public_assets": public_assets,
    }
    manifest_path = bundle_root / manifest_name
    write_canonical_json(manifest_path, manifest)
    checksum_records = [
        *public_assets,
        {
            "path": manifest_name,
            "name": manifest_name,
            "size": manifest_path.stat().st_size,
            "sha256": sha256_file(manifest_path),
        },
    ]
    checksum_payload = "".join(
        f"{item['sha256']}  {item['path']}\n" for item in sorted(checksum_records, key=lambda x: x["path"])
    )
    (bundle_root / checksums_name).write_text(checksum_payload, encoding="utf-8", newline="\n")
    verify_release_bundle(
        bundle_root=bundle_root,
        repo_root=repo_root,
        expected_source_sha=source_sha,
        expected_game_version=game_version,
        expected_release_version=release_version,
        expected_build_id=build_id,
        expected_actions_artifact_name=actions_artifact_name,
    )
    return manifest


def _verify_archive(archive: Path, expected: dict) -> None:
    with tempfile.TemporaryDirectory(prefix="verify-release-archive-") as temporary:
        extracted = Path(temporary) / "extracted"
        _extract_archive(archive, extracted, expected["files"])
        actual = file_inventory(extracted)
    if actual != expected["files"] or inventory_sha256(actual) != expected["inventory_sha256"]:
        raise ReleaseBundleError(f"Release archive content mismatch: {archive.name}")


def _verify_gamedata_reproducibility(*, repo_root: Path, bundle_root: Path, manifest: dict) -> None:
    game_version = manifest["game_version"]
    snapshot = bundle_root / PurePosixPath(manifest["snapshot"]["path"])
    with tempfile.TemporaryDirectory(prefix="verify-release-gamedata-") as temporary:
        temporary_root = Path(temporary)
        candidate_root = temporary_root / "candidate"
        session_path = temporary_root / "session.json"
        try:
            evidence = build_gamedata_candidate(
                gamever=game_version,
                build_id=manifest["build_id"],
                snapshot=snapshot,
                analysis_config=repo_root / "configs" / f"{game_version}.yaml",
                modules_dir=repo_root / "gamedata-generators",
                candidate_root=candidate_root,
                session_path=session_path,
            )
            difference = compare_gamedata_inventory(
                session=evidence,
                expected_files=manifest["gamedata"]["files"],
            )
        except (GamedataCandidateError, GamedataContractError, OSError, ValueError) as exc:
            raise ReleaseBundleError(f"Release gamedata fresh rebuild failed: {exc}") from exc
    if (
        not difference.matches
        or evidence["generator_contract_sha256"] != manifest["gamedata"]["generator_contract_sha256"]
        or evidence["gamedata_manifest_sha256"] != manifest["gamedata"]["manifest_sha256"]
    ):
        changed = [*difference.added, *difference.missing, *(item.path for item in difference.modified)]
        detail = ", ".join(changed[:10]) or "generator contract or manifest digest"
        raise ReleaseBundleError(f"Release gamedata is not reproducible from source-owned inputs: {detail}")


def validate_release_manifest(manifest: dict) -> None:
    """Validate the canonical public Release manifest schema and identities."""
    required = {
        "schema_version",
        "repository",
        "release_version",
        "game_version",
        "build_id",
        "actions_artifact_name",
        "source_sha",
        "source_subject",
        "download_sha256",
        "config_sha256",
        "sdk_gitlink_sha",
        "cpp_sdk",
        "sdk_files",
        "sdk_inventory_sha256",
        "binary_inventory",
        "binary_inventory_sha256",
        "artifact_inventory_sha256",
        "producer_contract",
        "ida_runtime_identity",
        "warm_idb_generation",
        "warm_idb_cache_key",
        "full_rebuild",
        "snapshot",
        "metadata",
        "gamedata",
        "cpp_validation_sha256",
        "binsync",
        "archives",
        "public_assets",
    }
    if set(manifest) != required or manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise ReleaseBundleError("Release manifest has unexpected fields or schema")
    if manifest.get("repository") != ALLOWED_REPOSITORY:
        raise ReleaseBundleError("Release manifest repository is not allowlisted")
    if not SHA_RE.fullmatch(str(manifest.get("source_sha", ""))):
        raise ReleaseBundleError("Release manifest source SHA is invalid")
    if not ARTIFACT_NAME_RE.fullmatch(str(manifest.get("actions_artifact_name", ""))):
        raise ReleaseBundleError("Release manifest Actions Artifact name is invalid")
    if not VERSION_RE.fullmatch(str(manifest.get("release_version", ""))) or not BUILD_ID_RE.fullmatch(
        str(manifest.get("build_id", ""))
    ):
        raise ReleaseBundleError("Release manifest version or build ID is invalid")
    cpp_sdk = manifest.get("cpp_sdk")
    if (
        not isinstance(cpp_sdk, dict)
        or set(cpp_sdk) != {"ref", "sha"}
        or not isinstance(cpp_sdk["ref"], str)
        or not cpp_sdk["ref"]
        or not SHA_RE.fullmatch(str(cpp_sdk["sha"]))
    ):
        raise ReleaseBundleError("Release C++ SDK identity is invalid")
    if (
        not SHA_RE.fullmatch(str(manifest.get("sdk_gitlink_sha", "")))
        or cpp_sdk["ref"] != CPP_SDK_REF
        or cpp_sdk["sha"] != manifest["sdk_gitlink_sha"]
    ):
        raise ReleaseBundleError("Release C++ SDK must equal the immutable source gitlink")
    for field in ("download_sha256", "config_sha256", "binary_inventory_sha256", "artifact_inventory_sha256"):
        if not DIGEST_RE.fullmatch(str(manifest.get(field, ""))):
            raise ReleaseBundleError(f"Release manifest {field} is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("cpp_validation_sha256", ""))):
        raise ReleaseBundleError("Release C++ validation evidence digest is invalid")
    full_rebuild = manifest.get("full_rebuild")
    if not isinstance(full_rebuild, dict):
        raise ReleaseBundleError("Release full-rebuild evidence is invalid")
    unsigned_rebuild = dict(full_rebuild)
    verification_digest = unsigned_rebuild.pop("verification_sha256", None)
    if verification_digest != _release_rebuild_digest("rebuild-verification", unsigned_rebuild):
        raise ReleaseBundleError("Release full-rebuild evidence digest mismatch")
    if (
        full_rebuild.get("source_sha") != manifest.get("source_sha")
        or full_rebuild.get("game_version") != manifest.get("game_version")
        or full_rebuild.get("artifact_inventory_sha256") != manifest.get("artifact_inventory_sha256")
    ):
        raise ReleaseBundleError("Release full-rebuild evidence identity mismatch")
    binsync = manifest.get("binsync")
    if not isinstance(binsync, dict) or not DIGEST_RE.fullmatch(str(binsync.get("candidate_publication_digest", ""))):
        raise ReleaseBundleError("Release BinSync candidate identity is invalid")
    game_version = manifest.get("game_version")
    expected_public_paths = {
        f"gamesymbols/{game_version}.yaml",
        f"gamesymbols/{game_version}.metadata.yaml",
        f"archives/gamedata-{game_version}.7z",
        f"archives/gamebin-{game_version}.7z",
    }
    public_assets = manifest.get("public_assets")
    if not isinstance(public_assets, list) or {
        item.get("path") for item in public_assets if isinstance(item, dict)
    } != (expected_public_paths):
        raise ReleaseBundleError("Release public asset allowlist is invalid")
    for item in public_assets:
        if (
            set(item) != {"path", "name", "size", "sha256"}
            or item["name"] != PurePosixPath(item["path"]).name
            or not isinstance(item["size"], int)
            or isinstance(item["size"], bool)
            or item["size"] <= 0
            or not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"]))
        ):
            raise ReleaseBundleError("Release public asset record is invalid")
    if (
        manifest.get("snapshot", {}).get("path") != f"gamesymbols/{game_version}.yaml"
        or manifest.get("metadata", {}).get("path") != f"gamesymbols/{game_version}.metadata.yaml"
    ):
        raise ReleaseBundleError("Release snapshot or metadata path is invalid")
    if manifest.get("gamedata", {}).get("path") != f"gamedata/{game_version}":
        raise ReleaseBundleError("Release gamedata path is invalid")
    if set(manifest.get("archives", {})) != {
        f"archives/gamedata-{game_version}.7z",
        f"archives/gamebin-{game_version}.7z",
    }:
        raise ReleaseBundleError("Release archive allowlist is invalid")


def _verify_source(repo_root: Path, manifest: dict) -> None:
    source_sha = manifest["source_sha"]
    if str(_git(repo_root, "rev-parse", "HEAD")).lower() != source_sha:
        raise ReleaseBundleError("hosted Release verifier checkout does not match source SHA")
    if str(_git(repo_root, "show", "-s", "--format=%s", source_sha)) != manifest["source_subject"]:
        raise ReleaseBundleError("hosted Release verifier source subject mismatch")
    if f"sha256:{sha256_bytes(_source_blob(repo_root, source_sha, 'download.yaml'))}" != manifest["download_sha256"]:
        raise ReleaseBundleError("hosted Release verifier download identity mismatch")
    if _producer_contract(repo_root, source_sha) != manifest["producer_contract"]:
        raise ReleaseBundleError("hosted Release verifier producer contract mismatch")
    game_version = manifest["game_version"]
    config_path = repo_root / "configs" / f"{game_version}.yaml"
    try:
        contract = load_contract(config_path, game_version, repo_root / "bin", artifactdir=repo_root / "bin_artifacts")
        artifacts = build_game_artifact_inventory(
            repo_root=repo_root,
            config_path=config_path,
            game_version=game_version,
            artifact_root=repo_root / "bin_artifacts",
            require_tracked=True,
        )
    except (SnapshotConfigError, ArtifactContractError) as exc:
        raise ReleaseBundleError(str(exc)) from exc
    if contract.config_sha256 != manifest["config_sha256"]:
        raise ReleaseBundleError("hosted Release verifier config identity mismatch")
    if artifacts.inventory_sha256 != manifest["artifact_inventory_sha256"]:
        raise ReleaseBundleError("hosted Release verifier artifact inventory mismatch")
    source_gitlink = str(_git(repo_root, "rev-parse", f"{source_sha}:hl2sdk_cs2")).lower()
    if source_gitlink != manifest["sdk_gitlink_sha"]:
        raise ReleaseBundleError("hosted Release verifier SDK gitlink mismatch")
    if manifest["cpp_sdk"] != {"ref": CPP_SDK_REF, "sha": source_gitlink}:
        raise ReleaseBundleError("hosted Release verifier C++ SDK differs from the source gitlink")
    sdk_files = _sdk_inventory(repo_root / "hl2sdk_cs2", manifest["cpp_sdk"]["sha"])
    if sdk_files != manifest["sdk_files"] or inventory_sha256(sdk_files) != manifest["sdk_inventory_sha256"]:
        raise ReleaseBundleError("hosted Release verifier SDK content mismatch")
    if _release_rebuild_digest("binary-inventory", manifest["binary_inventory"]) != manifest["binary_inventory_sha256"]:
        raise ReleaseBundleError("hosted Release verifier binary inventory digest mismatch")
    gamedata_archive = manifest["archives"].get(f"archives/gamedata-{game_version}.7z", {})
    expected_source_files = [
        {
            "path": item.path,
            "size": item.size,
            "sha256": item.sha256.removeprefix("sha256:"),
        }
        for item in artifacts.files
    ]
    expected_source_files.extend({**item, "path": f"hl2sdk_cs2/{item['path']}"} for item in manifest["sdk_files"])
    expected_source_files.extend(manifest["gamedata"]["files"])
    expected_source_files.extend(_binary_archive_inventory(game_version, manifest["binary_inventory"]))
    config_raw = _source_blob(repo_root, source_sha, f"configs/{game_version}.yaml")
    expected_source_files.append(
        {
            "path": f"configs/{game_version}.yaml",
            "size": len(config_raw),
            "sha256": sha256_bytes(config_raw),
        }
    )
    for public_key in ("snapshot", "metadata"):
        public_path = manifest[public_key]["path"]
        public_record = next(item for item in manifest["public_assets"] if item["path"] == public_path)
        expected_source_files.append(
            {"path": public_path, "size": public_record["size"], "sha256": public_record["sha256"]}
        )
    expected_source_files.sort(key=lambda item: item["path"])
    if gamedata_archive.get("files") != expected_source_files:
        raise ReleaseBundleError("gamedata archive source identity must match the exact source-derived inventory")


def verify_release_bundle(
    *,
    bundle_root: str | Path,
    repo_root: str | Path,
    expected_source_sha: str | None = None,
    expected_game_version: str | None = None,
    expected_release_version: str | None = None,
    expected_build_id: str | None = None,
    expected_actions_artifact_name: str | None = None,
    expected_binsync_candidate_digest: str | None = None,
    expected_binsync_target_state_digest: str | None = None,
) -> dict:
    bundle_root = Path(bundle_root).resolve()
    repo_root = Path(repo_root).resolve()
    try:
        reject_reparse_points(bundle_root)
    except ReleaseWorkflowError as exc:
        raise ReleaseBundleError(str(exc)) from exc
    manifests = list(bundle_root.glob("release-manifest-*.json"))
    if len(manifests) != 1:
        raise ReleaseBundleError("Release bundle must contain exactly one manifest")
    manifest_path = manifests[0]
    try:
        manifest = load_json_object(manifest_path)
    except ReleaseWorkflowError as exc:
        raise ReleaseBundleError(str(exc)) from exc
    if manifest_path.read_bytes() != canonical_json_bytes(manifest):
        raise ReleaseBundleError("Release manifest is not canonical JSON")
    validate_release_manifest(manifest)
    expected_values = {
        "source SHA": (expected_source_sha.lower() if expected_source_sha else None, manifest["source_sha"]),
        "GAMEVER": (
            str(expected_game_version) if expected_game_version is not None else None,
            manifest["game_version"],
        ),
        "release version": (expected_release_version, manifest["release_version"]),
        "build ID": (expected_build_id, manifest["build_id"]),
        "Actions Artifact name": (expected_actions_artifact_name, manifest["actions_artifact_name"]),
    }
    for label, (expected, actual) in expected_values.items():
        if expected is not None and expected != actual:
            raise ReleaseBundleError(f"Release bundle {label} mismatch: expected {expected}, got {actual}")
    if (
        expected_binsync_candidate_digest is not None
        and manifest["binsync"]["candidate_publication_digest"] != expected_binsync_candidate_digest
    ):
        raise ReleaseBundleError("Release bundle BinSync candidate digest mismatch")
    if (
        expected_binsync_target_state_digest is not None
        and manifest["binsync"]["target_state_digest"] != expected_binsync_target_state_digest
    ):
        raise ReleaseBundleError("Release bundle BinSync target-state digest mismatch")

    game_version = manifest["game_version"]
    public_assets = manifest["public_assets"]
    if not isinstance(public_assets, list) or len({item.get("name") for item in public_assets}) != len(public_assets):
        raise ReleaseBundleError("Release public asset names are invalid or collide")
    allowed_paths = {
        manifest_path.name,
        f"SHA256SUMS-{manifest['release_version']}.txt",
        *(item["path"] for item in public_assets),
        *(item["path"] for item in manifest["gamedata"]["files"]),
    }
    actual_paths = {path.relative_to(bundle_root).as_posix() for path in bundle_root.rglob("*") if path.is_file()}
    if actual_paths != allowed_paths:
        raise ReleaseBundleError("Release bundle contains unexpected or missing paths")
    for item in public_assets:
        path = bundle_root / PurePosixPath(item["path"])
        if path.stat().st_size != item["size"] or sha256_file(path) != item["sha256"]:
            raise ReleaseBundleError(f"Release public asset mismatch: {item['path']}")
    gamedata_root = bundle_root / "gamedata" / game_version
    gamedata_files = [
        {**item, "path": f"gamedata/{game_version}/{item['path']}"} for item in file_inventory(gamedata_root)
    ]
    if gamedata_files != manifest["gamedata"]["files"]:
        raise ReleaseBundleError("Release gamedata inventory mismatch")
    modules = discover_generator_modules(repo_root / "gamedata-generators")
    generated_files = validate_output_tree(gamedata_root, game_version, modules)
    if (
        generated_files != manifest["gamedata"]["files"]
        or generator_contract_sha256(modules) != manifest["gamedata"]["generator_contract_sha256"]
        or gamedata_manifest_sha256(generated_files) != manifest["gamedata"]["manifest_sha256"]
    ):
        raise ReleaseBundleError("Release gamedata generator contract mismatch")

    metadata_path = bundle_root / PurePosixPath(manifest["metadata"]["path"])
    with tempfile.TemporaryDirectory(prefix="verify-release-metadata-") as temporary:
        regenerated = Path(temporary) / metadata_path.name
        try:
            generate_metadata(game_version, repo_root / "configs" / f"{game_version}.yaml", regenerated)
        except MetadataGenerationError as exc:
            raise ReleaseBundleError(str(exc)) from exc
        if regenerated.read_bytes() != metadata_path.read_bytes():
            raise ReleaseBundleError("Release metadata bytes are not reproducible")
    contract = load_contract(
        repo_root / "configs" / f"{game_version}.yaml",
        game_version,
        repo_root / "bin",
        artifactdir=repo_root / "bin_artifacts",
    )
    _validate_snapshot(bundle_root / PurePosixPath(manifest["snapshot"]["path"]), contract)
    _verify_gamedata_reproducibility(repo_root=repo_root, bundle_root=bundle_root, manifest=manifest)
    for path, expected in manifest["archives"].items():
        _verify_archive(bundle_root / PurePosixPath(path), expected)
    expected_binaries = _binary_archive_inventory(game_version, manifest["binary_inventory"])
    gamebin_key = f"archives/gamebin-{game_version}.7z"
    gamedata_key = f"archives/gamedata-{game_version}.7z"
    if manifest["archives"].get(gamebin_key, {}).get("files") != expected_binaries:
        raise ReleaseBundleError("gamebin archive is not the exact configured binary inventory")
    gamedata_binary_files = [
        item for item in manifest["archives"].get(gamedata_key, {}).get("files", []) if item["path"].startswith("bin/")
    ]
    if gamedata_binary_files != expected_binaries:
        raise ReleaseBundleError("gamedata archive binary inventory mismatch")
    target_repositories = manifest["binsync"]["repositories"]
    if _digest("binsync-intended-remote-state:v1", target_repositories) != manifest["binsync"]["target_state_digest"]:
        raise ReleaseBundleError("Release BinSync target-state digest mismatch")

    checksum_records = [
        *public_assets,
        {
            "path": manifest_path.name,
            "name": manifest_path.name,
            "size": manifest_path.stat().st_size,
            "sha256": sha256_file(manifest_path),
        },
    ]
    expected_checksums = "".join(
        f"{item['sha256']}  {item['path']}\n" for item in sorted(checksum_records, key=lambda value: value["path"])
    ).encode("utf-8")
    checksums_path = bundle_root / f"SHA256SUMS-{manifest['release_version']}.txt"
    if checksums_path.read_bytes() != expected_checksums:
        raise ReleaseBundleError("Release SHA256SUMS contract mismatch")
    _verify_source(repo_root, manifest)
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "source_sha": manifest["source_sha"],
        "game_version": game_version,
        "release_version": manifest["release_version"],
        "build_id": manifest["build_id"],
        "manifest_sha256": sha256_file(manifest_path),
        "bundle_inventory_sha256": inventory_sha256(file_inventory(bundle_root)),
        "binsync_target_state_digest": manifest["binsync"]["target_state_digest"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--repo-root", default=".")
    build.add_argument("--bundle-root", required=True)
    build.add_argument("--repository", required=True)
    build.add_argument("--release-version", required=True)
    build.add_argument("--build-id", required=True)
    build.add_argument("--preparation", required=True)
    build.add_argument("--rebuild-verification", required=True)
    build.add_argument("--snapshot", required=True)
    build.add_argument("--metadata", required=True)
    build.add_argument("--gamedata-candidate-root", required=True)
    build.add_argument("--gamedata-session", required=True)
    build.add_argument("--cpp-validation-log", required=True)
    build.add_argument("--binsync-candidate-root", required=True)
    build.add_argument("--ida-runtime-identity", required=True)
    build.add_argument("--warm-idb-generation", required=True)
    build.add_argument("--warm-idb-cache-key", required=True)
    build.add_argument("--actions-artifact-name", required=True)
    build.add_argument("--cpp-sdk-ref", required=True)
    build.add_argument("--cpp-sdk-sha", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--repo-root", default=".")
    verify.add_argument("--bundle-root", required=True)
    verify.add_argument("--source-sha")
    verify.add_argument("--gamever")
    verify.add_argument("--release-version")
    verify.add_argument("--build-id")
    verify.add_argument("--actions-artifact-name")
    verify.add_argument("--binsync-candidate-digest")
    verify.add_argument("--binsync-target-state-digest")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build":
            result = build_release_bundle(
                repo_root=args.repo_root,
                bundle_root=args.bundle_root,
                repository=args.repository,
                release_version=args.release_version,
                build_id=args.build_id,
                preparation=args.preparation,
                rebuild_verification=args.rebuild_verification,
                snapshot=args.snapshot,
                metadata=args.metadata,
                gamedata_candidate_root=args.gamedata_candidate_root,
                gamedata_session=args.gamedata_session,
                cpp_validation_log=args.cpp_validation_log,
                binsync_candidate_root=args.binsync_candidate_root,
                ida_runtime_identity=args.ida_runtime_identity,
                warm_idb_generation=args.warm_idb_generation,
                warm_idb_cache_key=args.warm_idb_cache_key,
                actions_artifact_name=args.actions_artifact_name,
                cpp_sdk_ref=args.cpp_sdk_ref,
                cpp_sdk_sha=args.cpp_sdk_sha,
            )
        else:
            result = verify_release_bundle(
                bundle_root=args.bundle_root,
                repo_root=args.repo_root,
                expected_source_sha=args.source_sha,
                expected_game_version=args.gamever,
                expected_release_version=args.release_version,
                expected_build_id=args.build_id,
                expected_actions_artifact_name=args.actions_artifact_name,
                expected_binsync_candidate_digest=args.binsync_candidate_digest,
                expected_binsync_target_state_digest=args.binsync_target_state_digest,
            )
    except (ReleaseBundleError, OSError, ValueError) as exc:
        print(f"Release bundle error: {exc}", file=sys.stderr)
        return 1
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Source-owned binary identity locks bound to config and depot manifests."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping

import yaml

from binary_hashing import hash_file
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    normalized_relative_path,
    reject_reparse_components,
    sha256_bytes,
    write_canonical_json,
)
from trusted_yaml import load_yaml


BINARY_LOCK_SCHEMA_VERSION = 1
DEFAULT_APP_ID = "730"
DEFAULT_OS = "all-platform"
LOCK_FIELDS = {"schema_version", "game_version", "download", "binaries"}
DOWNLOAD_FIELDS = {"app_id", "branch", "manifests", "os"}
BINARY_FIELDS = {"path", "sha256", "md5", "crc32", "crc64", "size"}
PLATFORMS = frozenset({"windows", "linux"})
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MD5_RE = re.compile(r"^[0-9a-f]{32}$")
CRC32_RE = re.compile(r"^[0-9a-f]{8}$")
CRC64_RE = re.compile(r"^[0-9a-f]{16}$")


class BinaryLockError(ValueError):
    """Raised when a source-owned binary identity lock is invalid or drifts."""


@dataclass(frozen=True)
class BinaryLockContext:
    document: dict
    raw_bytes: bytes
    sha256: str


def _require_exact_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("extra=" + ",".join(extra))
        raise BinaryLockError(f"{label} fields are invalid ({'; '.join(details)})")


def _normalized_targets(binary_targets: Mapping) -> dict[tuple[str, str], str]:
    targets: dict[tuple[str, str], str] = {}
    for key, target in binary_targets.items():
        if not isinstance(key, tuple) or len(key) != 2:
            raise BinaryLockError("binary target key is invalid")
        module, platform = key
        source_path = getattr(target, "source_path", None)
        if not isinstance(module, str) or not module or "/" in module or "\\" in module:
            raise BinaryLockError("binary target module is invalid")
        if platform not in PLATFORMS or not isinstance(source_path, str):
            raise BinaryLockError(f"binary target is invalid: {module}/{platform}")
        try:
            source_path = normalized_relative_path(source_path)
        except ReleaseWorkflowError as exc:
            raise BinaryLockError(f"binary target path is invalid: {exc}") from exc
        normalized_key = (module, platform)
        if normalized_key in targets:
            raise BinaryLockError(f"duplicate binary target: {module}/{platform}")
        targets[normalized_key] = source_path
    if not targets:
        raise BinaryLockError("binary target inventory is empty")
    return targets


def download_identity(download_payload: bytes, game_version: str) -> dict:
    """Return the immutable DepotDownloader selection for one exact GAMEVER."""
    try:
        document = load_yaml(download_payload) or {}
    except (UnicodeError, yaml.YAMLError) as exc:
        raise BinaryLockError("download config is invalid YAML") from exc
    downloads = document.get("downloads") if isinstance(document, dict) else None
    if not isinstance(downloads, list):
        raise BinaryLockError("download config must contain a downloads list")
    matches = [item for item in downloads if isinstance(item, dict) and item.get("tag") == game_version]
    if len(matches) != 1:
        raise BinaryLockError(f"download config must contain exactly one entry for GAMEVER {game_version}")
    entry = matches[0]
    branch = entry.get("branch")
    if branch is not None and (not isinstance(branch, str) or not branch):
        raise BinaryLockError("download branch is invalid")
    manifests = entry.get("manifests")
    if not isinstance(manifests, dict) or not manifests:
        raise BinaryLockError("download manifests are invalid")
    normalized_manifests = {}
    for depot, manifest in manifests.items():
        if (
            not isinstance(depot, str)
            or not depot.isdecimal()
            or not isinstance(manifest, str)
            or not manifest.isdecimal()
            or depot in normalized_manifests
        ):
            raise BinaryLockError("download manifests are invalid")
        normalized_manifests[depot] = manifest
    return {
        "app_id": DEFAULT_APP_ID,
        "branch": branch,
        "manifests": normalized_manifests,
        "os": DEFAULT_OS,
    }


def _validate_binary_metadata(metadata: object, *, module: str, platform: str, expected_path: str) -> dict:
    if not isinstance(metadata, dict):
        raise BinaryLockError(f"binary metadata is invalid: {module}/{platform}")
    _require_exact_keys(metadata, BINARY_FIELDS, f"binary metadata {module}/{platform}")
    try:
        path = normalized_relative_path(metadata["path"])
    except (ReleaseWorkflowError, TypeError) as exc:
        raise BinaryLockError(f"binary path is invalid: {module}/{platform}") from exc
    if path != expected_path:
        raise BinaryLockError(f"binary target mismatch: {module}/{platform}")
    patterns = {
        "sha256": SHA256_RE,
        "md5": MD5_RE,
        "crc32": CRC32_RE,
        "crc64": CRC64_RE,
    }
    for field, pattern in patterns.items():
        if not isinstance(metadata[field], str) or not pattern.fullmatch(metadata[field]):
            raise BinaryLockError(f"binary {field} is invalid: {module}/{platform}")
    if not isinstance(metadata["size"], int) or isinstance(metadata["size"], bool) or metadata["size"] <= 0:
        raise BinaryLockError(f"binary size is invalid: {module}/{platform}")
    return metadata


def validate_binary_lock(
    document: object,
    *,
    game_version: str,
    download_payload: bytes,
    binary_targets: Mapping,
) -> dict:
    """Validate exact lock schema plus source config/download semantic identity."""
    if not isinstance(document, dict):
        raise BinaryLockError("binary lock top level must be an object")
    _require_exact_keys(document, LOCK_FIELDS, "binary lock")
    if document["schema_version"] != BINARY_LOCK_SCHEMA_VERSION:
        raise BinaryLockError("binary lock schema version is invalid")
    if document["game_version"] != game_version:
        raise BinaryLockError("binary lock GAMEVER mismatch")
    download = document["download"]
    if not isinstance(download, dict):
        raise BinaryLockError("binary lock download identity is invalid")
    _require_exact_keys(download, DOWNLOAD_FIELDS, "binary lock download identity")
    if download != download_identity(download_payload, game_version):
        raise BinaryLockError("binary lock download identity mismatch")

    targets = _normalized_targets(binary_targets)
    binaries = document["binaries"]
    if not isinstance(binaries, dict):
        raise BinaryLockError("binary lock inventory is invalid")
    actual_keys: set[tuple[str, str]] = set()
    for module, platforms in binaries.items():
        if not isinstance(module, str) or not module or not isinstance(platforms, dict) or not platforms:
            raise BinaryLockError("binary lock inventory is invalid")
        for platform, metadata in platforms.items():
            key = (module, platform)
            expected_path = targets.get(key)
            if expected_path is None:
                raise BinaryLockError(f"binary target mismatch: {module}/{platform}")
            if key in actual_keys:
                raise BinaryLockError(f"duplicate binary target: {module}/{platform}")
            _validate_binary_metadata(
                metadata,
                module=module,
                platform=platform,
                expected_path=expected_path,
            )
            actual_keys.add(key)
    if actual_keys != set(targets):
        raise BinaryLockError("binary target mismatch: configured target set differs from the lock")
    return document


def build_binary_lock(
    *,
    game_version: str,
    download_payload: bytes,
    binary_targets: Mapping,
    binaries: dict,
) -> dict:
    """Build a canonical lock document from already measured binary metadata."""
    document = {
        "schema_version": BINARY_LOCK_SCHEMA_VERSION,
        "game_version": game_version,
        "download": download_identity(download_payload, game_version),
        "binaries": binaries,
    }
    return validate_binary_lock(
        document,
        game_version=game_version,
        download_payload=download_payload,
        binary_targets=binary_targets,
    )


def build_binary_lock_from_root(
    *,
    game_version: str,
    download_payload: bytes,
    binary_targets: Mapping,
    binary_root: Path,
) -> dict:
    """Measure every configured binary under one GAMEVER root and build its lock."""
    targets = _normalized_targets(binary_targets)
    binary_root = Path(binary_root)
    if not binary_root.is_dir():
        raise BinaryLockError(f"binary root is missing: {binary_root}")
    binaries: dict[str, dict[str, dict]] = {}
    for (module, platform), source_path in sorted(targets.items()):
        path = binary_root / module / PurePosixPath(source_path).name
        try:
            reject_reparse_components(binary_root, path)
        except (OSError, ReleaseWorkflowError) as exc:
            raise BinaryLockError(f"binary path is unsafe: {path}: {exc}") from exc
        if not path.is_file():
            raise BinaryLockError(f"binary file is missing: {path}")
        try:
            metadata = {"path": source_path, **hash_file(path)}
        except OSError as exc:
            raise BinaryLockError(f"unable to hash binary file {path}: {exc}") from exc
        binaries.setdefault(module, {})[platform] = metadata
    return build_binary_lock(
        game_version=game_version,
        download_payload=download_payload,
        binary_targets=binary_targets,
        binaries=binaries,
    )


def _load_json_bytes(payload: bytes, label: str) -> dict:
    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise BinaryLockError(f"duplicate JSON key {key!r} in {label}")
            value[key] = item
        return value

    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BinaryLockError(f"unable to parse binary lock {label}: {exc}") from exc
    if not isinstance(document, dict):
        raise BinaryLockError(f"binary lock top level must be an object: {label}")
    if payload != canonical_json_bytes(document):
        raise BinaryLockError(f"binary lock is not canonical JSON: {label}")
    return document


def _context(
    payload: bytes,
    *,
    label: str,
    game_version: str,
    download_payload: bytes,
    binary_targets: Mapping,
) -> BinaryLockContext:
    document = _load_json_bytes(payload, label)
    validate_binary_lock(
        document,
        game_version=game_version,
        download_payload=download_payload,
        binary_targets=binary_targets,
    )
    return BinaryLockContext(document, payload, f"sha256:{sha256_bytes(payload)}")


def load_binary_lock(
    path: Path,
    *,
    game_version: str,
    download_payload: bytes,
    binary_targets: Mapping,
) -> BinaryLockContext:
    try:
        payload = Path(path).read_bytes()
    except OSError as exc:
        raise BinaryLockError(f"unable to read binary lock {path}: {exc}") from exc
    return _context(
        payload,
        label=str(path),
        game_version=game_version,
        download_payload=download_payload,
        binary_targets=binary_targets,
    )


def load_binary_lock_from_revision(
    *,
    repo_root: Path,
    revision: str,
    game_version: str,
    download_payload: bytes,
    binary_targets: Mapping,
) -> BinaryLockContext:
    """Load a lock from an immutable Git blob rather than mutable checkout bytes."""
    revision = revision.lower()
    if not SHA_RE.fullmatch(revision):
        raise BinaryLockError("binary lock Git revision is invalid")
    relative_path = f"binary_locks/{game_version}.json"
    result = subprocess.run(
        ["git", "-C", str(Path(repo_root)), "cat-file", "blob", f"{revision}:{relative_path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise BinaryLockError(detail or f"unable to read binary lock Git blob: {relative_path}")
    return _context(
        result.stdout,
        label=f"{revision}:{relative_path}",
        game_version=game_version,
        download_payload=download_payload,
        binary_targets=binary_targets,
    )


def verify_binary_root(document: dict, binary_root: Path) -> dict:
    """Require every configured local binary to exactly match the source-owned lock."""
    binary_root = Path(binary_root)
    if not binary_root.is_dir():
        raise BinaryLockError(f"binary root is missing: {binary_root}")
    for module, platforms in document["binaries"].items():
        for platform, expected in platforms.items():
            path = binary_root / module / PurePosixPath(expected["path"]).name
            try:
                reject_reparse_components(binary_root, path)
            except (OSError, ReleaseWorkflowError) as exc:
                raise BinaryLockError(f"binary path is unsafe: {path}: {exc}") from exc
            if not path.is_file():
                raise BinaryLockError(f"binary file is missing: {path}")
            try:
                actual = {"path": expected["path"], **hash_file(path)}
            except OSError as exc:
                raise BinaryLockError(f"unable to hash binary file {path}: {exc}") from exc
            if actual != expected:
                raise BinaryLockError(f"binary identity mismatch: {module}/{platform}")
    return document["binaries"]


def write_binary_lock(path: Path, document: dict) -> None:
    write_canonical_json(path, document)

#!/usr/bin/env python3
"""Inject fixed historical gamedata from the pinned pages-snapshots archive into a Pages staging tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    file_inventory,
    inventory_sha256,
    normalized_relative_path,
    sha256_bytes,
)

ALLOWED_REPOSITORY = "HLND2T/CS2_VibeSignatures"
LEGACY_INPUTS_SCHEMA_VERSION = 1
LEGACY_INPUTS_RECEIPT_SCHEMA_VERSION = 1
GAMESYMBOLS_PREFIX = "gamesymbols/"
GAMEDATA_PREFIX = "gamedata/"
GAME_VERSION_RE = re.compile(r"^\d{4,10}[a-z]?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PUBLISH_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
GAMESYMBOL_FILE_RE = re.compile(r"^gamesymbols/\d{4,10}[a-z]?\.[0-9a-f]{64}\.json$")


class LegacyInputError(Exception):
    """Raised when the pinned legacy inputs manifest or archive is not trustworthy."""


def _fail(source: str, message: str) -> None:
    raise LegacyInputError(f"{source}: {message}")


def _strict_json_bytes(raw: bytes, source: str) -> dict:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise LegacyInputError(f"{source}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LegacyInputError(f"{source}: invalid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        _fail(source, "top level must be an object")
    if raw != canonical_json_bytes(value):
        _fail(source, "manifest is not canonical JSON")
    return value


def _require_exact_keys(value: object, keys: tuple[str, ...], source: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys):
        _fail(source, f"expected keys {', '.join(sorted(keys))}")
    return value


def _require_string(value: object, source: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(source, "must be a non-empty string")
    return value


def _require_integer(value: object, source: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        _fail(source, f"must be an integer >= {minimum}")
    return value


def _require_game_version(value: object, source: str) -> str:
    if not isinstance(value, str) or not GAME_VERSION_RE.fullmatch(value):
        _fail(source, "is not a game version")
    return value


def _require_sha(value: object, source: str) -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        _fail(source, "must be a lowercase 40-hex commit SHA")
    return value


def _relative_path(value: object, source: str) -> str:
    if isinstance(value, str) and ":" in value:
        _fail(source, "must not contain a drive/stream separator")
    try:
        return normalized_relative_path(value)  # type: ignore[arg-type]
    except (ReleaseWorkflowError, TypeError) as exc:
        raise LegacyInputError(f"{source}: {exc}") from exc


def _version_key(game_version: str) -> tuple[int, str]:
    if not GAME_VERSION_RE.fullmatch(game_version):
        raise LegacyInputError(f"invalid game version {game_version!r}")
    if game_version[-1].isalpha():
        return (int(game_version[:-1]), game_version[-1])
    return (int(game_version), "")


def _assert_sorted(values: list, sort_key, source: str, label: str) -> None:
    keys = [sort_key(value) for value in values]
    if any(keys[index - 1] >= keys[index] for index in range(1, len(keys))):
        _fail(source, f"{label} must be strictly sorted and unique")


def _validate_file_inventory(value: object, source: str, *, prefix: str, pattern=None) -> list[dict]:
    if not isinstance(value, list) or not value:
        _fail(source, "must be a non-empty file inventory")
    records = []
    seen = set()
    for index, item in enumerate(value):
        item_source = f"{source}[{index}]"
        _require_exact_keys(item, ("path", "size", "sha256"), item_source)
        path = _relative_path(item["path"], f"{item_source}.path")
        if not path.startswith(prefix):
            _fail(f"{item_source}.path", f"must be under {prefix}")
        if pattern is not None and not pattern.fullmatch(path):
            _fail(f"{item_source}.path", "has an unexpected file name")
        _require_integer(item["size"], f"{item_source}.size")
        if not isinstance(item["sha256"], str) or not SHA256_RE.fullmatch(item["sha256"]):
            _fail(f"{item_source}.sha256", "must be a lowercase SHA-256")
        if path in seen:
            _fail(source, f"duplicate path {path}")
        seen.add(path)
        records.append({"path": path, "size": item["size"], "sha256": item["sha256"]})
    _assert_sorted([record["path"] for record in records], lambda path: path, source, "file inventory")
    return records


def _validate_selected(value: object, source: str, file_by_path: dict[str, dict]) -> None:
    if not isinstance(value, list) or not value:
        _fail(source, "must be a non-empty selected list")
    versions = []
    seen_versions = set()
    for index, item in enumerate(value):
        item_source = f"{source}[{index}]"
        _require_exact_keys(
            item,
            ("gameVersion", "url", "sha256", "size", "fileCount", "snapshotSchemaVersion", "lastPublishTime"),
            item_source,
        )
        game_version = _require_game_version(item["gameVersion"], f"{item_source}.gameVersion")
        if not isinstance(item["sha256"], str) or not SHA256_RE.fullmatch(item["sha256"]):
            _fail(f"{item_source}.sha256", "must be a lowercase SHA-256")
        if item["url"] != f"{game_version}.{item['sha256']}.json":
            _fail(f"{item_source}.url", "must be <gameVersion>.<sha256>.json")
        record = file_by_path.get(f"{GAMESYMBOLS_PREFIX}{item['url']}")
        if record is None:
            _fail(f"{item_source}.url", "is absent from the archived file inventory")
        if record["sha256"] != item["sha256"] or record["size"] != item["size"]:
            _fail(item_source, "size or SHA-256 differs from the archived file inventory")
        _require_integer(item["size"], f"{item_source}.size", minimum=1)
        _require_integer(item["fileCount"], f"{item_source}.fileCount")
        _require_integer(item["snapshotSchemaVersion"], f"{item_source}.snapshotSchemaVersion")
        if not isinstance(item["lastPublishTime"], str) or not PUBLISH_TIME_RE.fullmatch(item["lastPublishTime"]):
            _fail(f"{item_source}.lastPublishTime", "must be UTC ISO 8601 with second precision")
        if game_version in seen_versions:
            _fail(source, f"duplicate gameVersion {game_version}")
        seen_versions.add(game_version)
        versions.append(game_version)
    _assert_sorted(versions, _version_key, source, "selected game versions")


def _validate_gamesymbols(value: object, source: str) -> None:
    _require_exact_keys(value, ("files", "selected"), source)
    files = _validate_file_inventory(value["files"], f"{source}.files", prefix=GAMESYMBOLS_PREFIX, pattern=GAMESYMBOL_FILE_RE)
    _validate_selected(value["selected"], f"{source}.selected", {item["path"]: item for item in files})


def _validate_gamedata(value: object, source: str) -> None:
    _require_exact_keys(value, ("versions",), source)
    versions = value["versions"]
    if not isinstance(versions, list) or not versions:
        _fail(f"{source}.versions", "must be a non-empty list")
    version_keys = []
    seen_versions = set()
    seen_paths = set()
    for index, version in enumerate(versions):
        version_source = f"{source}.versions[{index}]"
        _require_exact_keys(version, ("gameVersion", "files"), version_source)
        game_version = _require_game_version(version["gameVersion"], f"{version_source}.gameVersion")
        if game_version in seen_versions:
            _fail(source, f"duplicate gamedata gameVersion {game_version}")
        seen_versions.add(game_version)
        files = _validate_file_inventory(version["files"], f"{version_source}.files", prefix=f"{GAMEDATA_PREFIX}{game_version}/")
        for item in files:
            relative = item["path"][len(GAMEDATA_PREFIX):]
            directory, _, rest = relative.partition("/")
            if directory != game_version or not rest:
                _fail(f"{version_source}.files", f"path directory must be {game_version}")
            if item["path"] in seen_paths:
                _fail(source, f"duplicate gamedata path {item['path']}")
            seen_paths.add(item["path"])
        version_keys.append(game_version)
    _assert_sorted(version_keys, _version_key, source, "gamedata game versions")


def _validate_excluded(value: object, source: str) -> None:
    if not isinstance(value, list):
        _fail(source, "must be a list")
    keys = []
    for index, item in enumerate(value):
        item_source = f"{source}[{index}]"
        _require_exact_keys(item, ("kind", "gameVersion", "reason"), item_source)
        kind = _require_string(item["kind"], f"{item_source}.kind")
        game_version = _require_game_version(item["gameVersion"], f"{item_source}.gameVersion")
        _require_string(item["reason"], f"{item_source}.reason")
        keys.append(f"{kind} {game_version}")
    _assert_sorted(keys, lambda key: key, source, "excluded entries")


def _validate_import_provenance(value: object, source: str, gamedata_versions: list[str]) -> None:
    _require_exact_keys(value, ("sourceArchiveCommit", "importBaseCommit", "selectedBasis", "releases"), source)
    _require_sha(value["sourceArchiveCommit"], f"{source}.sourceArchiveCommit")
    _require_sha(value["importBaseCommit"], f"{source}.importBaseCommit")
    basis = _require_exact_keys(value["selectedBasis"], ("kind", "sourceCommit", "indexSha256", "indexSize"), f"{source}.selectedBasis")
    _require_string(basis["kind"], f"{source}.selectedBasis.kind")
    _require_sha(basis["sourceCommit"], f"{source}.selectedBasis.sourceCommit")
    if not isinstance(basis["indexSha256"], str) or not SHA256_RE.fullmatch(basis["indexSha256"]):
        _fail(f"{source}.selectedBasis.indexSha256", "must be a lowercase SHA-256")
    _require_integer(basis["indexSize"], f"{source}.selectedBasis.indexSize", minimum=1)
    releases = value["releases"]
    if not isinstance(releases, list) or not releases:
        _fail(f"{source}.releases", "must be a non-empty list")
    tags = []
    for index, item in enumerate(releases):
        item_source = f"{source}.releases[{index}]"
        _require_exact_keys(item, ("tag", "releaseId", "assetId", "assetName", "assetSize", "sha256", "apiDigest"), item_source)
        tag = _require_game_version(item["tag"], f"{item_source}.tag")
        _require_integer(item["releaseId"], f"{item_source}.releaseId", minimum=1)
        _require_integer(item["assetId"], f"{item_source}.assetId", minimum=1)
        if item["assetName"] != f"gamedata-{tag}.7z":
            _fail(f"{item_source}.assetName", f"must be gamedata-{tag}.7z")
        _require_integer(item["assetSize"], f"{item_source}.assetSize", minimum=1)
        if not isinstance(item["sha256"], str) or not SHA256_RE.fullmatch(item["sha256"]):
            _fail(f"{item_source}.sha256", "must be a lowercase SHA-256")
        digest = item["apiDigest"]
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)):
            _fail(f"{item_source}.apiDigest", "must be null or sha256:<hex>")
        tags.append(tag)
    _assert_sorted(tags, _version_key, source, "release tags")
    if tags != gamedata_versions:
        _fail(f"{source}.releases", "must cover exactly the archived gamedata versions")


def _validate_legacy_inputs(value: object, source: str) -> dict:
    _require_exact_keys(
        value,
        ("schemaVersion", "repository", "archiveCommit", "gamesymbols", "gamedata", "excluded", "importProvenance"),
        source,
    )
    if value["schemaVersion"] != LEGACY_INPUTS_SCHEMA_VERSION:
        _fail(source, f"expected schemaVersion {LEGACY_INPUTS_SCHEMA_VERSION}")
    if value["repository"] != ALLOWED_REPOSITORY:
        _fail(f"{source}.repository", f"must be {ALLOWED_REPOSITORY}")
    _require_sha(value["archiveCommit"], f"{source}.archiveCommit")
    _validate_gamesymbols(value["gamesymbols"], f"{source}.gamesymbols")
    _validate_gamedata(value["gamedata"], f"{source}.gamedata")
    _validate_excluded(value["excluded"], f"{source}.excluded")
    gamedata_versions = [version["gameVersion"] for version in value["gamedata"]["versions"]]
    _validate_import_provenance(value["importProvenance"], f"{source}.importProvenance", gamedata_versions)

    selected_versions = {item["gameVersion"] for item in value["gamesymbols"]["selected"]}
    gamedata_version_set = set(gamedata_versions)
    for item in value["excluded"]:
        included = selected_versions if item["kind"] == "gamesymbols" else gamedata_version_set
        if item["gameVersion"] in included:
            _fail(f"{source}.excluded", f"{item['kind']} {item['gameVersion']} is both excluded and included")
    return value


def parse_legacy_inputs(raw: bytes, source: str) -> dict:
    return _validate_legacy_inputs(_strict_json_bytes(raw, source), source)


def _gamedata_inventory(manifest: dict) -> list[dict]:
    records = []
    for version in manifest["gamedata"]["versions"]:
        for item in version["files"]:
            records.append(
                {"path": item["path"][len(GAMEDATA_PREFIX):], "size": item["size"], "sha256": item["sha256"]}
            )
    records.sort(key=lambda item: item["path"])
    return records


def _copy_version(source_root: Path, target_root: Path) -> None:
    for path in source_root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(source_root)
        destination = target_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)


def stage_legacy_gamedata(
    *,
    manifest_path: str | Path,
    archive_root: str | Path,
    staging_root: str | Path,
    receipt_path: str | Path,
) -> dict:
    manifest_path = Path(manifest_path).resolve()
    raw = manifest_path.read_bytes()
    manifest = parse_legacy_inputs(raw, str(manifest_path))
    if manifest["repository"] != ALLOWED_REPOSITORY:
        raise LegacyInputError("repository is not allowlisted")

    archive_root = Path(archive_root).resolve()
    staging_root = Path(staging_root).resolve()
    gamedata_source = archive_root / "gamedata"
    if not gamedata_source.is_dir():
        raise LegacyInputError(f"archive gamedata subtree is missing: {gamedata_source}")
    expected = _gamedata_inventory(manifest)
    try:
        actual = file_inventory(gamedata_source)
    except ReleaseWorkflowError as exc:
        raise LegacyInputError(str(exc)) from exc
    if actual != expected:
        raise LegacyInputError(f"{gamedata_source}: archive inventory differs from the pinned manifest")

    staging_gamedata = staging_root / "gamedata"
    if not staging_gamedata.is_dir():
        raise LegacyInputError(f"staging gamedata directory is missing: {staging_gamedata}")

    added: list[dict] = []
    skipped: list[str] = []
    try:
        for version in manifest["gamedata"]["versions"]:
            game_version = version["gameVersion"]
            target = staging_gamedata / game_version
            if target.exists():
                if not target.is_dir():
                    raise LegacyInputError(f"{target}: existing gamedata version is not a directory")
                skipped.append(game_version)
                continue
            temporary = Path(tempfile.mkdtemp(prefix=f".{game_version}-", dir=str(staging_gamedata)))
            try:
                _copy_version(gamedata_source / game_version, temporary)
                relative_expected = sorted(
                    (
                        {"path": item["path"][len(f"{GAMEDATA_PREFIX}{game_version}/"):], "size": item["size"], "sha256": item["sha256"]}
                        for item in version["files"]
                    ),
                    key=lambda item: item["path"],
                )
                if file_inventory(temporary) != relative_expected:
                    raise LegacyInputError(f"{temporary}: copied gamedata inventory differs from the pinned manifest")
                os.replace(temporary, target)
            except BaseException:
                shutil.rmtree(temporary, ignore_errors=True)
                raise
            added.append(
                {
                    "gameVersion": game_version,
                    "fileCount": len(version["files"]),
                    "inventorySha256": inventory_sha256(relative_expected),
                }
            )
    except BaseException:
        for record in added:
            shutil.rmtree(staging_gamedata / record["gameVersion"], ignore_errors=True)
        raise

    receipt = {
        "schema_version": LEGACY_INPUTS_RECEIPT_SCHEMA_VERSION,
        "manifest_sha256": sha256_bytes(raw),
        "archive_commit": manifest["archiveCommit"],
        "repository": manifest["repository"],
        "added": added,
        "skipped_existing": skipped,
        "input_inventory_sha256": inventory_sha256(file_inventory(staging_gamedata)),
    }
    receipt_path = Path(receipt_path).resolve()
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--archive-root", required=True)
    parser.add_argument("--staging", required=True)
    parser.add_argument("--receipt", required=True)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = stage_legacy_gamedata(
            manifest_path=args.manifest,
            archive_root=args.archive_root,
            staging_root=args.staging,
            receipt_path=args.receipt,
        )
    except (OSError, LegacyInputError, ReleaseWorkflowError) as exc:
        print(f"Legacy Pages input error: {exc}", file=sys.stderr)
        return 1
    print(canonical_json_bytes(receipt).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

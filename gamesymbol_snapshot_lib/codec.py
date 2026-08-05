import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import PurePosixPath, PureWindowsPath

import yaml

from analysis_output_contract import ANALYSIS_OUTPUT_CONTRACT_VERSION
from gamesymbol_snapshot_lib.errors import SnapshotSchemaError
from gamesymbol_snapshot_lib.paths import validate_snapshot_key
from trusted_yaml import load_yaml

LEGACY_SCHEMA_VERSION = 1
SCHEMA_2_VERSION = 2
SCHEMA_3_VERSION = 3
SCHEMA_4_VERSION = 4
SCHEMA_VERSION = 5
SCHEMA_1_KEYS = ("schema_version", "game_version", "config_sha256", "file_count", "files")
SCHEMA_2_KEYS = (
    "schema_version",
    "config_digest_version",
    "game_version",
    "config_sha256",
    "file_count",
    "files",
)
SCHEMA_3_KEYS = (
    "schema_version",
    "analysis_output_contract_version",
    "config_digest_version",
    "game_version",
    "config_sha256",
    "file_count",
    "files",
)
SCHEMA_4_KEYS = (
    "schema_version",
    "last_publish_time",
    "binaries",
    "analysis_output_contract_version",
    "config_digest_version",
    "game_version",
    "config_sha256",
    "file_count",
    "files",
)
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MD5_PATTERN = re.compile(r"^[0-9a-f]{32}$")
PUBLISH_TIME_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
BINARY_PLATFORMS = ("windows", "linux")
BINARY_METADATA_KEYS = ("path", "sha256", "md5", "crc32", "crc64", "size")
LEGACY_BINARY_METADATA_KEYS = ("path", "sha256", "md5")
CRC32_PATTERN = re.compile(r"^[0-9a-f]{8}$")
CRC64_PATTERN = re.compile(r"^[0-9a-f]{16}$")


class CanonicalDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


class _QuotedString(str):
    """A string whose YAML representation must remain explicitly quoted."""


def _represent_quoted_string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="'")


CanonicalDumper.add_representer(_QuotedString, _represent_quoted_string)


def _key_sort_key(key):
    return type(key).__name__, str(key)


def canonicalize(value):
    if isinstance(value, Mapping):
        return {key: canonicalize(value[key]) for key in sorted(value, key=_key_sort_key)}
    if isinstance(value, list):
        return [canonicalize(item) for item in value]
    return value


def _canonicalize_binaries(binaries: Mapping, schema_version: int) -> dict:
    canonical_binaries = canonicalize(binaries)
    if schema_version != SCHEMA_VERSION:
        return canonical_binaries
    for platforms in canonical_binaries.values():
        if not isinstance(platforms, dict):
            continue
        for metadata in platforms.values():
            if not isinstance(metadata, dict):
                continue
            for field in ("md5", "sha256", "crc32", "crc64"):
                value = metadata.get(field)
                if isinstance(value, str):
                    metadata[field] = _QuotedString(value)
    return canonical_binaries


def canonical_yaml_bytes(value) -> bytes:
    text = yaml.dump(
        canonicalize(value),
        Dumper=CanonicalDumper,
        allow_unicode=True,
        default_flow_style=False,
        explicit_end=False,
        explicit_start=False,
        indent=2,
        line_break="\n",
        sort_keys=False,
        width=1_000_000,
    )
    return text.rstrip("\r\n").encode("utf-8") + b"\n"


def snapshot_config_digest_version(document: Mapping) -> int:
    schema_version = document.get("schema_version")
    if schema_version == LEGACY_SCHEMA_VERSION:
        return 1
    if schema_version in {SCHEMA_2_VERSION, SCHEMA_3_VERSION, SCHEMA_4_VERSION, SCHEMA_VERSION}:
        version = document.get("config_digest_version")
        if not isinstance(version, int) or isinstance(version, bool) or version != 2:
            raise SnapshotSchemaError(
                f"unsupported snapshot config_digest_version: {version!r}",
                reason="unsupported_config_digest_version",
            )
        return version
    raise SnapshotSchemaError(
        f"unsupported snapshot schema_version: {schema_version!r}",
        reason="unsupported_snapshot_schema",
    )


def snapshot_analysis_output_contract_version(document: Mapping) -> int:
    schema_version = document.get("schema_version")
    if schema_version in {LEGACY_SCHEMA_VERSION, SCHEMA_2_VERSION}:
        return 1
    if schema_version in {SCHEMA_3_VERSION, SCHEMA_4_VERSION, SCHEMA_VERSION}:
        version = document.get("analysis_output_contract_version")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise SnapshotSchemaError(
                f"invalid snapshot analysis_output_contract_version: {version!r}",
                reason="invalid_analysis_output_contract_version",
            )
        return version
    raise SnapshotSchemaError(
        f"unsupported snapshot schema_version: {schema_version!r}",
        reason="unsupported_snapshot_schema",
    )


def build_snapshot_document(
    game_version: str,
    config_sha256: str,
    files: Mapping,
    *,
    schema_version: int = SCHEMA_VERSION,
    config_digest_version: int | None = None,
    analysis_output_contract_version: int | None = None,
    last_publish_time: str | None = None,
    binaries: Mapping | None = None,
) -> dict:
    ordered_files = {path: canonicalize(files[path]) for path in sorted(files)}
    if schema_version == LEGACY_SCHEMA_VERSION:
        if config_digest_version not in (None, 1):
            raise SnapshotSchemaError("schema 1 snapshots require config digest version 1")
        return {
            "schema_version": LEGACY_SCHEMA_VERSION,
            "game_version": str(game_version),
            "config_sha256": config_sha256,
            "file_count": len(ordered_files),
            "files": ordered_files,
        }
    if schema_version == SCHEMA_2_VERSION:
        if config_digest_version is None:
            config_digest_version = 2
        if config_digest_version != 2:
            raise SnapshotSchemaError(
                f"unsupported snapshot config_digest_version: {config_digest_version!r}",
                reason="unsupported_config_digest_version",
            )
        if analysis_output_contract_version not in (None, 1):
            raise SnapshotSchemaError("schema 2 snapshots imply analysis output contract version 1")
        return {
            "schema_version": SCHEMA_2_VERSION,
            "config_digest_version": config_digest_version,
            "game_version": str(game_version),
            "config_sha256": config_sha256,
            "file_count": len(ordered_files),
            "files": ordered_files,
        }
    if schema_version not in {SCHEMA_3_VERSION, SCHEMA_4_VERSION, SCHEMA_VERSION}:
        raise SnapshotSchemaError(
            f"unsupported snapshot schema_version: {schema_version!r}",
            reason="unsupported_snapshot_schema",
        )
    if config_digest_version is None:
        config_digest_version = 2
    if config_digest_version != 2:
        raise SnapshotSchemaError(
            f"unsupported snapshot config_digest_version: {config_digest_version!r}",
            reason="unsupported_config_digest_version",
        )
    if analysis_output_contract_version is None:
        analysis_output_contract_version = ANALYSIS_OUTPUT_CONTRACT_VERSION
    if (
        not isinstance(analysis_output_contract_version, int)
        or isinstance(analysis_output_contract_version, bool)
        or analysis_output_contract_version < 1
    ):
        raise SnapshotSchemaError(
            f"invalid snapshot analysis_output_contract_version: {analysis_output_contract_version!r}",
            reason="invalid_analysis_output_contract_version",
        )
    document = {
        "schema_version": schema_version,
        "analysis_output_contract_version": analysis_output_contract_version,
        "config_digest_version": config_digest_version,
        "game_version": str(game_version),
        "config_sha256": config_sha256,
        "file_count": len(ordered_files),
        "files": ordered_files,
    }
    if schema_version == SCHEMA_3_VERSION:
        return document
    if last_publish_time is None or binaries is None:
        raise SnapshotSchemaError("published snapshots require last_publish_time and binaries")
    return {
        "schema_version": schema_version,
        "last_publish_time": last_publish_time,
        "binaries": _canonicalize_binaries(binaries, schema_version),
        **{key: value for key, value in document.items() if key != "schema_version"},
    }


def canonical_snapshot_bytes(document: Mapping) -> bytes:
    schema_version = document.get("schema_version")
    digest_version = snapshot_config_digest_version(document)
    canonical = build_snapshot_document(
        str(document["game_version"]),
        document["config_sha256"],
        document["files"],
        schema_version=schema_version,
        config_digest_version=digest_version,
        analysis_output_contract_version=snapshot_analysis_output_contract_version(document),
        last_publish_time=document.get("last_publish_time"),
        binaries=document.get("binaries"),
    )
    return canonical_yaml_bytes(canonical)


def _validate_metadata(document: object, expected_game_version: str | None) -> dict:
    if not isinstance(document, dict):
        raise SnapshotSchemaError("snapshot top level must be a mapping")
    schema_version = document.get("schema_version")
    expected_keys = {
        LEGACY_SCHEMA_VERSION: SCHEMA_1_KEYS,
        SCHEMA_2_VERSION: SCHEMA_2_KEYS,
        SCHEMA_3_VERSION: SCHEMA_3_KEYS,
        SCHEMA_4_VERSION: SCHEMA_4_KEYS,
        SCHEMA_VERSION: SCHEMA_4_KEYS,
    }.get(schema_version)
    if expected_keys is None:
        raise SnapshotSchemaError(
            f"unsupported snapshot schema_version: {schema_version!r}",
            reason="unsupported_snapshot_schema",
        )
    if set(document) != set(expected_keys):
        raise SnapshotSchemaError(f"snapshot schema {schema_version} must contain exactly: {', '.join(expected_keys)}")
    snapshot_config_digest_version(document)
    snapshot_analysis_output_contract_version(document)
    game_version = document.get("game_version")
    if not isinstance(game_version, str):
        raise SnapshotSchemaError("snapshot game_version must be a string")
    if expected_game_version is not None and game_version != str(expected_game_version):
        raise SnapshotSchemaError(
            f"snapshot game_version {game_version!r} does not match {str(expected_game_version)!r}"
        )
    if not isinstance(document.get("config_sha256"), str) or not DIGEST_PATTERN.fullmatch(document["config_sha256"]):
        raise SnapshotSchemaError("snapshot config_sha256 is invalid")
    if not isinstance(document.get("files"), dict):
        raise SnapshotSchemaError("snapshot files must be a mapping")
    count = document.get("file_count")
    if not isinstance(count, int) or isinstance(count, bool) or count != len(document["files"]):
        raise SnapshotSchemaError("snapshot file_count does not match files")
    if schema_version in {SCHEMA_4_VERSION, SCHEMA_VERSION}:
        _validate_publish_metadata(document)
    return document


def _validate_binary_path(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise SnapshotSchemaError(f"{context} must be a non-empty string")
    if "\\" in value or PureWindowsPath(value).is_absolute():
        raise SnapshotSchemaError(f"{context} must be a relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or "//" in value or any(part in {"", ".", ".."} for part in path.parts):
        raise SnapshotSchemaError(f"{context} is unsafe: {value!r}")
    return path.as_posix()


def _validate_publish_metadata(document: dict) -> None:
    publish_time = document.get("last_publish_time")
    if not isinstance(publish_time, str) or not PUBLISH_TIME_PATTERN.fullmatch(publish_time):
        raise SnapshotSchemaError("snapshot last_publish_time must be UTC ISO 8601 with second precision and Z suffix")
    try:
        datetime.strptime(publish_time, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise SnapshotSchemaError("snapshot last_publish_time is invalid") from exc
    schema_version = document["schema_version"]
    metadata_keys = LEGACY_BINARY_METADATA_KEYS if schema_version == SCHEMA_4_VERSION else BINARY_METADATA_KEYS
    binaries = document.get("binaries")
    if not isinstance(binaries, dict):
        raise SnapshotSchemaError("snapshot binaries must be a mapping")
    module_spellings = {}
    for module, platforms in binaries.items():
        if not isinstance(module, str) or not module or module in {".", ".."} or "/" in module or "\\" in module:
            raise SnapshotSchemaError(f"invalid snapshot binary module: {module!r}")
        prior_module = module_spellings.setdefault(module.casefold(), module)
        if prior_module != module:
            raise SnapshotSchemaError(
                f"case-insensitive snapshot binary module collision: {prior_module!r} and {module!r}"
            )
        if not isinstance(platforms, dict) or not platforms:
            raise SnapshotSchemaError(f"snapshot binaries.{module} must be a non-empty mapping")
        if not set(platforms).issubset(BINARY_PLATFORMS):
            raise SnapshotSchemaError(f"snapshot binaries.{module} contains an unsupported platform")
        for platform, metadata in platforms.items():
            context = f"snapshot binaries.{module}.{platform}"
            if not isinstance(metadata, dict) or set(metadata) != set(metadata_keys):
                raise SnapshotSchemaError(f"{context} must contain exactly: {', '.join(metadata_keys)}")
            metadata["path"] = _validate_binary_path(metadata.get("path"), f"{context}.path")
            if not isinstance(metadata.get("sha256"), str) or not SHA256_PATTERN.fullmatch(metadata["sha256"]):
                raise SnapshotSchemaError(f"{context}.sha256 is invalid")
            if not isinstance(metadata.get("md5"), str) or not MD5_PATTERN.fullmatch(metadata["md5"]):
                raise SnapshotSchemaError(f"{context}.md5 is invalid")
            if schema_version == SCHEMA_VERSION:
                if not isinstance(metadata.get("crc32"), str) or not CRC32_PATTERN.fullmatch(metadata["crc32"]):
                    raise SnapshotSchemaError(f"{context}.crc32 is invalid")
                if not isinstance(metadata.get("crc64"), str) or not CRC64_PATTERN.fullmatch(metadata["crc64"]):
                    raise SnapshotSchemaError(f"{context}.crc64 is invalid")
                size = metadata.get("size")
                if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                    raise SnapshotSchemaError(f"{context}.size must be a non-negative integer")


def parse_snapshot_bytes(data: bytes, expected_game_version: str | None = None) -> dict:
    try:
        document = load_yaml(data)
    except yaml.YAMLError as exc:
        raise SnapshotSchemaError(f"unable to parse snapshot YAML: {exc}") from exc
    document = _validate_metadata(document, expected_game_version)
    normalized_files = {}
    case_spellings = {}
    for raw_path, payload in document["files"].items():
        path = validate_snapshot_key(raw_path)
        prior = case_spellings.setdefault(path.casefold(), path)
        if prior != path:
            raise SnapshotSchemaError(f"case-insensitive snapshot path collision: {prior} and {path}")
        if not isinstance(payload, dict):
            raise SnapshotSchemaError(f"snapshot payload must be a mapping: {path}")
        normalized_files[path] = payload
    document["files"] = normalized_files
    return document

"""Deterministic source-artifact selection projection for BinSync publication."""

from __future__ import annotations

import hashlib
import re
import struct
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

import yaml

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import canonical_json_bytes, normalized_relative_path, sha256_bytes

SOURCE_PROJECTION_SCHEMA_VERSION = 1
FUNCTION_CATEGORIES = frozenset({"func", "vfunc"})
GLOBAL_CATEGORIES = frozenset({"gv"})
PROJECTED_CATEGORIES = FUNCTION_CATEGORIES | GLOBAL_CATEGORIES
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ENTRY_FIELDS = {
    "artifact_path",
    "artifact_sha256",
    "category",
    "module",
    "platform",
    "repository_id",
    "source_rva",
    "symbol",
}


class BinSyncProjectionError(ValueError):
    """Raised when a source selection projection is malformed or ambiguous."""


def pe_first_section_rva(data: bytes) -> int:
    """Return the lowest PE section RVA used as declib's first-segment bias."""
    if data[:2] != b"MZ":
        raise BinSyncProjectionError("not a PE (missing MZ signature)")
    if len(data) < 0x40:
        raise BinSyncProjectionError("truncated DOS header")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\x00\x00":
        raise BinSyncProjectionError("invalid PE signature")
    section_count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    section_table = pe + 24 + optional_size
    if section_count == 0:
        raise BinSyncProjectionError("PE has no sections")
    first_rva = None
    for index in range(section_count):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            raise BinSyncProjectionError("truncated PE section table")
        rva = struct.unpack_from("<I", data, offset + 12)[0]
        if first_rva is None or rva < first_rva:
            first_rva = rva
    if first_rva is None:
        raise BinSyncProjectionError("PE has no sections")
    return first_rva


def first_segment_lift_bias(binary_path: Path) -> int:
    """Return the raw-RVA delta to declib's first-segment-relative key."""
    data = binary_path.read_bytes()
    if data[:4] == b"\x7fELF":
        return 0
    if data[:2] == b"MZ":
        return pe_first_section_rva(data)
    raise BinSyncProjectionError(f"unsupported binary format for lift bias: {binary_path}")


def _projection_digest(unsigned: Mapping[str, object]) -> str:
    payload = b"binsync-source-projection:v1\n" + canonical_json_bytes(unsigned)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _entry_sort_key(entry: Mapping[str, object]) -> tuple:
    return (
        entry["repository_id"],
        entry["module"],
        entry["platform"],
        entry["artifact_path"],
        entry["category"],
        entry["symbol"],
        entry["source_rva"],
    )


def _normalized_path(value: str) -> str:
    try:
        return normalized_relative_path(value)
    except ReleaseWorkflowError as exc:
        raise BinSyncProjectionError(str(exc)) from exc


def build_source_projection(
    *,
    game_version: str,
    config_payload: bytes,
    targets: Iterable[Mapping[str, str]],
    read_artifact: Callable[[str], bytes | None],
) -> dict:
    """Project configured func/vfunc/gv artifacts without binary/IDA lowering."""
    try:
        config = yaml.safe_load(config_payload.decode("utf-8")) or {}
    except (UnicodeError, yaml.YAMLError) as exc:
        raise BinSyncProjectionError("analysis config is not valid UTF-8 YAML") from exc
    modules = config.get("modules") if isinstance(config, dict) else None
    if not isinstance(modules, list):
        raise BinSyncProjectionError("analysis config modules must be a list")
    modules_by_name: dict[str, list[dict]] = {}
    for module in modules:
        name = module.get("name") if isinstance(module, dict) else None
        if not isinstance(name, str) or not name:
            raise BinSyncProjectionError("analysis config has an invalid module")
        modules_by_name.setdefault(name, []).append(module)

    normalized_targets: list[tuple[str, str, str]] = []
    seen_targets: set[tuple[str, str]] = set()
    for target in targets:
        module = target.get("module")
        platform = target.get("platform")
        repository_id = target.get("repository_id")
        if (
            not isinstance(module, str)
            or not module
            or "/" in module
            or "\\" in module
            or platform not in {"windows", "linux"}
            or not isinstance(repository_id, str)
            or not repository_id
        ):
            raise BinSyncProjectionError("BinSync projection target is invalid")
        key = (module, platform)
        if key in seen_targets:
            raise BinSyncProjectionError(f"duplicate BinSync projection target: {module}/{platform}")
        if module not in modules_by_name:
            raise BinSyncProjectionError(f"BinSync projection target has no configured module: {module}")
        seen_targets.add(key)
        normalized_targets.append((module, platform, repository_id))

    entries: list[dict] = []
    seen_entries: set[tuple] = set()
    for module_name, platform, repository_id in sorted(normalized_targets):
        symbols = []
        for module in modules_by_name[module_name]:
            declared = module.get("symbols") or []
            if not isinstance(declared, list):
                raise BinSyncProjectionError(f"configured symbols must be a list: {module_name}")
            symbols.extend(declared)
        for symbol in symbols:
            if not isinstance(symbol, dict):
                continue
            category = symbol.get("category")
            symbol_name = symbol.get("name")
            if (
                category not in PROJECTED_CATEGORIES
                or not isinstance(symbol_name, str)
                or not symbol_name
                or "/" in symbol_name
                or "\\" in symbol_name
            ):
                continue
            symbol_platform = symbol.get("platform")
            if symbol_platform and symbol_platform != platform:
                continue
            artifact_path = _normalized_path(
                f"bin_artifacts/{game_version}/{module_name}/{symbol_name}.{platform}.yaml"
            )
            payload = read_artifact(artifact_path)
            if payload is None:
                continue
            if not isinstance(payload, bytes):
                raise BinSyncProjectionError(f"artifact reader returned non-bytes payload: {artifact_path}")
            try:
                artifact = yaml.safe_load(payload.decode("utf-8")) or {}
            except (UnicodeError, yaml.YAMLError):
                continue
            rva_field = "func_rva" if category in FUNCTION_CATEGORIES else "gv_rva"
            raw_rva = artifact.get(rva_field) if isinstance(artifact, dict) else None
            try:
                source_rva = int(str(raw_rva), 0)
            except (TypeError, ValueError):
                continue
            if source_rva < 0:
                continue
            entry = {
                "artifact_path": artifact_path,
                "artifact_sha256": f"sha256:{sha256_bytes(payload)}",
                "category": category,
                "module": module_name,
                "platform": platform,
                "repository_id": repository_id,
                "source_rva": source_rva,
                "symbol": symbol_name,
            }
            entry_key = _entry_sort_key(entry)
            if entry_key not in seen_entries:
                seen_entries.add(entry_key)
                entries.append(entry)

    entries.sort(key=_entry_sort_key)
    unsigned = {"schema_version": SOURCE_PROJECTION_SCHEMA_VERSION, "entries": entries}
    return {**unsigned, "digest": _projection_digest(unsigned)}


def validate_source_projection(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != {"schema_version", "entries", "digest"}:
        raise BinSyncProjectionError("BinSync source projection has unexpected fields")
    if document.get("schema_version") != SOURCE_PROJECTION_SCHEMA_VERSION:
        raise BinSyncProjectionError("BinSync source projection schema is invalid")
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise BinSyncProjectionError("BinSync source projection entries must be a list")
    seen: set[tuple] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
            raise BinSyncProjectionError("BinSync source projection entry has unexpected fields")
        for field in ("artifact_path", "module", "repository_id", "symbol"):
            if not isinstance(entry[field], str) or not entry[field]:
                raise BinSyncProjectionError(f"BinSync source projection {field} is invalid")
        if entry["platform"] not in {"windows", "linux"} or entry["category"] not in PROJECTED_CATEGORIES:
            raise BinSyncProjectionError("BinSync source projection platform or category is invalid")
        if not isinstance(entry["source_rva"], int) or isinstance(entry["source_rva"], bool) or entry["source_rva"] < 0:
            raise BinSyncProjectionError("BinSync source projection RVA is invalid")
        if not isinstance(entry["artifact_sha256"], str) or not DIGEST_RE.fullmatch(entry["artifact_sha256"]):
            raise BinSyncProjectionError("BinSync source projection artifact digest is invalid")
        expected_path = f"bin_artifacts/{{game_version}}/{entry['module']}/{entry['symbol']}.{entry['platform']}.yaml"
        path = _normalized_path(entry["artifact_path"])
        path_parts = path.split("/")
        if (
            len(path_parts) != 4
            or path_parts[0] != "bin_artifacts"
            or path != expected_path.format(game_version=path_parts[1])
        ):
            raise BinSyncProjectionError("BinSync source projection artifact path is invalid")
        key = _entry_sort_key(entry)
        if key in seen:
            raise BinSyncProjectionError("BinSync source projection contains a duplicate entry")
        seen.add(key)
    if entries != sorted(entries, key=_entry_sort_key):
        raise BinSyncProjectionError("BinSync source projection entries are not canonical")
    unsigned = {"schema_version": document["schema_version"], "entries": entries}
    if document.get("digest") != _projection_digest(unsigned):
        raise BinSyncProjectionError("BinSync source projection digest mismatch")
    return document

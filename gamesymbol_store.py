import copy
import fnmatch
import hashlib
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

import yaml

from analysis_config import AnalysisConfigError, resolve_analysis_config
from gamesymbol_snapshot_lib.codec import (
    SCHEMA_VERSION,
    canonical_snapshot_bytes,
    canonical_yaml_bytes,
    parse_snapshot_bytes,
    snapshot_config_digest_version,
)
from gamesymbol_snapshot_lib.config import LATEST_CONFIG_DIGEST_VERSION, load_contract
from gamesymbol_snapshot_lib.errors import SnapshotConfigError, SnapshotMismatchError, SnapshotSchemaError
from gamesymbol_snapshot_lib.operations import validate_snapshot_contract
from gamesymbol_snapshot_lib.paths import canonical_key, is_reparse_point, iter_yaml_paths


class SymbolStoreError(Exception):
    """Base error for read-only symbol stores."""


class SnapshotFormatError(SymbolStoreError):
    """Snapshot bytes or schema are invalid."""


class SnapshotCanonicalError(SymbolStoreError):
    """Snapshot bytes do not use the canonical encoding."""


class SnapshotConfigMismatchError(SymbolStoreError):
    """Snapshot metadata or paths do not match the analysis contract."""


class SnapshotGameVersionMismatchError(SymbolStoreError):
    """Snapshot game version does not match the requested version."""


class InvalidSymbolPathError(SymbolStoreError):
    """A symbol query contains an unsafe module, filename, or pattern."""


class SymbolNotFoundError(SymbolStoreError):
    """A required symbol is absent from the store."""


class CandidateChangedError(SymbolStoreError):
    """Candidate bytes or file identity changed after candidate-ready."""


@dataclass(frozen=True)
class SymbolEntry:
    path: str
    module: str
    filename: str
    payload: Mapping[str, Any]


class SymbolStore(Protocol):
    @property
    def game_version(self) -> str: ...

    @property
    def schema_version(self) -> int: ...

    @property
    def config_digest_version(self) -> int: ...

    @property
    def config_sha256(self) -> str: ...

    @property
    def candidate_sha256(self) -> str: ...

    @property
    def file_count(self) -> int: ...

    @property
    def binaries(self) -> Mapping[str, Any]: ...

    def contains(self, module: str, filename: str) -> bool: ...

    def get(self, module: str, filename: str) -> Mapping[str, Any] | None: ...

    def require(self, module: str, filename: str) -> Mapping[str, Any]: ...

    def glob_module(self, module: str, filename_pattern: str) -> Sequence[SymbolEntry]: ...

    def iter_module(self, module: str) -> Sequence[SymbolEntry]: ...


def _validate_component(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise InvalidSymbolPathError(f"{label} must be a non-empty path component")
    if "/" in value or "\\" in value:
        raise InvalidSymbolPathError(f"{label} must not contain a path separator: {value!r}")
    return value


def _validate_filename(filename: str) -> str:
    filename = _validate_component(filename, "filename")
    if not filename.endswith(".yaml"):
        raise InvalidSymbolPathError(f"filename must end with .yaml: {filename!r}")
    return filename


def _validate_pattern(pattern: str) -> str:
    pattern = _validate_component(pattern, "filename pattern")
    if "**" in pattern or "[" in pattern or "]" in pattern:
        raise InvalidSymbolPathError(f"unsupported filename glob pattern: {pattern!r}")
    return pattern


def _split_store_path(path: str) -> tuple[str, str]:
    parts = PurePosixPath(path).parts
    if len(parts) != 2:
        raise SnapshotFormatError(f"symbol store path must be <module>/<filename>: {path!r}")
    return _validate_component(parts[0], "module"), _validate_filename(parts[1])


def _ensure_plain_file(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    if not absolute.is_file():
        raise SnapshotFormatError(f"snapshot is not a regular file: {path}")
    for candidate in (absolute, *absolute.parents):
        if candidate.exists() and is_reparse_point(candidate):
            raise SnapshotFormatError(f"snapshot path must not traverse a link/reparse point: {candidate}")
    return absolute


class _MemorySymbolStore:
    def __init__(
        self,
        game_version: str,
        *,
        schema_version: int,
        config_digest_version: int,
        config_sha256: str,
        source_sha256: str,
        files: Mapping[str, Mapping],
        binaries: Mapping[str, Any] | None = None,
    ):
        self._game_version = str(game_version)
        self._schema_version = schema_version
        self._config_digest_version = config_digest_version
        self._config_sha256 = config_sha256
        self._candidate_sha256 = source_sha256
        self._files = {path: copy.deepcopy(payload) for path, payload in files.items()}
        self._binaries = copy.deepcopy(binaries or {})
        self._modules: dict[str, list[str]] = {}
        for path in sorted(self._files):
            module, _filename = _split_store_path(path)
            self._modules.setdefault(module, []).append(path)

    @property
    def game_version(self) -> str:
        return self._game_version

    @property
    def schema_version(self) -> int:
        return self._schema_version

    @property
    def config_digest_version(self) -> int:
        return self._config_digest_version

    @property
    def config_sha256(self) -> str:
        return self._config_sha256

    @property
    def candidate_sha256(self) -> str:
        return self._candidate_sha256

    @property
    def file_count(self) -> int:
        return len(self._files)

    @property
    def binaries(self) -> Mapping[str, Any]:
        return copy.deepcopy(self._binaries)

    def contains(self, module: str, filename: str) -> bool:
        return self._key(module, filename) in self._files

    def get(self, module: str, filename: str) -> Mapping[str, Any] | None:
        payload = self._files.get(self._key(module, filename))
        return copy.deepcopy(payload) if payload is not None else None

    def require(self, module: str, filename: str) -> Mapping[str, Any]:
        payload = self.get(module, filename)
        if payload is None:
            raise SymbolNotFoundError(f"symbol not found: {self._key(module, filename)}")
        return payload

    def glob_module(self, module: str, filename_pattern: str) -> Sequence[SymbolEntry]:
        module = _validate_component(module, "module")
        pattern = _validate_pattern(filename_pattern)
        return tuple(
            self._entry(path)
            for path in self._modules.get(module, ())
            if fnmatch.fnmatchcase(path.split("/", 1)[1], pattern)
        )

    def iter_module(self, module: str) -> Sequence[SymbolEntry]:
        module = _validate_component(module, "module")
        return tuple(self._entry(path) for path in self._modules.get(module, ()))

    @staticmethod
    def _key(module: str, filename: str) -> str:
        return f"{_validate_component(module, 'module')}/{_validate_filename(filename)}"

    def _entry(self, path: str) -> SymbolEntry:
        module, filename = _split_store_path(path)
        return SymbolEntry(path, module, filename, copy.deepcopy(self._files[path]))


class SnapshotSymbolStore(_MemorySymbolStore):
    @classmethod
    def open(cls, snapshot_path, *, expected_game_version: str, config_path=None):
        path = _ensure_plain_file(Path(snapshot_path))
        try:
            raw = path.read_bytes()
            document = parse_snapshot_bytes(raw)
        except (OSError, UnicodeError, SnapshotSchemaError) as exc:
            raise SnapshotFormatError(f"unable to open snapshot {path}: {exc}") from exc
        if document["game_version"] != str(expected_game_version):
            raise SnapshotGameVersionMismatchError(
                f"snapshot game version {document['game_version']} does not match {expected_game_version}"
            )
        try:
            config_path = resolve_analysis_config(expected_game_version, config_path)
            digest_version = snapshot_config_digest_version(document)
            contract = load_contract(config_path, expected_game_version, "bin", digest_version)
            validate_snapshot_contract(document, contract)
        except (AnalysisConfigError, SnapshotConfigError, SnapshotMismatchError) as exc:
            raise SnapshotConfigMismatchError(str(exc)) from exc
        if raw != canonical_snapshot_bytes(document):
            raise SnapshotCanonicalError(f"snapshot is not canonical: {path}")
        digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        return cls(
            document["game_version"],
            schema_version=document["schema_version"],
            config_digest_version=digest_version,
            config_sha256=document["config_sha256"],
            source_sha256=digest,
            files=document["files"],
            binaries=document.get("binaries", {}),
        )


class DirectorySymbolStore(_MemorySymbolStore):
    """Eager migration/test backend; production workflows must use snapshots."""

    def __init__(
        self,
        bin_root,
        game_version: str,
        *,
        config_sha256: str | None = None,
        config_digest_version: int = LATEST_CONFIG_DIGEST_VERSION,
    ):
        game_root = Path(bin_root) / str(game_version)
        files = self._load_files(game_root)
        digest = f"sha256:{hashlib.sha256(canonical_yaml_bytes(files)).hexdigest()}"
        super().__init__(
            str(game_version),
            schema_version=SCHEMA_VERSION,
            config_digest_version=config_digest_version,
            config_sha256=config_sha256 or f"sha256:{'0' * 64}",
            source_sha256=digest,
            files=files,
        )

    @staticmethod
    def _load_files(game_root: Path) -> dict[str, Mapping]:
        files = {}
        for path in iter_yaml_paths(game_root):
            key = canonical_key(game_root, str(path))
            try:
                payload = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, yaml.YAMLError) as exc:
                raise SnapshotFormatError(f"unable to read directory symbol {path}: {exc}") from exc
            if not isinstance(payload, dict):
                raise SnapshotFormatError(f"directory symbol payload must be a mapping: {path}")
            files[key] = payload
        return files


def open_snapshot_store(*, snapshot_path, config_path, expected_game_version: str) -> SnapshotSymbolStore:
    return SnapshotSymbolStore.open(
        snapshot_path,
        expected_game_version=expected_game_version,
        config_path=config_path,
    )

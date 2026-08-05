from __future__ import annotations

import importlib.util
import inspect
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType, ModuleType
from typing import Any

from release_workflow_lib.hashing import (
    canonical_json_bytes,
    file_inventory,
    inventory_sha256,
    reject_reparse_points,
    sha256_bytes,
)

MODULE_DIRECTORY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
GAMEVER_RE = re.compile(r"\d+[a-z]?\Z")
ALLOWED_OUTPUT_SUFFIXES = {".json", ".jsonc", ".txt"}
RESERVED_MODULE_DIRECTORIES = {"completed", "cleanup-trash", "locks", "pr-index"}
SUPPORTED_GENERATOR_API_VERSIONS = {1, 2}


class GamedataContractError(ValueError):
    pass


def _freeze_context_value(value):
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_context_value(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_context_value(item) for item in value)
    return value


@dataclass(frozen=True)
class GeneratorContext:
    game_version: str
    binaries: Mapping[str, Any]

    def __post_init__(self):
        object.__setattr__(self, "game_version", str(self.game_version))
        object.__setattr__(self, "binaries", _freeze_context_value(self.binaries))


@dataclass(frozen=True)
class GeneratorModule:
    directory: str
    name: str
    api_version: int
    source_dir: Path
    module: ModuleType
    output_paths: tuple[str, ...]
    download_sources: tuple[tuple[str, str], ...]
    static_sources: tuple[tuple[str, str], ...]
    source_files: tuple[dict, ...]

    def record(self) -> dict:
        return {
            "directory": self.directory,
            "name": self.name,
            "api_version": self.api_version,
            "output_paths": list(self.output_paths),
            "download_sources": [list(item) for item in self.download_sources],
            "static_sources": [list(item) for item in self.static_sources],
            "source_files": list(self.source_files),
        }


def _normalized_output_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise GamedataContractError(f"invalid declared output path: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise GamedataContractError(f"declared output path is not contained: {value!r}")
    normalized = pure.as_posix()
    if pure.suffix.lower() not in ALLOWED_OUTPUT_SUFFIXES:
        raise GamedataContractError(f"declared output has a forbidden extension: {normalized}")
    return normalized


def _normalized_source_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise GamedataContractError(f"invalid static source path: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise GamedataContractError(f"static source path is not contained: {value!r}")
    return pure.as_posix()


def _load_module(directory: str, module_path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"gamedata_generator_{directory}", module_path)
    if spec is None or spec.loader is None:
        raise GamedataContractError(f"unable to load generator module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise GamedataContractError(f"failed to load generator {directory}: {exc}") from exc
    return module


def _module_contract(directory: str, source_dir: Path, module: ModuleType) -> GeneratorModule:
    if not MODULE_DIRECTORY_RE.fullmatch(directory):
        raise GamedataContractError(f"invalid generator directory name: {directory!r}")
    if GAMEVER_RE.fullmatch(directory) or directory in RESERVED_MODULE_DIRECTORIES:
        raise GamedataContractError(f"reserved generator directory name: {directory}")
    name = getattr(module, "MODULE_NAME", None)
    if not isinstance(name, str) or not name.strip():
        raise GamedataContractError(f"generator {directory} has no valid MODULE_NAME")
    api_version = getattr(module, "GENERATOR_API_VERSION", 1)
    if (
        isinstance(api_version, bool)
        or not isinstance(api_version, int)
        or api_version not in SUPPORTED_GENERATOR_API_VERSIONS
    ):
        raise GamedataContractError(f"generator {directory} has unsupported GENERATOR_API_VERSION: {api_version!r}")
    update = getattr(module, "update", None)
    if not callable(update):
        raise GamedataContractError(f"generator {directory} has no callable update")
    if api_version == 2:
        try:
            context_parameter = inspect.signature(update).parameters.get("context")
        except (TypeError, ValueError) as exc:
            raise GamedataContractError(f"generator {directory} has an unreadable update signature: {exc}") from exc
        if context_parameter is None or context_parameter.kind not in {
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        }:
            raise GamedataContractError(f"generator {directory} API v2 update must accept a context keyword argument")
    declared = getattr(module, "OUTPUT_PATHS", None)
    if not isinstance(declared, (tuple, list)) or not declared:
        raise GamedataContractError(f"generator {directory} must declare non-empty OUTPUT_PATHS")
    output_paths = tuple(_normalized_output_path(value) for value in declared)
    if len(set(output_paths)) != len(output_paths):
        raise GamedataContractError(f"generator {directory} declares duplicate output paths")

    downloads = getattr(module, "DOWNLOAD_SOURCES", ())
    if not isinstance(downloads, (tuple, list)):
        raise GamedataContractError(f"generator {directory} has invalid DOWNLOAD_SOURCES")
    normalized_downloads: list[tuple[str, str]] = []
    for item in downloads:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise GamedataContractError(f"generator {directory} has an invalid download declaration")
        url, target = item
        target = _normalized_output_path(target)
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            raise GamedataContractError(f"generator {directory} has an invalid download URL")
        if target not in output_paths:
            raise GamedataContractError(f"generator {directory} downloads undeclared output: {target}")
        normalized_downloads.append((url, target))
    if len({target for _url, target in normalized_downloads}) != len(normalized_downloads):
        raise GamedataContractError(f"generator {directory} downloads the same output more than once")

    static_sources = getattr(module, "STATIC_SOURCES", ())
    if not isinstance(static_sources, (tuple, list)):
        raise GamedataContractError(f"generator {directory} has invalid STATIC_SOURCES")
    normalized_static: list[tuple[str, str]] = []
    for item in static_sources:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise GamedataContractError(f"generator {directory} has an invalid static source declaration")
        source, target = item
        source = _normalized_source_path(source)
        target = _normalized_output_path(target)
        if target not in output_paths:
            raise GamedataContractError(f"generator {directory} copies an undeclared output: {target}")
        if not (source_dir / source).is_file():
            raise GamedataContractError(f"generator {directory} static source is missing: {source}")
        normalized_static.append((source, target))
    claimed_sources = {target for _url, target in normalized_downloads} | {
        target for _source, target in normalized_static
    }
    if len(claimed_sources) != len(normalized_downloads) + len(normalized_static):
        raise GamedataContractError(f"generator {directory} initializes an output more than once")

    reject_reparse_points(source_dir)
    source_files = tuple(
        sorted(
            (
                item
                for item in file_inventory(source_dir)
                if "__pycache__" not in PurePosixPath(item["path"]).parts and not item["path"].endswith(".pyc")
            ),
            key=lambda item: item["path"],
        )
    )
    return GeneratorModule(
        directory=directory,
        name=name.strip(),
        api_version=api_version,
        source_dir=source_dir,
        module=module,
        output_paths=output_paths,
        download_sources=tuple(normalized_downloads),
        static_sources=tuple(normalized_static),
        source_files=source_files,
    )


def discover_generator_modules(modules_dir: str | Path) -> list[GeneratorModule]:
    root = Path(modules_dir)
    if not root.is_dir():
        raise GamedataContractError(f"generator directory does not exist: {root}")
    reject_reparse_points(root)
    modules: list[GeneratorModule] = []
    claimed_outputs: set[str] = set()
    claimed_names: set[str] = set()
    for source_dir in sorted((path for path in root.iterdir() if path.is_dir()), key=lambda path: path.name):
        module_path = source_dir / "gamedata.py"
        if not module_path.is_file():
            continue
        module = _load_module(source_dir.name, module_path)
        if not getattr(module, "MODULE_ENABLED", True):
            continue
        contract = _module_contract(source_dir.name, source_dir, module)
        if contract.name in claimed_names:
            raise GamedataContractError(f"duplicate generator MODULE_NAME: {contract.name}")
        claimed_names.add(contract.name)
        full_outputs = {f"{contract.directory}/{path}" for path in contract.output_paths}
        duplicates = claimed_outputs & full_outputs
        if duplicates:
            raise GamedataContractError("duplicate generator outputs: " + ", ".join(sorted(duplicates)))
        claimed_outputs.update(full_outputs)
        modules.append(contract)
    if not modules:
        raise GamedataContractError(f"no enabled gamedata generators found below {root}")
    return modules


def generator_contract_sha256(modules: list[GeneratorModule]) -> str:
    records = [module.record() for module in modules]
    return sha256_bytes(canonical_json_bytes({"schema_version": 1, "modules": records}))


def expected_inventory_paths(modules: list[GeneratorModule], gamever: str) -> list[str]:
    return sorted(f"gamedata/{gamever}/{module.directory}/{path}" for module in modules for path in module.output_paths)


def prefixed_output_inventory(output_root: str | Path, gamever: str) -> list[dict]:
    prefix = f"gamedata/{gamever}/"
    inventory = [{**item, "path": prefix + item["path"]} for item in file_inventory(Path(output_root))]
    return sorted(inventory, key=lambda item: item["path"])


def canonicalize_output_text(output_root: str | Path) -> None:
    root = Path(output_root)
    for path in sorted(path for path in root.rglob("*") if path.is_file()):
        data = path.read_bytes()
        normalized = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if normalized != data:
            path.write_bytes(normalized)


def validate_output_tree(output_root: str | Path, gamever: str, modules: list[GeneratorModule]) -> list[dict]:
    root = Path(output_root)
    if not root.is_dir():
        raise GamedataContractError(f"versioned gamedata output is missing: {root}")
    reject_reparse_points(root)
    expected = sorted(f"{module.directory}/{path}" for module in modules for path in module.output_paths)
    actual_inventory = sorted(file_inventory(root), key=lambda item: item["path"])
    actual = [item["path"] for item in actual_inventory]
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("undeclared=" + ",".join(extra))
        raise GamedataContractError("versioned gamedata tree violates OUTPUT_PATHS: " + "; ".join(details))
    return prefixed_output_inventory(root, gamever)


def gamedata_manifest_sha256(inventory: list[dict]) -> str:
    return inventory_sha256(inventory)

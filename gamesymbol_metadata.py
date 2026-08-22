#!/usr/bin/env python3
"""Generate the immutable alias-metadata companion for a game-symbol snapshot.

``gamesymbols/<GAMEVER>.metadata.yaml`` carries the subset of
``configs/<GAMEVER>.yaml`` that the pages app consumes at build time: the
per-symbol alias map (``modules[].symbols[].alias``). It is emitted alongside
the snapshot during release and freezes with it.

Field-scope rule: a config field is included IFF it is present in the config,
absent from the snapshot, and consumed by ``pages/``. Today that is only the
alias map. See ``memory/gamesymbol_metadata.md``.
"""

from __future__ import annotations

import argparse
import os
import tempfile
import traceback
from pathlib import Path

import yaml

from analysis_config import AnalysisConfigError, resolve_analysis_config
from trusted_yaml import load_yaml_file

REPO_ROOT = Path(__file__).resolve().parent


class MetadataGenerationError(RuntimeError):
    """Metadata could not be generated safely."""


def normalize_alias_list(value) -> list[str]:
    """Normalize a config ``alias`` value (string or list) into a string list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item]
    return []


def extract_alias_subset(raw: dict) -> dict:
    """Return the config alias subset consumed by the pages app.

    Mirrors ``pages/gameSymbolsPlugin.ts`` ``buildConfigAliasIndex``: read only
    ``modules[].name``, ``modules[].symbols[].name``, and
    ``modules[].symbols[].alias``. Symbols without aliases and modules without
    any aliased symbol are omitted.
    """
    modules = []
    for module in raw.get("modules", []):
        if not isinstance(module, dict):
            continue
        module_name = module.get("name")
        if not isinstance(module_name, str) or not module_name:
            continue
        symbols = []
        for symbol in module.get("symbols", []) or []:
            if not isinstance(symbol, dict):
                continue
            name = symbol.get("name")
            if not isinstance(name, str) or not name:
                continue
            alias = normalize_alias_list(symbol.get("alias"))
            if not alias:
                continue
            symbols.append({"name": name, "alias": alias})
        if symbols:
            modules.append({"name": module_name, "symbols": symbols})
    return {"modules": modules}


def _atomic_write_text(path: Path, data: str) -> None:
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise MetadataGenerationError(f"unable to write metadata {path}: {exc}") from exc
    finally:
        if temporary and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


def generate_metadata(gamever: str, config_path, output_path: Path) -> Path:
    raw = load_yaml_file(Path(config_path))
    if not isinstance(raw, dict):
        raise MetadataGenerationError(f"config root must be a mapping: {config_path}")
    subset = extract_alias_subset(raw)
    data = yaml.safe_dump(subset, sort_keys=False, allow_unicode=True)
    destination = Path(output_path)
    _atomic_write_text(destination, data)
    return destination


def default_metadata_path(gamever: str, *, repo_root: Path | None = None) -> Path:
    root = Path(repo_root or REPO_ROOT)
    return root / "gamesymbols" / f"{gamever}.metadata.yaml"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Generate game-symbol snapshot alias metadata")
    parser.add_argument("-debug", action="store_true", help="Print tracebacks on errors")
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate")
    generate.add_argument("-gamever", required=True)
    generate.add_argument(
        "-configyaml",
        default=None,
        help="Analysis config path; defaults to configs/<GAMEVER>.yaml",
    )
    generate.add_argument(
        "-output",
        default=None,
        help="Output metadata path; defaults to gamesymbols/<GAMEVER>.metadata.yaml",
    )
    return parser.parse_args(argv)


def _run(args) -> None:
    if args.command != "generate":
        raise MetadataGenerationError(f"unknown command: {args.command}")
    config_path = resolve_analysis_config(args.gamever, args.configyaml)
    output = Path(args.output) if args.output else default_metadata_path(args.gamever)
    destination = generate_metadata(args.gamever, config_path, output)
    print(f"Metadata written: {destination}")


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        _run(args)
    except (AnalysisConfigError, MetadataGenerationError) as exc:
        print(f"Error: {exc}")
        if args.debug:
            traceback.print_exc()
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

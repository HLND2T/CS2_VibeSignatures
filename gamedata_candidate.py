from __future__ import annotations

import argparse
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from gamedata_contract import (
    GamedataContractError,
    discover_generator_modules,
    gamedata_manifest_sha256,
    generator_contract_sha256,
    require_source_owned_generator_inputs,
    validate_output_tree,
)
from gamesymbol_store import SymbolStoreError
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    load_json_object,
    normalized_relative_path,
    sha256_file,
    write_canonical_json,
)
from update_gamedata import generate_gamedata

SESSION_FIELDS = {
    "schema_version",
    "gamever",
    "build_id",
    "candidate_root",
    "snapshot_path",
    "analysis_config_path",
    "modules_dir",
    "gamedata_path",
    "candidate_sha256",
    "analysis_config_sha256",
    "generator_contract_sha256",
    "gamedata_manifest_sha256",
    "files",
}
GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$", re.ASCII)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class GamedataCandidateError(ValueError):
    pass


@dataclass(frozen=True)
class GamedataInventoryModification:
    path: str
    expected_size: int
    expected_sha256: str
    candidate_size: int
    candidate_sha256: str


@dataclass(frozen=True)
class GamedataInventoryDiff:
    added: tuple[str, ...]
    missing: tuple[str, ...]
    modified: tuple[GamedataInventoryModification, ...]

    @property
    def matches(self) -> bool:
        return not (self.added or self.missing or self.modified)


def _validated_gamever(gamever: str) -> str:
    if not isinstance(gamever, str) or not GAMEVER_RE.fullmatch(gamever):
        raise GamedataCandidateError(f"invalid GAMEVER: {gamever!r}")
    return gamever


def _canonical_inventory_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise GamedataCandidateError(f"path must be a non-empty POSIX relative path: {value!r}")
    if value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/")):
        raise GamedataCandidateError(f"unsafe relative path: {value!r}")
    try:
        normalized = normalized_relative_path(value)
    except ReleaseWorkflowError as exc:
        raise GamedataCandidateError(str(exc)) from exc
    if normalized != value:
        raise GamedataCandidateError(f"inventory path is not canonical: {value!r}")
    return normalized


def _absolute_file(path: str | Path, label: str) -> Path:
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise GamedataCandidateError(f"{label} is missing: {resolved}")
    return resolved


def _load_session(session_path: str | Path) -> dict:
    session = load_json_object(Path(session_path))
    if set(session) != SESSION_FIELDS or session.get("schema_version") != 1:
        raise GamedataCandidateError("gamedata candidate session has unexpected fields or schema")
    return session


def build_candidate(
    *,
    gamever: str,
    build_id: str,
    snapshot: str | Path,
    analysis_config: str | Path,
    modules_dir: str | Path,
    candidate_root: str | Path,
    session_path: str | Path,
    platforms: list[str] | None = None,
    debug: bool = False,
) -> dict:
    gamever = _validated_gamever(gamever)
    snapshot = _absolute_file(snapshot, "symbol candidate")
    analysis_config = _absolute_file(analysis_config, "analysis config")
    modules_dir = Path(modules_dir).resolve()
    candidate_root = Path(candidate_root).resolve()
    version_root = candidate_root / "gamedata" / gamever
    if version_root.exists():
        raise GamedataCandidateError(f"gamedata candidate output already exists: {version_root}")
    version_root.parent.mkdir(parents=True, exist_ok=True)
    modules = discover_generator_modules(modules_dir)
    require_source_owned_generator_inputs(modules)
    result = generate_gamedata(
        gamever=gamever,
        snapshot_path=snapshot,
        config_path=analysis_config,
        modules_dir=modules_dir,
        output_root=version_root,
        platforms=platforms or ["windows", "linux"],
        debug=debug,
        download_latest=False,
        strict=True,
    )
    session = {
        "schema_version": 1,
        "gamever": gamever,
        "build_id": build_id,
        "candidate_root": str(candidate_root),
        "snapshot_path": str(snapshot),
        "analysis_config_path": str(analysis_config),
        "modules_dir": str(modules_dir),
        "gamedata_path": f"gamedata/{gamever}",
        "candidate_sha256": sha256_file(snapshot),
        "analysis_config_sha256": sha256_file(analysis_config),
        "generator_contract_sha256": result["generator_contract_sha256"],
        "gamedata_manifest_sha256": result["gamedata_manifest_sha256"],
        "files": result["files"],
    }
    write_canonical_json(Path(session_path), session)
    return session


def guard_candidate(session_path: str | Path) -> dict:
    session = _load_session(session_path)
    gamever = _validated_gamever(session["gamever"])
    if session["gamedata_path"] != f"gamedata/{gamever}":
        raise GamedataCandidateError("gamedata candidate session has an invalid versioned output path")
    snapshot = _absolute_file(session["snapshot_path"], "symbol candidate")
    analysis_config = _absolute_file(session["analysis_config_path"], "analysis config")
    if sha256_file(snapshot) != session["candidate_sha256"]:
        raise GamedataCandidateError("symbol candidate changed after gamedata generation")
    if sha256_file(analysis_config) != session["analysis_config_sha256"]:
        raise GamedataCandidateError("analysis config changed after gamedata generation")
    modules = discover_generator_modules(session["modules_dir"])
    if generator_contract_sha256(modules) != session["generator_contract_sha256"]:
        raise GamedataCandidateError("generator contract changed after gamedata generation")
    version_root = Path(session["candidate_root"]) / session["gamedata_path"]
    files = validate_output_tree(version_root, gamever, modules)
    if files != session["files"] or gamedata_manifest_sha256(files) != session["gamedata_manifest_sha256"]:
        raise GamedataCandidateError("gamedata candidate bytes changed after generation")
    return session


def _inventory_by_path(
    files: Sequence[Mapping[str, object]], *, gamever: str, label: str
) -> dict[str, dict[str, object]]:
    if not isinstance(files, Sequence) or isinstance(files, (str, bytes)) or not files:
        raise GamedataCandidateError(f"{label} is missing or empty")
    prefix = f"gamedata/{gamever}/"
    by_path: dict[str, dict[str, object]] = {}
    casefolded_paths: dict[str, str] = {}
    for item in files:
        if not isinstance(item, Mapping) or set(item) != {"path", "size", "sha256"}:
            raise GamedataCandidateError(f"{label} has an invalid inventory record")
        path = _canonical_inventory_path(item["path"])
        if not path.startswith(prefix):
            raise GamedataCandidateError(f"{label} path is outside exact root {prefix}: {path}")
        size = item["size"]
        digest = item["sha256"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise GamedataCandidateError(f"{label} has an invalid size for {path}")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise GamedataCandidateError(f"{label} has an invalid SHA-256 for {path}")
        if path in by_path:
            raise GamedataCandidateError(f"{label} has a duplicate path: {path}")
        folded = path.casefold()
        if folded in casefolded_paths:
            raise GamedataCandidateError(
                f"{label} has a case-insensitive path collision: {casefolded_paths[folded]} and {path}"
            )
        record = {"path": path, "size": size, "sha256": digest}
        by_path[path] = record
        casefolded_paths[folded] = path
    return by_path


def compare_gamedata_inventory(
    *, session: Mapping[str, object], expected_files: Sequence[Mapping[str, object]]
) -> GamedataInventoryDiff:
    gamever = _validated_gamever(session.get("gamever"))
    candidate_files = session.get("files")
    candidate = _inventory_by_path(candidate_files, gamever=gamever, label="candidate gamedata inventory")
    expected = _inventory_by_path(expected_files, gamever=gamever, label="expected gamedata inventory")
    candidate_paths = set(candidate)
    expected_paths = set(expected)
    modified = []
    for path in sorted(candidate_paths & expected_paths):
        candidate_record = candidate[path]
        expected_record = expected[path]
        if (candidate_record["size"], candidate_record["sha256"]) != (
            expected_record["size"],
            expected_record["sha256"],
        ):
            modified.append(
                GamedataInventoryModification(
                    path=path,
                    expected_size=expected_record["size"],
                    expected_sha256=expected_record["sha256"],
                    candidate_size=candidate_record["size"],
                    candidate_sha256=candidate_record["sha256"],
                )
            )
    return GamedataInventoryDiff(
        added=tuple(sorted(expected_paths - candidate_paths)),
        missing=tuple(sorted(candidate_paths - expected_paths)),
        modified=tuple(modified),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and guard release-local immutable gamedata candidates")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("-gamever", required=True)
    build.add_argument("-build-id", required=True)
    build.add_argument("-snapshot", required=True)
    build.add_argument("-configyaml", required=True)
    build.add_argument("-modulesdir", default="gamedata-generators")
    build.add_argument("-candidate-root", required=True)
    build.add_argument("-session", required=True)
    build.add_argument("-platform", default="windows,linux")
    build.add_argument("-debug", action="store_true")
    guard = commands.add_parser("guard")
    guard.add_argument("-session", required=True)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build":
            build_candidate(
                gamever=args.gamever,
                build_id=args.build_id,
                snapshot=args.snapshot,
                analysis_config=args.configyaml,
                modules_dir=args.modulesdir,
                candidate_root=args.candidate_root,
                session_path=args.session,
                platforms=[item.strip() for item in args.platform.split(",") if item.strip()],
                debug=args.debug,
            )
        elif args.command == "guard":
            guard_candidate(args.session)
    except (
        GamedataCandidateError,
        GamedataContractError,
        ReleaseWorkflowError,
        SymbolStoreError,
        OSError,
        ValueError,
    ) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

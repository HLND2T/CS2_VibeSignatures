import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from gamesymbol_snapshot_lib.candidate_session import (
    VALIDATION_STEPS,
    CandidateContractError,
    absolute_path,
    atomic_json_write,
    ensure_real_path,
    file_identity,
    initial_manifest,
    load_manifest,
    update_session,
)
from gamesymbol_snapshot_lib.codec import (
    canonical_snapshot_bytes,
    parse_snapshot_bytes,
    snapshot_analysis_output_contract_version,
    snapshot_config_digest_version,
)
from gamesymbol_snapshot_lib.diff import format_snapshot_mismatch
from gamesymbol_snapshot_lib.errors import SnapshotMismatchError, SnapshotSchemaError
from gamesymbol_snapshot_lib.operations import pack_snapshot
from gamesymbol_snapshot_lib.paths import is_reparse_point
from gamesymbol_store import CandidateChangedError, SnapshotSymbolStore


class CandidatePublicationError(Exception):
    """Candidate publication failed without replacing the destination."""


@dataclass(frozen=True)
class CandidateInfo:
    path: str
    candidate_sha256: str
    game_version: str
    snapshot_schema_version: int
    config_digest_version: int
    config_sha256: str
    file_count: int


@dataclass(frozen=True)
class SnapshotDiff:
    actual_sha256: str
    expected_sha256: str
    equal: bool


@dataclass(frozen=True)
class PublishedInfo:
    path: str
    candidate_sha256: str
    byte_count: int


def _validate_staging_paths(output_path, session_path) -> tuple[Path, Path]:
    output = absolute_path(output_path)
    session = absolute_path(session_path)
    tracked_root = absolute_path(Path.cwd() / "gamesymbols")
    if output == tracked_root or tracked_root in output.parents:
        raise CandidateContractError("candidate output must not use the tracked gamesymbols namespace")
    if output.parent != session.parent:
        raise CandidateContractError("candidate and session manifest must share one staging directory")
    if output.exists() or session.exists():
        raise CandidateContractError("candidate output and session manifest must be new paths")
    output.parent.mkdir(parents=True, exist_ok=True)
    ensure_real_path(output)
    ensure_real_path(session)
    return output, session


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _candidate_info(path: Path) -> CandidateInfo:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CandidateContractError(f"unable to read candidate {path}: {exc}") from exc
    try:
        document = parse_snapshot_bytes(raw)
    except SnapshotSchemaError as exc:
        raise CandidateContractError(f"candidate snapshot is invalid: {exc}") from exc
    if canonical_snapshot_bytes(document) != raw:
        raise CandidateContractError(f"candidate snapshot is not canonical: {path}")
    return CandidateInfo(
        str(path),
        _sha256(raw),
        document["game_version"],
        document["schema_version"],
        snapshot_config_digest_version(document),
        document["config_sha256"],
        document["file_count"],
    )


def build_candidate_snapshot(
    *, game_version, bin_root, config_path, output_path, session_path, last_publish_time: str | None = None
) -> CandidateInfo:
    output, session = _validate_staging_paths(output_path, session_path)
    try:
        pack_snapshot(
            game_version,
            bin_root,
            config_path,
            output,
            last_publish_time=last_publish_time,
            binary_metadata_source_path=Path("gamesymbols") / f"{game_version}.yaml",
        )
        store = SnapshotSymbolStore.open(
            output,
            expected_game_version=str(game_version),
            config_path=config_path,
        )
        info = _candidate_info(output)
        if store.candidate_sha256 != info.candidate_sha256:
            raise CandidateChangedError("candidate hash changed during reopen validation")
        atomic_json_write(session, initial_manifest(info, output))
        return info
    except Exception:
        if output.exists() and not session.exists():
            output.unlink()
        raise


def guard_candidate(*, candidate_path, session_path) -> CandidateInfo:
    candidate = absolute_path(candidate_path)
    ensure_real_path(candidate, require_file=True)
    _session, manifest = load_manifest(session_path)
    if manifest.get("candidate_path") != str(candidate):
        raise CandidateChangedError("candidate path does not match the session manifest")
    try:
        info = _candidate_info(candidate)
    except CandidateContractError as exc:
        raise CandidateChangedError(str(exc)) from exc
    expected_fields = (
        "candidate_sha256",
        "game_version",
        "snapshot_schema_version",
        "config_digest_version",
        "config_sha256",
        "file_count",
    )
    for field in expected_fields:
        if manifest.get(field) != getattr(info, field):
            raise CandidateChangedError(f"candidate {field} changed after candidate-ready")
    if manifest.get("file_identity") != file_identity(candidate):
        raise CandidateChangedError("candidate file identity changed after candidate-ready")
    return info


def compare_snapshots(
    *, actual_path, expected_path, config_path, expected_game_version, session_path=None
) -> SnapshotDiff:
    if session_path is not None:
        guard_candidate(candidate_path=actual_path, session_path=session_path)
    actual = SnapshotSymbolStore.open(
        actual_path,
        expected_game_version=str(expected_game_version),
        config_path=config_path,
    )
    expected = SnapshotSymbolStore.open(
        expected_path,
        expected_game_version=str(expected_game_version),
        config_path=config_path,
    )
    if actual.candidate_sha256 != expected.candidate_sha256:
        try:
            actual_document = parse_snapshot_bytes(Path(actual_path).read_bytes())
            expected_document = parse_snapshot_bytes(Path(expected_path).read_bytes())
        except OSError as exc:
            raise CandidateContractError(f"unable to read snapshots for comparison: {exc}") from exc
        comparable_actual = dict(actual_document)
        comparable_expected = dict(expected_document)
        comparable_actual.pop("last_publish_time", None)
        comparable_expected.pop("last_publish_time", None)
        if comparable_actual == comparable_expected:
            if session_path is not None:
                guard_candidate(candidate_path=actual_path, session_path=session_path)
                session, manifest = load_manifest(session_path)
                manifest["completed_steps"]["expected_compare"] = True
                update_session(session, manifest, state="expected_matched")
            return SnapshotDiff(actual.candidate_sha256, expected.candidate_sha256, True)
        raise SnapshotMismatchError(format_snapshot_mismatch(comparable_expected, comparable_actual))
    if session_path is not None:
        guard_candidate(candidate_path=actual_path, session_path=session_path)
        session, manifest = load_manifest(session_path)
        manifest["completed_steps"]["expected_compare"] = True
        update_session(session, manifest, state="expected_matched")
    return SnapshotDiff(actual.candidate_sha256, expected.candidate_sha256, True)


def complete_candidate_step(*, candidate_path, session_path, step: str) -> CandidateInfo:
    if step not in VALIDATION_STEPS:
        raise CandidateContractError(f"unsupported candidate validation step: {step}")
    info = guard_candidate(candidate_path=candidate_path, session_path=session_path)
    session, manifest = load_manifest(session_path)
    completed = manifest["completed_steps"]
    if step == "cpp_tests" and not completed.get("gamedata"):
        raise CandidateContractError("cpp_tests cannot complete before gamedata")
    completed[step] = True
    state = "validated" if all(completed.get(item) for item in VALIDATION_STEPS) else "gamedata_passed"
    update_session(session, manifest, state=state)
    return info


def _validate_destination(destination: Path, game_version: str) -> None:
    tracked_root = absolute_path(Path.cwd() / "gamesymbols")
    if destination.parent != tracked_root or destination.name != f"{game_version}.yaml":
        raise CandidateContractError(f"published snapshot must be gamesymbols/{game_version}.yaml")
    destination.parent.mkdir(parents=True, exist_ok=True)
    ensure_real_path(destination)
    if destination.exists() and is_reparse_point(destination):
        raise CandidateContractError(f"published snapshot destination must not be a link: {destination}")
    if destination.exists() and not destination.is_file():
        raise CandidateContractError(f"published snapshot destination is not a regular file: {destination}")


def _atomic_publish(destination: Path, raw: bytes, digest: str) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=f".{destination.name}.", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        if _sha256(temporary.read_bytes()) != digest:
            raise CandidatePublicationError("destination temporary copy hash mismatch")
        os.replace(temporary, destination)
    except OSError as exc:
        raise CandidatePublicationError(f"unable to publish candidate: {exc}") from exc
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def publish_candidate(*, candidate_path, session_path, destination) -> PublishedInfo:
    info = guard_candidate(candidate_path=candidate_path, session_path=session_path)
    session, manifest = load_manifest(session_path)
    if manifest.get("state") != "validated":
        raise CandidateContractError("candidate session must be validated before publication")
    target = absolute_path(destination)
    _validate_destination(target, info.game_version)
    try:
        raw = Path(info.path).read_bytes()
    except OSError as exc:
        raise CandidatePublicationError(f"unable to read candidate for publication: {exc}") from exc
    _atomic_publish(target, raw, info.candidate_sha256)
    try:
        published_digest = _sha256(target.read_bytes())
    except OSError as exc:
        raise CandidatePublicationError(f"unable to verify published snapshot: {exc}") from exc
    if published_digest != info.candidate_sha256:
        raise CandidatePublicationError("published snapshot hash does not match candidate")
    update_session(session, manifest, state="published")
    return PublishedInfo(str(target), info.candidate_sha256, len(raw))

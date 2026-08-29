import hashlib
import json
import os
import random
import stat
import subprocess
import time
import uuid
from pathlib import Path, PurePosixPath

from release_workflow_lib.errors import ReleaseWorkflowError

HEX_SHA256_LENGTH = 64
READ_CHUNK_SIZE = 1024 * 1024
REGULAR_GIT_MODES = {"100644", "100755"}
WINDOWS_ERROR_ACCESS_DENIED = 5
WINDOWS_ERROR_SHARING_VIOLATION = 32
WINDOWS_REPLACE_RETRY_ERRORS = {WINDOWS_ERROR_ACCESS_DENIED, WINDOWS_ERROR_SHARING_VIOLATION}
WINDOWS_REPLACE_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6)
WINDOWS_REPLACE_RETRY_JITTER_RATIO = 0.25


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(READ_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path_matches_payload(path: Path, payload: bytes) -> bool:
    try:
        return path.read_bytes() == payload
    except OSError:
        return False


def _replace_with_windows_retry(source: Path, target: Path, payload: bytes) -> None:
    attempts = 0
    while True:
        attempts += 1
        try:
            os.replace(source, target)
            return
        except OSError as exc:
            if _path_matches_payload(target, payload):
                return
            winerror = getattr(exc, "winerror", None)
            retry_index = attempts - 1
            if winerror not in WINDOWS_REPLACE_RETRY_ERRORS:
                raise
            if retry_index >= len(WINDOWS_REPLACE_RETRY_DELAYS):
                raise OSError(
                    f"atomic replace failed after {attempts} attempts with WinError {winerror}: "
                    f"{source} -> {target}: {exc}"
                ) from exc
            delay = WINDOWS_REPLACE_RETRY_DELAYS[retry_index]
            jitter = random.uniform(0.0, delay * WINDOWS_REPLACE_RETRY_JITTER_RATIO)
            time.sleep(delay + jitter)


def write_canonical_json(path: Path, value: object) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(value)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(payload)
        _replace_with_windows_retry(temporary, path, payload)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    else:
        temporary.unlink(missing_ok=True)


def load_json_object(path: Path) -> dict:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseWorkflowError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseWorkflowError(f"unable to read JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseWorkflowError(f"JSON top level must be an object: {path}")
    return value


def normalized_relative_path(value: str) -> str:
    if not value or "\\" in value:
        raise ReleaseWorkflowError(f"path must be a non-empty POSIX relative path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ReleaseWorkflowError(f"unsafe relative path: {value!r}")
    return path.as_posix()


def contained_path(root: Path, *parts: str) -> Path:
    root = Path(os.path.abspath(root))
    target = Path(os.path.abspath(root.joinpath(*parts)))
    resolved_root = root.resolve(strict=False)
    resolved_target = target.resolve(strict=False)
    try:
        resolved_target.relative_to(resolved_root)
    except ValueError as exc:
        raise ReleaseWorkflowError(f"path escapes root {root}: {target}") from exc
    return target


def _is_reparse_point(path: Path) -> bool:
    info = path.lstat()
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def reject_reparse_points(root: Path) -> None:
    root = Path(root)
    if not root.exists():
        raise ReleaseWorkflowError(f"path does not exist: {root}")
    candidates = [root, *root.rglob("*")]
    for path in candidates:
        try:
            if _is_reparse_point(path):
                raise ReleaseWorkflowError(f"reparse points are not allowed: {path}")
        except OSError as exc:
            raise ReleaseWorkflowError(f"unable to inspect path {path}: {exc}") from exc


def reject_reparse_components(root: Path, target: Path) -> None:
    root = Path(os.path.abspath(root))
    target = Path(os.path.abspath(target))
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise ReleaseWorkflowError(f"path escapes root {root}: {target}") from exc
    current = root
    candidates = [root]
    for part in relative.parts:
        current /= part
        candidates.append(current)
    for path in candidates:
        if path.exists() and _is_reparse_point(path):
            raise ReleaseWorkflowError(f"reparse path component is not allowed: {path}")


def file_inventory(root: Path) -> list[dict]:
    root = Path(root)
    reject_reparse_points(root)
    inventory = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = normalized_relative_path(path.relative_to(root).as_posix())
        inventory.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    return inventory


def inventory_sha256(inventory: list[dict]) -> str:
    return sha256_bytes(canonical_json_bytes({"files": inventory}))


def verify_inventory(root: Path, expected: list[dict]) -> str:
    actual = file_inventory(root)
    if actual != expected:
        raise ReleaseWorkflowError(f"file inventory mismatch under {root}")
    return inventory_sha256(actual)


def _git_bytes(repo_root: Path, arguments: list[str]) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise ReleaseWorkflowError(detail or f"git {' '.join(arguments)} failed")
    return result.stdout


def _git_index_inventory(repo_root: Path, pathspecs: list[str]) -> list[dict]:
    raw_entries = _git_bytes(repo_root, ["ls-files", "--stage", "-z", "--", *pathspecs])
    inventory = []
    seen = set()
    for record in raw_entries.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split()
        relative = normalized_relative_path(os.fsdecode(raw_path).replace("\\", "/"))
        if stage != "0" or mode not in REGULAR_GIT_MODES or relative in seen:
            raise ReleaseWorkflowError(f"tracked output has an unsupported Git index entry: {relative}")
        blob = _git_bytes(repo_root, ["cat-file", "blob", object_id])
        inventory.append({"path": relative, "size": len(blob), "sha256": sha256_bytes(blob)})
        seen.add(relative)
    return sorted(inventory, key=lambda item: item["path"])


def tracked_output_inventory(repo_root: Path, gamever: str) -> list[dict]:
    repo_root = Path(repo_root)
    snapshot = f"gamesymbols/{gamever}.yaml"
    metadata = f"gamesymbols/{gamever}.metadata.yaml"
    gamedata = f"gamedata/{gamever}"
    inventory = _git_index_inventory(repo_root, [snapshot, metadata, gamedata])
    paths = {item["path"] for item in inventory}
    if snapshot not in paths:
        raise ReleaseWorkflowError(f"required tracked output is missing from the Git index: {snapshot}")
    if metadata not in paths:
        raise ReleaseWorkflowError(f"required tracked output is missing from the Git index: {metadata}")
    if not any(path.startswith(gamedata + "/") for path in paths):
        raise ReleaseWorkflowError(f"required tracked output is missing from the Git index: {gamedata}")
    return inventory


def allowed_output_path(path: str, gamever: str) -> bool:
    path = normalized_relative_path(path)
    return path in {
        f"gamesymbols/{gamever}.yaml",
        f"gamesymbols/{gamever}.metadata.yaml",
        f"release-manifests/{gamever}.json",
    } or path.startswith(f"gamedata/{gamever}/")


def validate_output_paths(paths: list[str], gamever: str) -> None:
    rejected = [path for path in paths if not allowed_output_path(path, gamever)]
    if rejected:
        raise ReleaseWorkflowError("generated-output PR contains disallowed paths: " + ", ".join(sorted(rejected)))
    required = {f"release-manifests/{gamever}.json"}
    if not required.issubset(paths):
        raise ReleaseWorkflowError(f"generated-output PR must change release-manifests/{gamever}.json")

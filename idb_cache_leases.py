"""Persistent single-generation selections; callers hold the GAMEVER lock."""

from __future__ import annotations

import re
import stat
import sys
import time
import uuid
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path

from release_workflow_lib.binary_cache import require_gamever, version_lock
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    contained_path,
    load_json_object,
    reject_reparse_components,
    sha256_bytes,
    sha256_file,
    write_canonical_json,
)


CACHE_NAMESPACE = "idb-cache-v2"
GENERATION_PATTERN = re.compile(r"^[0-9a-f]{64}-[0-9]+-[0-9]+$")
LEASE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RUN_PATTERN = re.compile(r"^[1-9][0-9]*$")
LEASE_SCHEMA_VERSION = 1
# Cover a full workflow, including queued jobs; expired producers are bounded.
LEASE_LIFETIME_SECONDS = 36 * 24 * 60 * 60
CLOCK_SKEW_SECONDS = 60 * 60
LOCK_TIMEOUT_SECONDS = 10 * 60
LOCK_POLL_SECONDS = 0.1


@dataclass(frozen=True)
class LeaseOwner:
    repository: str
    run_id: str
    run_attempt: str

    def document(self) -> dict:
        if not isinstance(self.repository, str) or not REPOSITORY_PATTERN.fullmatch(self.repository):
            raise ReleaseWorkflowError("invalid IDB lease repository")
        for value in (self.run_id, self.run_attempt):
            if not isinstance(value, str) or not RUN_PATTERN.fullmatch(value):
                raise ReleaseWorkflowError("invalid IDB lease run ID/attempt")
        return {"repository": self.repository, "run_id": self.run_id, "run_attempt": self.run_attempt}


def cache_root(persisted_root: Path, gamever: str) -> Path:
    return contained_path(persisted_root, CACHE_NAMESPACE, require_gamever(gamever))


@contextmanager
def cache_lock(persisted_root: Path, gamever: str, *, timeout: float = LOCK_TIMEOUT_SECONDS):
    """Serialize selection/pin, prune, and the entire verify/copy/release operation."""
    lock_path = contained_path(persisted_root, CACHE_NAMESPACE, ".locks", f"{require_gamever(gamever)}.lock")
    reject_reparse_components(persisted_root, lock_path)
    deadline = time.monotonic() + timeout
    with ExitStack() as stack:
        while True:
            try:
                stack.enter_context(version_lock(lock_path))
                break
            except ReleaseWorkflowError as exc:
                if time.monotonic() >= deadline:
                    raise ReleaseWorkflowError(f"timed out acquiring IDB cache lock: {lock_path}") from exc
                time.sleep(LOCK_POLL_SECONDS)
        yield


def lease_path(persisted_root: Path, gamever: str, lease_id: str) -> Path:
    if not isinstance(lease_id, str) or not LEASE_ID_PATTERN.fullmatch(lease_id):
        raise ReleaseWorkflowError("invalid IDB lease ID")
    path = cache_root(persisted_root, gamever) / "leases" / f"{lease_id}.json"
    reject_reparse_components(persisted_root, path)
    return path


def _validate(payload: dict, *, gamever: str, lease_id: str) -> None:
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != LEASE_SCHEMA_VERSION
        or payload.get("gamever") != gamever
        or payload.get("lease_id") != lease_id
        or payload.get("state") not in ("active", "released")
    ):
        raise ReleaseWorkflowError("invalid IDB lease metadata")
    owner = payload.get("owner")
    if not isinstance(owner, dict) or set(owner) != {"repository", "run_id", "run_attempt"}:
        raise ReleaseWorkflowError("invalid IDB lease owner")
    LeaseOwner(**owner).document()
    for key, pattern in (
        ("generation", GENERATION_PATTERN),
        ("cache_key", SHA256_PATTERN),
        ("manifest_sha256", SHA256_PATTERN),
    ):
        if not isinstance(payload.get(key), str) or not pattern.fullmatch(payload[key]):
            raise ReleaseWorkflowError(f"invalid IDB lease {key}")
    if not payload["generation"].startswith(payload["cache_key"] + "-"):
        raise ReleaseWorkflowError("IDB lease generation/cache key mismatch")
    created, expires = payload.get("created_at"), payload.get("expires_at")
    if type(created) is not int or type(expires) is not int or created < 0:
        raise ReleaseWorkflowError("invalid IDB lease timestamps")
    if expires - created != LEASE_LIFETIME_SECONDS:
        raise ReleaseWorkflowError("invalid IDB lease lifetime")


def create_lease(
    *,
    persisted_root: Path,
    gamever: str,
    generation: str,
    cache_key: str,
    manifest_sha256: str,
    owner: LeaseOwner,
) -> dict:
    lease_id = uuid.uuid4().hex
    path = lease_path(persisted_root, gamever, lease_id)
    created = int(time.time())
    payload = {
        "schema_version": LEASE_SCHEMA_VERSION,
        "lease_id": lease_id,
        "state": "active",
        "gamever": gamever,
        "generation": generation,
        "cache_key": cache_key,
        "manifest_sha256": manifest_sha256,
        "owner": owner.document(),
        "created_at": created,
        "expires_at": created + LEASE_LIFETIME_SECONDS,
    }
    _validate(payload, gamever=gamever, lease_id=lease_id)
    if path.exists():
        raise ReleaseWorkflowError("IDB lease ID collision")
    write_canonical_json(path, payload)
    return {"lease_id": lease_id, "lease_sha256": sha256_bytes(canonical_json_bytes(payload))}


def require_lease(
    *,
    persisted_root: Path,
    gamever: str,
    generation: str,
    cache_key: str,
    lease_id: str,
    lease_sha256: str,
    owner: LeaseOwner,
) -> dict:
    path = lease_path(persisted_root, gamever, lease_id)
    payload = load_json_object(path)
    _validate(payload, gamever=gamever, lease_id=lease_id)
    if payload["state"] != "active":
        raise ReleaseWorkflowError("IDB lease has been released; rerun the producer workflow")
    now = time.time()
    if now >= payload["expires_at"] or payload["created_at"] > now + CLOCK_SKEW_SECONDS:
        raise ReleaseWorkflowError("IDB lease expired or clock differs; rerun the producer workflow")
    if payload["owner"] != owner.document():
        raise ReleaseWorkflowError("IDB lease repository/run/attempt mismatch; rerun the producer workflow")
    if payload["generation"] != generation or payload["cache_key"] != cache_key:
        raise ReleaseWorkflowError("IDB lease selection mismatch")
    if not isinstance(lease_sha256, str) or not SHA256_PATTERN.fullmatch(lease_sha256):
        raise ReleaseWorkflowError("invalid IDB lease SHA-256")
    if sha256_file(path) != lease_sha256:
        raise ReleaseWorkflowError("IDB lease SHA-256 mismatch")
    return payload


def release_lease(*, persisted_root: Path, gamever: str, payload: dict) -> None:
    path = lease_path(persisted_root, gamever, payload["lease_id"])
    write_canonical_json(path, {**payload, "state": "released"})


def protected_generations(*, persisted_root: Path, gamever: str, now: float) -> set[str]:
    root = cache_root(persisted_root, gamever) / "leases"
    reject_reparse_components(persisted_root, root)
    try:
        root_mode = root.stat().st_mode
    except FileNotFoundError:
        return set()
    if not stat.S_ISDIR(root_mode):
        raise ReleaseWorkflowError("IDB lease root is not a directory")
    protected = set()
    expired = []
    # Validate every lease before allowing any destructive cleanup. Corruption fails closed.
    # iterdir propagates enumeration errors; glob can silently hide unreadable leases.
    for path in sorted(root.iterdir()):
        if path.suffix != ".json":
            continue
        lease_id = path.stem
        path = lease_path(persisted_root, gamever, lease_id)
        payload = load_json_object(path)
        _validate(payload, gamever=gamever, lease_id=lease_id)
        if payload["created_at"] > now + CLOCK_SKEW_SECONDS:
            raise ReleaseWorkflowError("IDB lease creation time is in the future")
        if now >= payload["expires_at"] + CLOCK_SKEW_SECONDS:
            expired.append(path)
        elif payload["state"] == "active":
            protected.add(payload["generation"])
    for path in expired:
        path.unlink()
        print(f"Expired IDB lease removed: {gamever}/{path.stem}", file=sys.stderr)
    return protected

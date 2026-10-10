#!/usr/bin/env python3
"""S3 transport layout for the existing verified, filesystem-based CI caches."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import uuid
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import idb_cache
import idb_cache_leases as leases
from release_workflow_lib.binary_cache import (
    configured_binary_paths,
    load_source_binary_lock,
    require_gamever,
    validate_binary_cache_tree,
    verify_source_binary_root,
)
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.filesystem import remove_tree
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    normalized_relative_path,
    reject_reparse_components,
    sha256_bytes,
    sha256_file,
)


STAGING = ".ci-cache"
STORE = f"{STAGING}/store"
TRANSPORT_VERSION = "cs2vibe-s3-v1"


def parse_endpoint(value: str) -> dict[str, str]:
    """MinIO expects a hostname and a separate numeric port, not a URL."""
    if not value or any(character.isspace() for character in value):
        raise ValueError("S3_ENDPOINT_URL must be an absolute HTTP(S) URL without whitespace")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or parsed.netloc.endswith(":")
    ):
        raise ValueError("S3_ENDPOINT_URL must contain only an HTTP(S) origin")
    port = parsed.port
    if port == 0:
        raise ValueError("S3 endpoint port must be between 1 and 65535")
    host = parsed.hostname if parsed.netloc.startswith("[") else parsed.netloc.split(":")[0]
    if not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
        raise ValueError("S3 endpoint hostname is invalid")
    return {
        "endpoint": host,
        "port": str(port if port is not None else (80 if parsed.scheme == "http" else 443)),
        "insecure": str(parsed.scheme == "http").lower(),
    }


def namespace(repository: str, platform: str) -> str:
    if not leases.REPOSITORY_PATTERN.fullmatch(repository) or any(
        part in (".", "..") for part in repository.split("/")
    ):
        raise ValueError("Invalid cache repository")
    if platform not in ("Windows", "Linux", "macOS"):
        raise ValueError("Invalid runner platform")
    # tespkg uses Node path.join for object names. Separators inside a key would be
    # normalized on Windows while listObjects uses the unmodified input key.
    repository_id = sha256_bytes(repository.lower().encode("utf-8"))
    return f"{TRANSPORT_VERSION}-{repository_id}-{platform.lower()}"


def depot_files(gamever: str, document: dict) -> list[tuple[str, dict]]:
    result = []
    for platforms in document["binaries"].values():
        for expected in platforms.values():
            relative = normalized_relative_path(expected["path"])
            result.append((f"cs2_depot/{require_gamever(gamever)}/{relative}", expected))
    return sorted(result, key=lambda item: item[0])


def cache_layout(repo_root: Path, gamever: str, repository: str, platform: str) -> dict:
    gamever = require_gamever(gamever)
    prefix = namespace(repository, platform)
    lock = load_source_binary_lock(repo_root, gamever)
    targets = sorted(configured_binary_paths(repo_root, gamever))
    accepted_identity = sha256_bytes(canonical_json_bytes({"lock": lock.sha256, "targets": targets}))
    files = depot_files(gamever, lock.document)
    depot_identity = sha256_bytes(
        canonical_json_bytes(
            {
                "download": lock.document["download"],
                "paths": [path for path, _ in files],
                "targets": targets,
            }
        )
    )
    return {
        "prefix": prefix,
        "persisted-root": STORE,
        "binary-lock-sha256": lock.sha256,
        "accepted-key": f"{prefix}-accepted-{gamever}-{accepted_identity}",
        "accepted-path": f"{STORE}/bin/{gamever}",
        "depot-key": f"{prefix}-depot-{gamever}-{depot_identity}",
        "depot-path": "\n".join(path for path, _ in files),
    }


def prepare_staging(repo_root: Path) -> None:
    root = repo_root.resolve()
    staging = root / STAGING
    # Reject links before resolving/deleting; only this job's disposable transport tree is cleared.
    reject_reparse_components(root, staging)
    if staging.exists():
        remove_tree(staging)
    (root / STORE).mkdir(parents=True)
    for name in ("bin", "cs2_depot"):
        target = root / name
        reject_reparse_components(root, target)
        target.mkdir(exist_ok=True)


def selection_layout(
    gamever: str, repository: str, platform: str, generation: str, lease_id: str, run_id: str, run_attempt: str
) -> dict:
    gamever = require_gamever(gamever)
    prefix = namespace(repository, platform)
    leases.LeaseOwner(repository, run_id, run_attempt).document()
    if not leases.GENERATION_PATTERN.fullmatch(generation) or not leases.LEASE_ID_PATTERN.fullmatch(lease_id):
        raise ValueError("Invalid IDB generation or lease selection")
    return {
        "generation-key": f"{prefix}-idb-{gamever}-{generation}",
        "generation-path": f"{STORE}/{leases.CACHE_NAMESPACE}/{gamever}/generations/{generation}",
        "lease-key": f"{prefix}-lease-{gamever}-{run_id}-{run_attempt}-{lease_id}",
        "lease-path": f"{STORE}/{leases.CACHE_NAMESPACE}/{gamever}/leases/{lease_id}.json",
    }


def depot_ready(repo_root: Path, gamever: str) -> bool:
    lock = load_source_binary_lock(repo_root, gamever)
    files = depot_files(gamever, lock.document)
    if not files or not all((repo_root / path).is_file() for path, _ in files):
        return False  # Accepted-bin hits need not download the depot at all.
    for relative, expected in files:
        path = repo_root / relative
        reject_reparse_components(repo_root, path)
        if path.stat().st_size != expected["size"] or sha256_file(path) != expected["sha256"]:
            raise ValueError("Depot binary differs from the source lock")
    return True


def verify_restored(repo_root: Path, gamever: str, *, accepted_hit: bool, depot_hit: bool) -> None:
    if accepted_hit:
        binary_root = repo_root / STORE / "bin" / require_gamever(gamever)
        validate_binary_cache_tree(binary_root, configured_binary_paths(repo_root, gamever), allow_excluded=False)
        verify_source_binary_root(
            repo_root=repo_root, gamever=gamever, binary_root=binary_root, label="S3 accepted binaries"
        )
    if depot_hit and not depot_ready(repo_root, gamever):
        raise ValueError("Restored S3 depot cache is incomplete")
    if depot_hit and not accepted_hit:
        # Materialize verified depot files before init_gamebin: otherwise its
        # release/Steam fallback would run despite having all binaries in S3.
        lock = load_source_binary_lock(repo_root, gamever)
        accepted_root = repo_root / STORE / "bin" / require_gamever(gamever)
        reject_reparse_components(repo_root, accepted_root)
        if accepted_root.exists():
            remove_tree(accepted_root)
        for module, platforms in lock.document["binaries"].items():
            for expected in platforms.values():
                relative = normalized_relative_path(expected["path"])
                source = repo_root / "cs2_depot" / gamever / relative
                destination = accepted_root / module / PurePosixPath(relative).name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)


def write_outputs(values: dict, path: str | None) -> None:
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            text = str(value).lower() if isinstance(value, bool) else str(value)
            delimiter = uuid.uuid4().hex
            handle.write(f"{key}<<{delimiter}\n{text}\n{delimiter}\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("endpoint", "prepare", "identity", "selection", "depot-ready", "verify-restored")
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--gamever", default=os.environ.get("GAMEVER", ""))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--platform", default=os.environ.get("RUNNER_OS", ""))
    parser.add_argument("--ida-version")
    parser.add_argument("--generation", default=os.environ.get("IDB_CACHE_GENERATION", ""))
    parser.add_argument("--lease-id", default=os.environ.get("IDB_CACHE_LEASE_ID", ""))
    parser.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT"))
    args = parser.parse_args(argv)
    try:
        if args.command == "endpoint":
            for name in ("S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"):
                if not os.environ.get(name, "").strip():
                    raise ValueError(f"{name} is not configured")
            result = parse_endpoint(os.environ.get("S3_ENDPOINT_URL", ""))
        elif args.command == "prepare":
            result = cache_layout(args.repo_root, args.gamever, args.repository, args.platform)
            prepare_staging(args.repo_root)
        elif args.command == "identity":
            result = idb_cache.cache_identity(
                repo_root=args.repo_root, gamever=args.gamever, ida_version=args.ida_version
            )
            prefix = namespace(args.repository, args.platform)
            result = {
                "cache-key": result["cache_key"],
                "restore-prefix": f"{prefix}-idb-{args.gamever}-{result['cache_key']}-",
                "generation-path": f"{STORE}/{leases.CACHE_NAMESPACE}/{args.gamever}/generations",
            }
        elif args.command == "selection":
            result = selection_layout(
                args.gamever,
                args.repository,
                args.platform,
                args.generation,
                args.lease_id,
                os.environ.get("GITHUB_RUN_ID", ""),
                os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            )
        elif args.command == "verify-restored":
            verify_restored(
                args.repo_root,
                args.gamever,
                accepted_hit=os.environ.get("CACHE_ACCEPTED_HIT") == "true",
                depot_hit=os.environ.get("CACHE_DEPOT_HIT") == "true",
            )
            result = {"verified": True}
        else:
            result = {"ready": depot_ready(args.repo_root, args.gamever)}
        write_outputs(result, args.github_output)
    except (ValueError, OSError, ReleaseWorkflowError, idb_cache.IdbCacheError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    # Endpoint is a secret-derived setting; do not echo it to logs.
    if args.command != "endpoint":
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

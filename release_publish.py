#!/usr/bin/env python3
"""Publish an immutable GitHub Release after hosted and BinSync verification."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from binsync_candidate import _remote_heads
from release_bundle import ReleaseBundleError, verify_release_bundle
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import canonical_json_bytes, load_json_object, sha256_file

TOKEN_ENVIRONMENT_VARIABLE = "GH_TOKEN"
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ReleasePublishError(Exception):
    """Raised when immutable GitHub Release publication cannot proceed."""


def _gh(arguments: list[str], *, allowed=(0,)) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(["gh", *arguments], capture_output=True, text=True, check=False)
    except OSError as exc:
        raise ReleasePublishError(f"unable to run GitHub CLI: {exc}") from exc
    if result.returncode not in allowed:
        detail = (result.stderr or result.stdout).strip()
        raise ReleasePublishError(detail or f"gh {' '.join(arguments)} failed with exit {result.returncode}")
    return result


def _gh_json(arguments: list[str], *, allow_404: bool = False) -> dict | None:
    result = _gh(arguments, allowed=(0, 1) if allow_404 else (0,))
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        if allow_404 and re.search(r"\bHTTP\s+404\b", detail, re.IGNORECASE):
            return None
        raise ReleasePublishError(detail or f"gh {' '.join(arguments)} failed")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReleasePublishError("GitHub CLI returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ReleasePublishError("GitHub CLI returned a non-object response")
    return value


def _tag_target(repository: str, tag: str) -> str | None:
    value = _gh_json(["api", f"repos/{repository}/git/ref/tags/{tag}"], allow_404=True)
    if value is None:
        return None
    target = value.get("object")
    if not isinstance(target, dict) or target.get("type") != "commit" or not isinstance(target.get("sha"), str):
        raise ReleasePublishError(f"Release tag is not a direct commit ref: {tag}")
    return target["sha"].lower()


def _create_tag(repository: str, tag: str, source_sha: str) -> None:
    _gh(
        [
            "api",
            "--method",
            "POST",
            f"repos/{repository}/git/refs",
            "-f",
            f"ref=refs/tags/{tag}",
            "-f",
            f"sha={source_sha}",
        ]
    )


def _release_state(repository: str, tag: str) -> dict | None:
    return _gh_json(["api", f"repos/{repository}/releases/tags/{tag}"], allow_404=True)


def _create_draft_release(repository: str, tag: str, source_sha: str, title: str, notes: str) -> None:
    _gh(
        [
            "api",
            "--method",
            "POST",
            f"repos/{repository}/releases",
            "-f",
            f"tag_name={tag}",
            "-f",
            f"target_commitish={source_sha}",
            "-f",
            f"name={title}",
            "-f",
            f"body={notes}",
            "-F",
            "draft=true",
            "-F",
            "prerelease=false",
        ]
    )


def _upload_asset(repository: str, tag: str, path: Path) -> None:
    _gh(["release", "upload", tag, str(path), "--repo", repository])


def _download_asset(repository: str, tag: str, name: str, destination: Path) -> Path:
    _gh(["release", "download", tag, "--repo", repository, "--pattern", name, "--dir", str(destination)])
    path = destination / name
    if not path.is_file():
        raise ReleasePublishError(f"GitHub CLI did not download exact Release asset: {name}")
    return path


def _publish_release(repository: str, release_id: int) -> None:
    _gh(
        [
            "api",
            "--method",
            "PATCH",
            f"repos/{repository}/releases/{release_id}",
            "-F",
            "draft=false",
        ]
    )


def _notes(manifest: dict) -> str:
    return (
        f"Source-owned CS2 release `{manifest['release_version']}`.\n\n"
        f"- Source SHA: `{manifest['source_sha']}`\n"
        f"- GAMEVER: `{manifest['game_version']}`\n"
        f"- Build ID: `{manifest['build_id']}`\n"
        f"- Artifact inventory: `{manifest['artifact_inventory_sha256']}`\n"
        f"- BinSync target state: `{manifest['binsync']['target_state_digest']}`\n"
    )


def _expected_assets(bundle_root: Path, manifest_path: Path, manifest: dict) -> list[dict]:
    records = list(manifest["public_assets"])
    checksums_path = bundle_root / f"SHA256SUMS-{manifest['release_version']}.txt"
    records.extend(
        [
            {
                "path": manifest_path.name,
                "name": manifest_path.name,
                "size": manifest_path.stat().st_size,
                "sha256": sha256_file(manifest_path),
            },
            {
                "path": checksums_path.name,
                "name": checksums_path.name,
                "size": checksums_path.stat().st_size,
                "sha256": sha256_file(checksums_path),
            },
        ]
    )
    names = [item["name"] for item in records]
    if len(names) != len(set(names)):
        raise ReleasePublishError("Release asset names collide")
    for item in records:
        path = bundle_root / PurePosixPath(item["path"])
        if path.name != item["name"] or path.stat().st_size != item["size"] or sha256_file(path) != item["sha256"]:
            raise ReleasePublishError(f"Release asset input mismatch: {item['path']}")
    return records


def _verify_binsync_targets(manifest: dict) -> None:
    for repository in manifest["binsync"]["repositories"]:
        remote = f"https://github.com/{repository['owner']}/{repository['name']}"
        heads = _remote_heads(remote)
        mismatches = [item["ref"] for item in repository["refs"] if heads.get(item["ref"]) != item["commit"]]
        if mismatches:
            raise ReleasePublishError(
                f"BinSync remote target state is incomplete for {repository['repository_id']}: {', '.join(mismatches)}"
            )


def _validate_release_identity(release: dict, *, tag: str, source_sha: str, title: str, notes: str) -> None:
    if (
        release.get("tag_name") != tag
        or str(release.get("target_commitish", "")).lower() != source_sha
        or release.get("name") != title
        or release.get("body") != notes
        or release.get("prerelease") is not False
        or not isinstance(release.get("id"), int)
        or isinstance(release.get("id"), bool)
    ):
        raise ReleasePublishError("existing GitHub Release identity differs from the verified bundle")


def _verify_remote_assets(repository: str, tag: str, release: dict, expected: list[dict]) -> dict[str, dict]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ReleasePublishError("GitHub Release assets response is invalid")
    by_name = {}
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str) or asset["name"] in by_name:
            raise ReleasePublishError("GitHub Release has invalid or duplicate asset names")
        by_name[asset["name"]] = asset
    expected_names = {item["name"] for item in expected}
    unexpected = set(by_name) - expected_names
    if unexpected:
        raise ReleasePublishError(
            "GitHub Release contains unexpected immutable assets: " + ", ".join(sorted(unexpected))
        )
    expected_by_name = {item["name"]: item for item in expected}
    with tempfile.TemporaryDirectory(prefix="verify-release-assets-") as temporary:
        download_root = Path(temporary)
        for name, asset in by_name.items():
            expected_item = expected_by_name[name]
            if asset.get("size") != expected_item["size"]:
                raise ReleasePublishError(f"GitHub Release asset size mismatch: {name}")
            downloaded = _download_asset(repository, tag, name, download_root)
            if sha256_file(downloaded) != expected_item["sha256"]:
                raise ReleasePublishError(f"GitHub Release asset digest mismatch: {name}")
    return by_name


def publish_release(
    *,
    bundle_root: str | Path,
    repo_root: str | Path,
    expected_source_sha: str | None = None,
    expected_game_version: str | None = None,
    expected_release_version: str | None = None,
    expected_build_id: str | None = None,
    expected_actions_artifact_name: str | None = None,
    expected_binsync_candidate_digest: str | None = None,
) -> dict:
    """Create/recover one draft and publish only exact immutable Release bytes."""
    token = os.environ.get(TOKEN_ENVIRONMENT_VARIABLE, "")
    if not token or token != token.strip() or "\r" in token or "\n" in token:
        raise ReleasePublishError(f"{TOKEN_ENVIRONMENT_VARIABLE} is required")
    bundle_root = Path(bundle_root).resolve()
    try:
        verified = verify_release_bundle(
            bundle_root=bundle_root,
            repo_root=repo_root,
            expected_source_sha=expected_source_sha,
            expected_game_version=expected_game_version,
            expected_release_version=expected_release_version,
            expected_build_id=expected_build_id,
            expected_actions_artifact_name=expected_actions_artifact_name,
            expected_binsync_candidate_digest=expected_binsync_candidate_digest,
        )
        manifest_path = next(bundle_root.glob("release-manifest-*.json"))
        manifest = load_json_object(manifest_path)
    except (ReleaseBundleError, ReleaseWorkflowError, StopIteration) as exc:
        raise ReleasePublishError(str(exc)) from exc
    repository = manifest["repository"]
    tag = manifest["release_version"]
    source_sha = manifest["source_sha"]
    if not VERSION_RE.fullmatch(tag):
        raise ReleasePublishError("Release version is unsafe for a tag or asset name")
    title = f"gamedata-{tag}"
    notes = _notes(manifest)
    expected_assets = _expected_assets(bundle_root, manifest_path, manifest)
    _verify_binsync_targets(manifest)

    current_tag = _tag_target(repository, tag)
    if current_tag is None:
        _create_tag(repository, tag, source_sha)
        current_tag = _tag_target(repository, tag)
    if current_tag != source_sha:
        raise ReleasePublishError(f"Release tag {tag} does not point directly to immutable source {source_sha}")

    release = _release_state(repository, tag)
    if release is None:
        _create_draft_release(repository, tag, source_sha, title, notes)
        release = _release_state(repository, tag)
    if release is None:
        raise ReleasePublishError("draft GitHub Release was not created")
    _validate_release_identity(release, tag=tag, source_sha=source_sha, title=title, notes=notes)
    assets = _verify_remote_assets(repository, tag, release, expected_assets)
    if release.get("draft") is False:
        if set(assets) != {item["name"] for item in expected_assets}:
            raise ReleasePublishError("published GitHub Release is incomplete and immutable")
        return {**verified, "status": "already-published", "tag": tag, "release_id": release["id"]}
    if release.get("draft") is not True:
        raise ReleasePublishError("GitHub Release draft state is invalid")

    for item in expected_assets:
        if item["name"] not in assets:
            _upload_asset(repository, tag, bundle_root / PurePosixPath(item["path"]))
    release = _release_state(repository, tag)
    if release is None:
        raise ReleasePublishError("draft GitHub Release disappeared during publication")
    _validate_release_identity(release, tag=tag, source_sha=source_sha, title=title, notes=notes)
    assets = _verify_remote_assets(repository, tag, release, expected_assets)
    if set(assets) != {item["name"] for item in expected_assets}:
        raise ReleasePublishError("draft GitHub Release assets remain incomplete")
    _verify_binsync_targets(manifest)
    _publish_release(repository, release["id"])
    published = _release_state(repository, tag)
    if published is None or published.get("draft") is not False:
        raise ReleasePublishError("GitHub Release did not become published")
    _validate_release_identity(published, tag=tag, source_sha=source_sha, title=title, notes=notes)
    _verify_remote_assets(repository, tag, published, expected_assets)
    return {**verified, "status": "published", "tag": tag, "release_id": published["id"]}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--bundle-root", required=True)
    parser.add_argument("--source-sha")
    parser.add_argument("--gamever")
    parser.add_argument("--release-version")
    parser.add_argument("--build-id")
    parser.add_argument("--actions-artifact-name")
    parser.add_argument("--binsync-candidate-digest")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = publish_release(
            bundle_root=args.bundle_root,
            repo_root=args.repo_root,
            expected_source_sha=args.source_sha,
            expected_game_version=args.gamever,
            expected_release_version=args.release_version,
            expected_build_id=args.build_id,
            expected_actions_artifact_name=args.actions_artifact_name,
            expected_binsync_candidate_digest=args.binsync_candidate_digest,
        )
    except (ReleasePublishError, OSError) as exc:
        print(f"Release publish error: {exc}", file=sys.stderr)
        return 1
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

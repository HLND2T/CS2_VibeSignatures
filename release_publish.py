#!/usr/bin/env python3
"""Publish an immutable GitHub Release after hosted and BinSync verification."""

from __future__ import annotations

import argparse
import base64
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
PUBLICATION_MODES = ("publish", "republish")


class ReleasePublishError(Exception):
    """Raised when protected GitHub Release publication cannot proceed."""


def check_publication_target(repository: str, tag: str, source_sha: str, publication_mode: str) -> tuple:
    """Read-only check shared by preflight and the protected publisher."""
    if publication_mode not in PUBLICATION_MODES:
        raise ReleasePublishError("Unsupported release publication mode")
    if not VERSION_RE.fullmatch(tag) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ReleasePublishError("Invalid release tag or source SHA")
    current = _tag_target(repository, tag)
    release = _release_state(repository, tag, allow_orphan=publication_mode == "republish")
    if publication_mode == "republish":
        if release is None:
            raise ReleasePublishError(f"Release {tag} does not exist; use publish")
        if release.get("immutable") is not False:
            raise ReleasePublishError("Release is immutable or its mutability is unknown")
        if current is None:
            raise ReleasePublishError("Existing Release tag is missing")
    elif current is not None and current != source_sha:
        raise ReleasePublishError(f"Release tag {tag} does not point directly to immutable source {source_sha}")
    return current, release


def _release_by_id(repository: str, release_id: int) -> dict:
    release = _gh_json(["api", f"repos/{repository}/releases/{release_id}"])
    # The embedded assets list may be truncated. Fetch all pages explicitly.
    result = _gh(["api", "--paginate", "--slurp", f"repos/{repository}/releases/{release_id}/assets?per_page=100"])
    try:
        pages = json.loads(result.stdout)
        if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
            raise ValueError("invalid assets pages")
        release["assets"] = [asset for page in pages for asset in page]
    except (ValueError, TypeError) as exc:
        raise ReleasePublishError("Invalid Release assets response") from exc
    return release


def _update_release(repository: str, release_id: int, **fields) -> None:
    arguments = ["api", "--method", "PATCH", f"repos/{repository}/releases/{release_id}"]
    for key, value in fields.items():
        arguments.extend(
            [
                "-F" if isinstance(value, bool) else "-f",
                f"{key}={str(value).lower() if isinstance(value, bool) else value}",
            ]
        )
    _gh(arguments)


def _delete_asset(repository: str, asset_id: int) -> None:
    _gh(["api", "--method", "DELETE", f"repos/{repository}/releases/assets/{asset_id}"])


def _move_tag(repository: str, tag: str, source_sha: str, old_sha: str, repo_root: Path) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ReleasePublishError("Invalid GitHub repository")
    environment = dict(os.environ)
    credentials = base64.b64encode(f"x-access-token:{environment[TOKEN_ENVIRONMENT_VARIABLE]}".encode()).decode()
    environment.update(
        GIT_CONFIG_COUNT="1",
        GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
        GIT_CONFIG_VALUE_0=f"AUTHORIZATION: basic {credentials}",
        GIT_TERMINAL_PROMPT="0",
    )
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "push",
            "--no-verify",
            f"--force-with-lease=refs/tags/{tag}:{old_sha}",
            f"https://github.com/{repository}.git",
            f"{source_sha}:refs/tags/{tag}",
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ReleasePublishError("Release tag lease update failed; check tag protection or concurrent changes")


def _asset_diff(repository: str, tag: str, release: dict, expected: list[dict]) -> tuple[list, set]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ReleasePublishError("Invalid Release assets response")
    by_name = {item["name"]: item for item in expected}
    remove, matching, seen = [], set(), set()
    with tempfile.TemporaryDirectory(prefix="republish-assets-") as temporary:
        for asset in assets:
            if (
                not isinstance(asset, dict)
                or not isinstance(asset.get("name"), str)
                or type(asset.get("id")) is not int
                or asset["id"] <= 0
                or asset["name"] in seen
            ):
                raise ReleasePublishError("Invalid or duplicate Release asset")
            name = asset["name"]
            seen.add(name)
            item = by_name.get(name)
            if item is not None and asset.get("size") == item["size"]:
                downloaded = _download_asset(repository, tag, name, Path(temporary))
                if sha256_file(downloaded) == item["sha256"]:
                    matching.add(name)
                    continue
            remove.append(asset)
    return remove, matching


def _republish(repository, tag, source_sha, title, notes, expected_assets, bundle_root, repo_root, manifest, verified):
    stage = "target-check"
    receipt = {**verified, "tag": tag, "target_sha": source_sha}
    try:
        old_sha, release = check_publication_target(repository, tag, source_sha, "republish")
        release_id = release.get("id")
        if type(release_id) is not int or release_id <= 0:
            raise ReleasePublishError("Invalid Release ID")
        receipt.update(release_id=release_id, previous_source_sha=old_sha)
        release = _release_by_id(repository, release_id)
        if release.get("immutable") is not False or not _tag_name_matches(release.get("tag_name"), tag):
            raise ReleasePublishError("Release target changed before republish")
        # A draft can never satisfy the already-published fast path, and its
        # assets cannot be addressed by tag while the tag move below has it
        # orphaned, so defer the asset diff until after the tag is rebound.
        if release.get("draft") is True:
            remove, matching = [], set()
        else:
            remove, matching = _asset_diff(repository, tag, release, expected_assets)
        identity_matches = all(
            release.get(key) == value
            for key, value in dict(target_commitish=source_sha, name=title, body=notes, prerelease=False).items()
        )
        if (
            old_sha == source_sha
            and identity_matches
            and not remove
            and len(matching) == len(expected_assets)
            and release.get("draft") is False
        ):
            if _tag_target(repository, tag) != source_sha:
                raise ReleasePublishError("Release tag changed during republish verification")
            receipt.update(status="already-published", stage="complete")
            _record_republish(receipt)
            return receipt
        stage = "draft"
        _update_release(repository, release_id, draft=True)
        release = _release_by_id(repository, release_id)
        if release.get("draft") is not True or not _tag_name_matches(release.get("tag_name"), tag):
            raise ReleasePublishError("Release did not become draft")
        stage = "tag"
        if old_sha != source_sha:
            _move_tag(repository, tag, source_sha, old_sha, Path(repo_root))
        stage = "metadata"
        # Moving the tag orphans this draft, so rebind the real tag name in the
        # same update; every later tag-addressed asset call depends on it.
        _update_release(
            repository,
            release_id,
            tag_name=tag,
            target_commitish=source_sha,
            name=title,
            body=notes,
            prerelease=False,
        )
        # Re-read after entering draft; do not act on the pre-draft asset inventory.
        release = _release_by_id(repository, release_id)
        _validate_release_identity(release, tag=tag, source_sha=source_sha, title=title, notes=notes)
        stage = "assets"
        remove, matching = _asset_diff(repository, tag, release, expected_assets)
        for asset in remove:
            _delete_asset(repository, asset["id"])
        for item in expected_assets:
            if item["name"] not in matching:
                _upload_asset(repository, tag, bundle_root / PurePosixPath(item["path"]))
        stage = "verification"
        release = _release_by_id(repository, release_id)
        _validate_release_identity(release, tag=tag, source_sha=source_sha, title=title, notes=notes)
        remove, matching = _asset_diff(repository, tag, release, expected_assets)
        if remove or len(matching) != len(expected_assets) or release.get("draft") is not True:
            raise ReleasePublishError("Republish draft assets remain incomplete")
        if _tag_target(repository, tag) != source_sha:
            raise ReleasePublishError("Release tag changed during republish")
        _verify_binsync_targets(manifest)
        stage = "publish"
        _publish_release(repository, release_id)
        stage = "published-verification"
        release = _release_by_id(repository, release_id)
        _validate_release_identity(release, tag=tag, source_sha=source_sha, title=title, notes=notes)
        remove, matching = _asset_diff(repository, tag, release, expected_assets)
        if (
            release.get("draft") is not False
            or remove
            or len(matching) != len(expected_assets)
            or _tag_target(repository, tag) != source_sha
        ):
            raise ReleasePublishError("Republished Release verification failed")
        receipt.update(status="republished", stage="complete")
        _record_republish(receipt)
        return receipt
    except (ReleasePublishError, OSError) as exc:
        if stage in ("publish", "published-verification"):
            # A publish request may have succeeded even if its response was lost.
            try:
                _update_release(repository, receipt["release_id"], draft=True)
            except (ReleasePublishError, OSError) as recovery_error:
                print(f"Unable to restore draft; inspect Release state: {recovery_error}", file=sys.stderr)
        _record_republish({**receipt, "stage": stage, "status": "failed"})
        raise ReleasePublishError(f"Republish failed at {stage}: {exc}") from exc


def _record_republish(receipt: dict) -> None:
    print(json.dumps(receipt), file=sys.stderr)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as stream:
                stream.write("\n## Republish receipt\n\n")
                for key in (
                    "status",
                    "stage",
                    "release_id",
                    "previous_source_sha",
                    "target_sha",
                    "bundle_inventory_sha256",
                ):
                    stream.write(f"- {key}: `{receipt.get(key, 'unknown')}`\n")
        except OSError as exc:
            print(f"Unable to write republish summary: {exc}", file=sys.stderr)


def _gh(arguments: list[str], *, allowed=(0,)) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(["gh", *arguments], capture_output=True, text=True, check=False)
    except OSError as exc:
        raise ReleasePublishError(f"unable to run GitHub CLI: {exc}") from exc
    if result.returncode not in allowed:
        detail = (result.stderr or result.stdout).strip()
        raise ReleasePublishError(
            f"gh {' '.join(arguments)} failed: {detail}"
            if detail
            else f"gh {' '.join(arguments)} failed with exit {result.returncode}"
        )
    return result


def _gh_json(arguments: list[str], *, allow_404: bool = False) -> dict | None:
    result = _gh(arguments, allowed=(0, 1) if allow_404 else (0,))
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        if allow_404 and re.search(r"\bHTTP\s+404\b", detail, re.IGNORECASE):
            return None
        raise ReleasePublishError(
            f"gh {' '.join(arguments)} failed: {detail}" if detail else f"gh {' '.join(arguments)} failed"
        )
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


def _release_title(tag: str) -> str:
    return f"gamedata-{tag}"


def _tag_name_matches(tag_name, tag: str) -> bool:
    # Force-updating a release tag orphans its draft: GitHub rewrites the
    # draft's tag_name to an untagged-* placeholder until it is rebound to the
    # tag, so a placeholder is accepted until that rebind happens.
    return tag_name == tag or (isinstance(tag_name, str) and tag_name.startswith("untagged-"))


def _is_orphaned_draft(release: dict, tag: str) -> bool:
    tag_name = release.get("tag_name")
    return (
        release.get("draft") is True
        and release.get("name") == _release_title(tag)
        and isinstance(tag_name, str)
        and tag_name.startswith("untagged-")
    )


def _release_state(repository: str, tag: str, *, allow_orphan: bool = False) -> dict | None:
    # The by-tag endpoint never returns draft releases, so fall back to the
    # release list (which does) before concluding a draft is missing.
    state = _gh_json(["api", f"repos/{repository}/releases/tags/{tag}"], allow_404=True)
    if state is not None:
        return state
    result = _gh(["api", f"repos/{repository}/releases?per_page=100"])
    try:
        releases = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReleasePublishError("GitHub CLI returned invalid JSON") from exc
    if not isinstance(releases, list) or any(not isinstance(item, dict) for item in releases):
        raise ReleasePublishError("GitHub CLI returned a non-list response")
    batch = releases
    page = 2
    while len(batch) == 100:
        result = _gh(["api", f"repos/{repository}/releases?per_page=100&page={page}"])
        try:
            batch = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ReleasePublishError("GitHub CLI returned invalid JSON") from exc
        if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
            raise ReleasePublishError("GitHub CLI returned a non-list response")
        releases.extend(batch)
        page += 1
    matches = [item for item in releases if item.get("tag_name") == tag]
    if not matches and allow_orphan:
        matches = [item for item in releases if _is_orphaned_draft(item, tag)]
    if len(matches) > 1:
        raise ReleasePublishError(f"multiple GitHub Releases declare tag {tag}")
    return matches[0] if matches else None


def _create_draft_release(repository: str, tag: str, source_sha: str, title: str, notes: str) -> dict:
    """Create the draft and return it; the by-tag lookup cannot see drafts."""
    result = _gh(
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
    try:
        created = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReleasePublishError("GitHub CLI returned invalid JSON") from exc
    if not isinstance(created, dict) or not isinstance(created.get("id"), int) or isinstance(created.get("id"), bool):
        raise ReleasePublishError("GitHub Release creation returned an invalid response")
    return created


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
    publication_mode: str = "publish",
    expected_source_sha: str | None = None,
    expected_game_version: str | None = None,
    expected_release_version: str | None = None,
    expected_build_id: str | None = None,
    expected_actions_artifact_name: str | None = None,
    expected_binsync_candidate_digest: str | None = None,
    expected_binsync_target_state_digest: str | None = None,
    expected_manifest_digest: str | None = None,
    expected_bundle_digest: str | None = None,
    expected_verified_binsync_target_state_digest: str | None = None,
) -> dict:
    """Create/recover one draft and publish only exact immutable Release bytes."""
    if publication_mode not in PUBLICATION_MODES:
        raise ReleasePublishError("Unsupported release publication mode")
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
            expected_binsync_target_state_digest=expected_binsync_target_state_digest,
        )
        manifest_path = next(bundle_root.glob("release-manifest-*.json"))
        manifest = load_json_object(manifest_path)
    except (ReleaseBundleError, ReleaseWorkflowError, StopIteration) as exc:
        raise ReleasePublishError(str(exc)) from exc
    # Bind this publication to the hosted verifier's digests before any write.
    for label, expected, actual in (
        ("manifest digest", expected_manifest_digest, verified["manifest_sha256"]),
        ("bundle digest", expected_bundle_digest, verified["bundle_inventory_sha256"]),
        (
            "verified BinSync target-state digest",
            expected_verified_binsync_target_state_digest,
            verified["binsync_target_state_digest"],
        ),
    ):
        if expected is not None and expected != actual:
            raise ReleasePublishError(f"Release {label} differs from the hosted verifier output")
    repository = manifest["repository"]
    tag = manifest["release_version"]
    source_sha = manifest["source_sha"]
    if not VERSION_RE.fullmatch(tag):
        raise ReleasePublishError("Release version is unsafe for a tag or asset name")
    title = _release_title(tag)
    notes = _notes(manifest)
    expected_assets = _expected_assets(bundle_root, manifest_path, manifest)
    _verify_binsync_targets(manifest)

    if publication_mode == "republish":
        return _republish(
            repository, tag, source_sha, title, notes, expected_assets, bundle_root, repo_root, manifest, verified
        )

    current_tag, release = check_publication_target(repository, tag, source_sha, publication_mode)
    if current_tag is None:
        _create_tag(repository, tag, source_sha)
        current_tag = _tag_target(repository, tag)
    if current_tag != source_sha:
        raise ReleasePublishError(f"Release tag {tag} does not point directly to immutable source {source_sha}")

    release = _release_state(repository, tag)
    if release is None:
        release = _create_draft_release(repository, tag, source_sha, title, notes)
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
    parser.add_argument("--bundle-root")
    parser.add_argument("--publication-mode", choices=PUBLICATION_MODES, default="publish")
    parser.add_argument("--check-target-only", action="store_true")
    parser.add_argument("--repository")
    parser.add_argument("--source-sha")
    parser.add_argument("--gamever")
    parser.add_argument("--release-version")
    parser.add_argument("--build-id")
    parser.add_argument("--actions-artifact-name")
    parser.add_argument("--binsync-candidate-digest")
    parser.add_argument("--binsync-target-state-digest")
    parser.add_argument("--verified-manifest-digest")
    parser.add_argument("--verified-bundle-digest")
    parser.add_argument("--verified-binsync-target-state-digest")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.check_target_only:
            if not all((args.repository, args.release_version, args.source_sha)):
                raise ReleasePublishError("Target check requires repository, release-version and source-sha")
            check_publication_target(args.repository, args.release_version, args.source_sha, args.publication_mode)
            print(json.dumps({"status": "target-checked"}))
            return 0
        if not args.bundle_root:
            raise ReleasePublishError("--bundle-root is required for publication")
        result = publish_release(
            publication_mode=args.publication_mode,
            bundle_root=args.bundle_root,
            repo_root=args.repo_root,
            expected_source_sha=args.source_sha,
            expected_game_version=args.gamever,
            expected_release_version=args.release_version,
            expected_build_id=args.build_id,
            expected_actions_artifact_name=args.actions_artifact_name,
            expected_binsync_candidate_digest=args.binsync_candidate_digest,
            expected_binsync_target_state_digest=args.binsync_target_state_digest,
            expected_manifest_digest=args.verified_manifest_digest,
            expected_bundle_digest=args.verified_bundle_digest,
            expected_verified_binsync_target_state_digest=args.verified_binsync_target_state_digest,
        )
    except (ReleasePublishError, OSError) as exc:
        print(f"Release publish error: {exc}", file=sys.stderr)
        return 1
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Hydrate verified immutable GitHub Releases into a Pages input tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

from release_bundle import ALLOWED_REPOSITORY, BUNDLE_SCHEMA_VERSION, ReleaseBundleError, validate_release_manifest
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    file_inventory,
    inventory_sha256,
    normalized_relative_path,
    sha256_bytes,
    sha256_file,
    write_canonical_json,
)
from release_workflow_lib.sevenzip import listed_archive_files

RELEASE_INPUT_SCHEMA_VERSION = 1
GAME_VERSION_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,240}$")


class PagesReleaseInputError(Exception):
    """Raised when published Releases cannot form a trusted Pages input tree."""


def _normalize_sha256(value: str) -> str:
    normalized = str(value).lower().removeprefix("sha256:")
    if not SHA256_RE.fullmatch(normalized):
        raise PagesReleaseInputError(f"invalid SHA-256 digest: {value!r}")
    return normalized


def _release_set_digest(releases: list[dict]) -> str:
    payload = b"source-owned-pages-release-set:v1\n" + canonical_json_bytes(releases)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _strict_json_bytes(raw: bytes, source: str) -> dict:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PagesReleaseInputError(f"{source}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PagesReleaseInputError(f"{source}: invalid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PagesReleaseInputError(f"{source}: JSON top level must be an object")
    return value


def _validate_file_records(value: object, *, source: str, prefix: str | None = None) -> list[dict]:
    if not isinstance(value, list) or not value:
        raise PagesReleaseInputError(f"{source}: expected a non-empty file inventory")
    records = []
    seen = set()
    for index, item in enumerate(value):
        item_source = f"{source}[{index}]"
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise PagesReleaseInputError(f"{item_source}: invalid file record")
        try:
            path = normalized_relative_path(item["path"])
        except (ReleaseWorkflowError, TypeError) as exc:
            raise PagesReleaseInputError(f"{item_source}: {exc}") from exc
        if prefix is not None and not path.startswith(prefix):
            raise PagesReleaseInputError(f"{item_source}: path is outside {prefix}")
        if path in seen:
            raise PagesReleaseInputError(f"{source}: duplicate path {path}")
        size = item["size"]
        digest = item["sha256"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise PagesReleaseInputError(f"{item_source}: invalid size")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise PagesReleaseInputError(f"{item_source}: invalid SHA-256")
        records.append({"path": path, "size": size, "sha256": digest})
        seen.add(path)
    if records != sorted(records, key=lambda item: item["path"]):
        raise PagesReleaseInputError(f"{source}: inventory is not sorted")
    return records


def _asset_map(release: dict) -> dict[str, dict]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise PagesReleaseInputError("GitHub Release assets response is invalid")
    result = {}
    for asset in assets:
        if (
            not isinstance(asset, dict)
            or not isinstance(asset.get("id"), int)
            or isinstance(asset.get("id"), bool)
            or not isinstance(asset.get("name"), str)
            or not ASSET_NAME_RE.fullmatch(asset["name"])
            or not isinstance(asset.get("size"), int)
            or isinstance(asset.get("size"), bool)
            or asset["size"] <= 0
            or asset["name"] in result
        ):
            raise PagesReleaseInputError("GitHub Release contains an invalid or duplicate asset")
        result[asset["name"]] = asset
    return result


def _public_asset_map(manifest: dict) -> dict[str, dict]:
    result = {}
    for item in manifest["public_assets"]:
        if item["name"] in result:
            raise PagesReleaseInputError("Release manifest public asset names collide")
        result[item["name"]] = item
    return result


def _expected_checksum_bytes(manifest_name: str, manifest_bytes: bytes, manifest: dict) -> bytes:
    records = [
        *manifest["public_assets"],
        {
            "path": manifest_name,
            "name": manifest_name,
            "size": len(manifest_bytes),
            "sha256": sha256_bytes(manifest_bytes),
        },
    ]
    return "".join(
        f"{item['sha256']}  {item['path']}\n" for item in sorted(records, key=lambda item: item["path"])
    ).encode("utf-8")


def _verify_download(path: Path, record: dict, source: str) -> None:
    if path.stat().st_size != record["size"] or sha256_file(path) != record["sha256"]:
        raise PagesReleaseInputError(f"{source}: downloaded asset size or SHA-256 mismatch")


class GhReleaseClient:
    """Minimal read-only GitHub CLI adapter used by the Pages hydrator."""

    def __init__(self, repository: str):
        self.repository = repository

    @staticmethod
    def _run(arguments: list[str]) -> subprocess.CompletedProcess:
        try:
            result = subprocess.run(["gh", *arguments], capture_output=True, check=False)
        except OSError as exc:
            raise PagesReleaseInputError(f"unable to run GitHub CLI: {exc}") from exc
        if result.returncode:
            detail = (result.stderr or result.stdout).decode(errors="replace").strip()
            raise PagesReleaseInputError(detail or f"gh {' '.join(arguments)} failed")
        return result

    def list_releases(self) -> list[dict]:
        result = self._run(["api", "--paginate", "--slurp", f"repos/{self.repository}/releases?per_page=100"])
        try:
            pages = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise PagesReleaseInputError("GitHub CLI returned invalid release JSON") from exc
        if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
            raise PagesReleaseInputError("GitHub CLI returned an invalid paginated release response")
        return [release for page in pages for release in page]

    def tag_target(self, tag: str) -> str:
        result = self._run(["api", f"repos/{self.repository}/git/ref/tags/{quote(tag, safe='')}"])
        value = _strict_json_bytes(result.stdout, f"tag {tag}")
        target = value.get("object")
        if (
            not isinstance(target, dict)
            or target.get("type") != "commit"
            or not SHA_RE.fullmatch(str(target.get("sha", "")).lower())
        ):
            raise PagesReleaseInputError(f"Release tag is not a direct commit ref: {tag}")
        return target["sha"].lower()

    def download_asset(self, asset: dict, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        arguments = [
            "gh",
            "api",
            "-H",
            "Accept: application/octet-stream",
            f"repos/{self.repository}/releases/assets/{asset['id']}",
        ]
        try:
            with destination.open("xb") as handle:
                result = subprocess.run(arguments, stdout=handle, stderr=subprocess.PIPE, check=False)
        except OSError as exc:
            raise PagesReleaseInputError(f"unable to download Release asset {asset['name']}: {exc}") from exc
        if result.returncode:
            destination.unlink(missing_ok=True)
            detail = result.stderr.decode(errors="replace").strip()
            raise PagesReleaseInputError(detail or f"unable to download Release asset {asset['name']}")


class SevenZipGamedataExtractor:
    """Preflight a 7z inventory before extracting only the declared gamedata subtree."""

    @staticmethod
    def _run(arguments: list[str]) -> subprocess.CompletedProcess:
        try:
            result = subprocess.run(["7z", *arguments], capture_output=True, text=True, check=False)
        except OSError as exc:
            raise PagesReleaseInputError(f"unable to run 7z: {exc}") from exc
        if result.returncode:
            raise PagesReleaseInputError((result.stderr or result.stdout).strip() or "7z command failed")
        return result

    @staticmethod
    def _listed_files(output: str) -> list[dict]:
        try:
            return listed_archive_files(output)
        except ReleaseWorkflowError as exc:
            raise PagesReleaseInputError(str(exc)) from exc

    def extract_gamedata(self, archive: Path, destination: Path, game_version: str, expected: list[dict]) -> None:
        listed = self._listed_files(self._run(["l", "-slt", "-ba", str(archive)]).stdout)
        expected_listing = [{"path": item["path"], "size": item["size"]} for item in expected]
        if listed != expected_listing:
            raise PagesReleaseInputError("gamedata archive listed inventory differs from the Release manifest")
        destination.mkdir(parents=True)
        self._run(
            [
                "x",
                "-y",
                "-bd",
                "-bso0",
                "-bsp0",
                f"-o{destination}",
                str(archive),
                f"gamedata/{game_version}/*",
            ]
        )


def _download(client, asset: dict, destination: Path, record: dict | None = None) -> bytes:
    client.download_asset(asset, destination)
    raw = destination.read_bytes()
    if asset["size"] != len(raw):
        raise PagesReleaseInputError(f"downloaded Release asset size mismatch: {asset['name']}")
    if record is not None:
        _verify_download(destination, record, asset["name"])
    return raw


def _compatible_manifest_asset(release: dict, assets: dict[str, dict]) -> tuple[str, dict] | None:
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not tag:
        raise PagesReleaseInputError("published GitHub Release tag is invalid")
    manifest_name = f"release-manifest-{tag}.json"
    manifest_asset = assets.get(manifest_name)
    if manifest_asset is None:
        return None
    return manifest_name, manifest_asset


def _stage_release(
    *,
    release: dict,
    client,
    extractor,
    output_root: Path,
    temporary_root: Path,
) -> dict | None:
    if release.get("draft") is True:
        return None
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise PagesReleaseInputError("GitHub Release publication state is invalid")
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
        raise PagesReleaseInputError("GitHub Release ID is invalid")
    assets = _asset_map(release)
    compatible = _compatible_manifest_asset(release, assets)
    if compatible is None:
        return None
    manifest_name, manifest_asset = compatible
    release_root = temporary_root / str(release_id)
    release_root.mkdir()
    manifest_path = release_root / manifest_name
    manifest_bytes = _download(client, manifest_asset, manifest_path)
    manifest = _strict_json_bytes(manifest_bytes, manifest_name)
    if manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION or "artifact_inventory_sha256" not in manifest:
        return None
    if manifest_bytes != canonical_json_bytes(manifest):
        raise PagesReleaseInputError(f"{manifest_name}: Release manifest is not canonical JSON")
    try:
        validate_release_manifest(manifest)
    except ReleaseBundleError as exc:
        raise PagesReleaseInputError(str(exc)) from exc

    tag = release["tag_name"]
    source_sha = manifest["source_sha"]
    game_version = manifest["game_version"]
    if (
        manifest["release_version"] != tag
        or not GAME_VERSION_RE.fullmatch(game_version)
        or tag != game_version
        or str(release.get("target_commitish", "")).lower() != source_sha
        or client.tag_target(tag) != source_sha
    ):
        raise PagesReleaseInputError(f"Release {release_id} tag, source, or GAMEVER identity mismatch")

    public_assets = _public_asset_map(manifest)
    checksum_name = f"SHA256SUMS-{tag}.txt"
    expected_names = {*public_assets, manifest_name, checksum_name}
    if set(assets) != expected_names:
        raise PagesReleaseInputError(f"Release {release_id} asset allowlist mismatch")
    for name, record in public_assets.items():
        if assets[name]["size"] != record["size"]:
            raise PagesReleaseInputError(f"Release asset size differs from the manifest: {name}")
    if manifest_asset["size"] != len(manifest_bytes):
        raise PagesReleaseInputError("Release manifest asset size mismatch")
    checksum_path = release_root / checksum_name
    checksum_bytes = _download(client, assets[checksum_name], checksum_path)
    if checksum_bytes != _expected_checksum_bytes(manifest_name, manifest_bytes, manifest):
        raise PagesReleaseInputError("Release SHA256SUMS contract mismatch")

    prefix = f"gamedata/{game_version}/"
    gamedata_files = _validate_file_records(
        manifest["gamedata"].get("files"), source="manifest.gamedata.files", prefix=prefix
    )
    archive_path = f"archives/gamedata-{game_version}.7z"
    archive_contract = manifest["archives"].get(archive_path)
    if not isinstance(archive_contract, dict) or set(archive_contract) != {"files", "inventory_sha256"}:
        raise PagesReleaseInputError("Release gamedata archive contract is invalid")
    archive_files = _validate_file_records(archive_contract["files"], source="manifest archives")
    if inventory_sha256(archive_files) != archive_contract["inventory_sha256"]:
        raise PagesReleaseInputError("Release gamedata archive inventory digest mismatch")
    archive_by_path = {item["path"]: item for item in archive_files}
    if any(archive_by_path.get(item["path"]) != item for item in gamedata_files):
        raise PagesReleaseInputError("Release gamedata inventory is absent from the gamedata archive")

    snapshot_record = public_assets.get(f"{game_version}.yaml")
    metadata_record = public_assets.get(f"{game_version}.metadata.yaml")
    archive_record = public_assets.get(f"gamedata-{game_version}.7z")
    if (
        snapshot_record is None
        or snapshot_record["path"] != manifest["snapshot"]["path"]
        or snapshot_record["sha256"] != manifest["snapshot"]["sha256"]
        or metadata_record is None
        or metadata_record["path"] != manifest["metadata"]["path"]
        or metadata_record["sha256"] != manifest["metadata"]["sha256"]
        or archive_record is None
        or archive_record["path"] != archive_path
    ):
        raise PagesReleaseInputError("Release Pages asset bindings are invalid")

    snapshot_path = release_root / snapshot_record["name"]
    metadata_path = release_root / metadata_record["name"]
    archive_file = release_root / archive_record["name"]
    _download(client, assets[snapshot_record["name"]], snapshot_path, snapshot_record)
    _download(client, assets[metadata_record["name"]], metadata_path, metadata_record)
    _download(client, assets[archive_record["name"]], archive_file, archive_record)
    extracted_root = release_root / "extracted"
    extractor.extract_gamedata(archive_file, extracted_root, game_version, archive_files)
    try:
        extracted_inventory = file_inventory(extracted_root)
    except ReleaseWorkflowError as exc:
        raise PagesReleaseInputError(str(exc)) from exc
    if extracted_inventory != gamedata_files:
        raise PagesReleaseInputError("extracted Pages gamedata differs from the Release manifest")

    snapshot_target = output_root / "gamesymbols" / f"{game_version}.yaml"
    metadata_target = output_root / "gamesymbols" / f"{game_version}.metadata.yaml"
    gamedata_target = output_root / "gamedata" / game_version
    if snapshot_target.exists() or metadata_target.exists() or gamedata_target.exists():
        raise PagesReleaseInputError(f"multiple published Releases declare GAMEVER {game_version}")
    snapshot_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(snapshot_path, snapshot_target)
    shutil.copyfile(metadata_path, metadata_target)
    shutil.copytree(extracted_root / "gamedata" / game_version, gamedata_target)
    return {
        "release_id": release_id,
        "tag": tag,
        "source_sha": source_sha,
        "game_version": game_version,
        "manifest_sha256": sha256_bytes(manifest_bytes),
    }


def stage_pages_release_inputs(
    *,
    repository: str,
    triggering_release_id: int,
    triggering_tag: str,
    triggering_source_sha: str,
    triggering_manifest_sha256: str,
    output_root: str | Path,
    receipt_path: str | Path,
    client=None,
    extractor=None,
) -> dict:
    """Build a fresh Pages input tree from every compatible published Release."""
    if repository != ALLOWED_REPOSITORY:
        raise PagesReleaseInputError(f"repository is not allowlisted: {repository}")
    if (
        not isinstance(triggering_release_id, int)
        or isinstance(triggering_release_id, bool)
        or triggering_release_id <= 0
    ):
        raise PagesReleaseInputError("triggering Release ID is invalid")
    if not GAME_VERSION_RE.fullmatch(triggering_tag):
        raise PagesReleaseInputError("triggering Release tag is invalid")
    triggering_source_sha = triggering_source_sha.lower()
    if not SHA_RE.fullmatch(triggering_source_sha):
        raise PagesReleaseInputError("triggering source SHA is invalid")
    triggering_manifest_sha256 = _normalize_sha256(triggering_manifest_sha256)
    output_root = Path(os.path.abspath(output_root))
    receipt_path = Path(os.path.abspath(receipt_path))
    if output_root.exists():
        raise PagesReleaseInputError(f"Pages Release input root must be fresh: {output_root}")
    if receipt_path.exists():
        raise PagesReleaseInputError(f"Pages Release receipt path must be fresh: {receipt_path}")
    output_root.mkdir(parents=True)
    client = client or GhReleaseClient(repository)
    extractor = extractor or SevenZipGamedataExtractor()
    staged = []
    try:
        releases = client.list_releases()
        if not isinstance(releases, list):
            raise PagesReleaseInputError("GitHub Release list is invalid")
        with tempfile.TemporaryDirectory(prefix="pages-release-input-") as temporary:
            temporary_root = Path(temporary)
            for release in releases:
                if not isinstance(release, dict):
                    raise PagesReleaseInputError("GitHub Release list contains a non-object")
                record = _stage_release(
                    release=release,
                    client=client,
                    extractor=extractor,
                    output_root=output_root,
                    temporary_root=temporary_root,
                )
                if record is not None:
                    staged.append(record)
        staged.sort(key=lambda item: item["game_version"])
        trigger = next((item for item in staged if item["release_id"] == triggering_release_id), None)
        if trigger is None:
            raise PagesReleaseInputError("triggering Release is not a compatible published source-owned Release")
        if (
            trigger["tag"] != triggering_tag
            or trigger["source_sha"] != triggering_source_sha
            or trigger["manifest_sha256"] != triggering_manifest_sha256
        ):
            raise PagesReleaseInputError("triggering Release identity differs from the verified publication")
        try:
            inputs = file_inventory(output_root)
        except ReleaseWorkflowError as exc:
            raise PagesReleaseInputError(str(exc)) from exc
        receipt = {
            "schema_version": RELEASE_INPUT_SCHEMA_VERSION,
            "repository": repository,
            "triggering_release_id": triggering_release_id,
            "triggering_tag": triggering_tag,
            "triggering_source_sha": triggering_source_sha,
            "releases": staged,
            "release_set_digest": _release_set_digest(staged),
            "input_files": inputs,
            "input_inventory_sha256": inventory_sha256(inputs),
        }
        write_canonical_json(receipt_path, receipt)
        return receipt
    except BaseException:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-id", required=True, type=int)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--receipt", required=True)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not os.environ.get("GH_TOKEN", "").strip():
            raise PagesReleaseInputError("GH_TOKEN is required")
        result = stage_pages_release_inputs(
            repository=args.repository,
            triggering_release_id=args.release_id,
            triggering_tag=args.release_tag,
            triggering_source_sha=args.source_sha,
            triggering_manifest_sha256=args.manifest_sha256,
            output_root=args.output_root,
            receipt_path=args.receipt,
        )
    except (OSError, PagesReleaseInputError, ValueError) as exc:
        print(f"Pages Release input error: {exc}", file=sys.stderr)
        return 1
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

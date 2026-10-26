#!/usr/bin/env python3
"""Idempotently initialize release binaries for one GAMEVER."""

import argparse
import functools
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import requests
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from analysis_config import AnalysisConfigError, resolve_analysis_config  # noqa: E402
from release_workflow_lib.binary_cache import verify_source_binary_root  # noqa: E402
from release_workflow_lib.errors import ReleaseWorkflowError  # noqa: E402
from release_workflow_lib.hashing import (  # noqa: E402
    canonical_json_bytes,
    file_inventory,
    load_json_object,
    sha256_file,
)
from release_workflow_lib.sevenzip import listed_archive_files  # noqa: E402

RELEASE_ASSET_URL = "https://github.com/HLND2T/CS2_VibeSignatures/releases/download/{0}/{1}"
RELEASE_TAG_API_URL = "https://api.github.com/repos/HLND2T/CS2_VibeSignatures/git/ref/tags/{0}"
GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")
DOWNLOAD_TIMEOUT = (30, 300)
COPY_BUFFER_SIZE = 1024 * 1024
GITHUB_TOKEN_ENVIRONMENT_VARIABLES = ("GH_TOKEN", "GITHUB_TOKEN")


class InitGamebinError(Exception):
    """Raised when gamebin initialization cannot safely continue."""


def run_command(command, cwd: Path, *, allowed=(0,), capture=False, label=None):
    """Run a command and normalize executable and exit-code failures."""
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=capture, text=True, check=False)
    except FileNotFoundError as exc:
        raise InitGamebinError(f"required executable not found: {command[0]}") from exc
    except OSError as exc:
        raise InitGamebinError(f"unable to run {label or command[0]}: {exc}") from exc
    if result.returncode not in allowed:
        detail = (result.stderr or result.stdout).strip() if capture else ""
        suffix = f": {detail}" if detail else ""
        raise InitGamebinError(f"{label or command[0]} failed with exit code {result.returncode}{suffix}")
    return result


def repository_root() -> Path:
    """Require execution from the repository that owns this project-level skill."""
    expected = Path(__file__).resolve().parent
    result = run_command(["git", "rev-parse", "--show-toplevel"], expected, capture=True, label="git rev-parse")
    actual = Path(result.stdout.strip()).resolve()
    if actual != expected:
        raise InitGamebinError(f"skill is not running in its owning repository: {actual}")
    return actual


def load_versions(config_path: Path) -> list[str]:
    """Load ordered, unique GAMEVER tags from download.yaml."""
    try:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise InitGamebinError(f"unable to read {config_path}: {exc}") from exc
    downloads = document.get("downloads") if isinstance(document, dict) else None
    if not isinstance(downloads, list):
        raise InitGamebinError("download.yaml field 'downloads' must be a list")
    versions = []
    for index, entry in enumerate(downloads):
        tag = entry.get("tag") if isinstance(entry, dict) else None
        if not isinstance(tag, str) or not GAMEVER_RE.fullmatch(tag):
            raise InitGamebinError(f"download.yaml downloads[{index}].tag is not a valid GAMEVER")
        versions.append(tag)
    if not versions:
        raise InitGamebinError("download.yaml contains no GAMEVER entries")
    duplicates = sorted({version for version in versions if versions.count(version) > 1})
    if duplicates:
        raise InitGamebinError(f"download.yaml contains duplicate GAMEVER entries: {', '.join(duplicates)}")
    return versions


def load_yaml_document(config_path: Path, label: str) -> dict:
    """Load one YAML mapping with normalized errors."""
    try:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise InitGamebinError(f"unable to read {config_path}: {exc}") from exc
    if not isinstance(document, dict):
        raise InitGamebinError(f"{label} must contain a YAML mapping")
    return document


def select_version(requested: str, versions: list[str]) -> str:
    """Resolve latest or validate an exact requested version."""
    if requested == "latest":
        return versions[-1]
    if not GAMEVER_RE.fullmatch(requested):
        raise InitGamebinError(f"invalid requested GAMEVER: {requested}")
    if requested not in versions:
        raise InitGamebinError(f"GAMEVER {requested} is absent from download.yaml")
    return requested


def check_binaries(root: Path, gamever: str, config_path: Path) -> bool:
    """Return whether all configured binary targets already exist."""
    command = [
        "uv",
        "run",
        "copy_depot_bin.py",
        "-gamever",
        gamever,
        "-platform",
        "all-platform",
        "-checkonly",
        "-config",
        str(config_path),
    ]
    result = run_command(command, root, allowed=(0, 1, 2), label="copy_depot_bin.py -checkonly")
    if result.returncode == 2:
        raise InitGamebinError("copy_depot_bin.py -checkonly reported a configuration or argument error")
    return result.returncode == 0


def iter_configured_binaries(root: Path, gamever: str, config_path: Path, *, require_existing: bool = True):
    """Yield ``(module_name, platform, binary_path)`` for every configured binary.

    Order is first-seen across modules, then ``windows`` before ``linux`` within
    each module. Duplicate real paths are skipped. ``require_existing=False``
    enumerates from the config alone before binaries have been downloaded.
    """
    document = load_yaml_document(config_path, "analysis config")
    modules = document.get("modules")
    if not isinstance(modules, list):
        raise InitGamebinError("analysis config field 'modules' must be a list")

    gamever_root = (root / "bin" / gamever).resolve()
    seen_paths = set()
    found_any = False
    for index, module in enumerate(modules):
        if not isinstance(module, dict):
            raise InitGamebinError(f"analysis config modules[{index}] must be a mapping")
        module_name = module.get("name")
        if not isinstance(module_name, str) or not module_name:
            raise InitGamebinError(f"analysis config modules[{index}].name must be a non-empty string")
        module_root = (gamever_root / module_name).resolve()
        try:
            module_root.relative_to(gamever_root)
        except ValueError as exc:
            raise InitGamebinError(f"analysis config module name escapes bin/{gamever}: {module_name}") from exc

        for platform in ("windows", "linux"):
            configured_path = module.get(f"path_{platform}")
            if configured_path is None:
                continue
            if not isinstance(configured_path, str) or not configured_path:
                raise InitGamebinError(f"analysis config modules[{index}].path_{platform} must be a non-empty string")
            binary_name = Path(configured_path).name
            if not binary_name:
                raise InitGamebinError(f"analysis config contains an invalid {platform} binary path: {configured_path}")
            binary_path = (module_root / binary_name).resolve()
            try:
                binary_path.relative_to(gamever_root)
            except ValueError as exc:
                raise InitGamebinError(f"configured binary escapes bin/{gamever}: {binary_path}") from exc
            if require_existing and not binary_path.is_file():
                raise InitGamebinError(f"configured binary is missing after preparation: {binary_path}")

            path_key = os.path.normcase(str(binary_path))
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            found_any = True
            yield module_name, platform, binary_path

    if not found_any:
        raise InitGamebinError(f"analysis config contains no Windows or Linux binaries for GAMEVER {gamever}")


@functools.lru_cache(maxsize=1)
def github_token() -> str | None:
    """Resolve a GitHub token, preferring the environment over the gh CLI.

    Returns None when neither source provides a usable token, so every caller
    degrades to the same unauthenticated request the project already made.
    """
    for variable in GITHUB_TOKEN_ENVIRONMENT_VARIABLES:
        value = os.environ.get(variable, "")
        if value.strip():
            return value.strip()
    if shutil.which("gh") is None:
        return None
    try:
        result = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    token = result.stdout.strip()
    return token or None


def github_request_headers() -> dict:
    """Return authenticated GitHub request headers, or an empty mapping when anonymous.

    Unauthenticated api.github.com access is limited to 60 requests per hour, so
    reusing the gh CLI credential keeps Release lookups and downloads out of that
    quota and reports its own reason instead of a misleading HTTP 403.
    """
    token = github_token()
    if token is None:
        return {}
    return {"Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"}


def rate_limit_hint() -> str:
    """Return an actionable suffix for an authentication-quota failure."""
    return (
        " (unauthenticated GitHub API quota; set GH_TOKEN or authenticate gh"
        " so Release lookups and downloads use an authenticated token)"
    )


def is_rate_limit_status(response) -> bool:
    """Return whether a response reports an authentication quota failure."""
    if response.status_code != 403:
        return False
    return response.headers.get("x-ratelimit-remaining") == "0"


def download_release_asset(url: str, destination: Path) -> bool:
    """Download one release asset; return False only for HTTP 404."""
    try:
        with requests.get(
            url,
            headers=github_request_headers(),
            stream=True,
            allow_redirects=True,
            timeout=DOWNLOAD_TIMEOUT,
        ) as response:
            if response.status_code == 404:
                return False
            if response.status_code == 429 or is_rate_limit_status(response):
                raise InitGamebinError(
                    f"gamebin download failed with HTTP {response.status_code} {response.reason}{rate_limit_hint()}"
                )
            if not 200 <= response.status_code < 300:
                raise InitGamebinError(f"gamebin download failed with HTTP {response.status_code} {response.reason}")
            with destination.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=COPY_BUFFER_SIZE):
                    if chunk:
                        handle.write(chunk)
    except requests.RequestException as exc:
        raise InitGamebinError(f"gamebin download failed: {exc}") from exc
    if not destination.is_file() or destination.stat().st_size == 0:
        raise InitGamebinError("gamebin download produced an empty archive")
    return True


def release_tag_target(gamever: str) -> str:
    try:
        response = requests.get(
            RELEASE_TAG_API_URL.format(gamever),
            headers=github_request_headers(),
            timeout=DOWNLOAD_TIMEOUT,
        )
        if response.status_code == 429 or is_rate_limit_status(response):
            raise InitGamebinError(
                f"Release tag lookup failed with HTTP {response.status_code} {response.reason}{rate_limit_hint()}"
            )
        if not 200 <= response.status_code < 300:
            raise InitGamebinError(f"Release tag lookup failed with HTTP {response.status_code} {response.reason}")
        document = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise InitGamebinError(f"unable to resolve immutable Release tag: {exc}") from exc
    target = document.get("object") if isinstance(document, dict) else None
    if (
        not isinstance(target, dict)
        or target.get("type") != "commit"
        or not isinstance(target.get("sha"), str)
        or not re.fullmatch(r"[0-9a-f]{40}", target["sha"])
    ):
        raise InitGamebinError("Release tag is not a direct immutable commit ref")
    return target["sha"]


def gamebin_archive_name(gamever: str) -> str:
    """Return the public asset name of the binary-only gamebin archive."""
    return f"gamebin-{gamever}.7z"


def idb_archive_name(gamever: str) -> str:
    """Return the public asset name of the warm IDB archive.

    The Release manifest owns the authoritative archive name.
    """
    from release_bundle import gamebin_with_idb_archive_name

    return gamebin_with_idb_archive_name(gamever)


def load_verified_release_manifest(gamever: str, manifest_path: Path, checksums_path: Path) -> dict:
    """Validate a downloaded Release manifest and its SHA256SUMS against the tag."""
    from release_bundle import ReleaseBundleError, validate_release_manifest

    try:
        manifest = load_json_object(manifest_path)
        if manifest_path.read_bytes() != canonical_json_bytes(manifest):
            raise InitGamebinError("Release manifest is not canonical JSON")
        validate_release_manifest(manifest)
    except (OSError, ReleaseWorkflowError, ReleaseBundleError) as exc:
        raise InitGamebinError(f"Release manifest validation failed: {exc}") from exc
    if (
        manifest.get("repository") != "HLND2T/CS2_VibeSignatures"
        or manifest.get("release_version") != gamever
        or manifest.get("game_version") != gamever
        or release_tag_target(gamever) != manifest.get("source_sha")
    ):
        raise InitGamebinError("Release manifest, tag, and GAMEVER identity differ")

    manifest_name = f"release-manifest-{gamever}.json"
    checksum_records = [
        *manifest["public_assets"],
        {
            "path": manifest_name,
            "name": manifest_name,
            "size": manifest_path.stat().st_size,
            "sha256": sha256_file(manifest_path),
        },
    ]
    expected_checksums = "".join(
        f"{item['sha256']}  {item['path']}\n" for item in sorted(checksum_records, key=lambda item: item["path"])
    ).encode("utf-8")
    if checksums_path.read_bytes() != expected_checksums:
        raise InitGamebinError("downloaded SHA256SUMS differs from the Release manifest")
    return manifest


def verify_declared_archive(manifest: dict, archive_name: str, archive_path: Path) -> list[dict]:
    """Require one downloaded archive to be a declared Release asset and match it."""
    archive_key = f"archives/{archive_name}"
    archive_record = next((item for item in manifest["public_assets"] if item.get("path") == archive_key), None)
    if archive_record is None or archive_record.get("name") != archive_name:
        raise InitGamebinError(f"Release manifest does not declare the {archive_name} asset")
    if archive_path.stat().st_size != archive_record["size"] or sha256_file(archive_path) != archive_record["sha256"]:
        raise InitGamebinError(f"downloaded {archive_name} differs from the Release manifest")
    archive_contract = manifest.get("archives", {}).get(archive_key)
    if not isinstance(archive_contract, dict) or not isinstance(archive_contract.get("files"), list):
        raise InitGamebinError(f"Release manifest does not declare the {archive_name} archive contract")
    return archive_contract["files"]


def verify_downloaded_release_assets(
    *, gamever: str, manifest_path: Path, checksums_path: Path, archive_path: Path
) -> list[dict]:
    manifest = load_verified_release_manifest(gamever, manifest_path, checksums_path)
    return verify_declared_archive(manifest, gamebin_archive_name(gamever), archive_path)


def fetch_release_manifest(gamever: str, temporary: Path) -> dict | None:
    """Download and validate the Release manifest and SHA256SUMS; None on HTTP 404."""
    manifest_path = temporary / f"release-manifest-{gamever}.json"
    checksums_path = temporary / f"SHA256SUMS-{gamever}.txt"
    if not download_release_asset(RELEASE_ASSET_URL.format(gamever, manifest_path.name), manifest_path):
        return None
    if not download_release_asset(RELEASE_ASSET_URL.format(gamever, checksums_path.name), checksums_path):
        raise InitGamebinError("published Release is missing SHA256SUMS")
    return load_verified_release_manifest(gamever, manifest_path, checksums_path)


def release_declares_idb_archive(manifest: dict, gamever: str) -> bool:
    """Return whether the manifest declares the warm IDB archive and a public asset for it."""
    archive_key = f"archives/{idb_archive_name(gamever)}"
    if archive_key not in manifest.get("archives", {}):
        return False
    return any(item.get("path") == archive_key for item in manifest["public_assets"])


def download_verified_release_archive(
    manifest: dict, gamever: str, archive_name: str, temporary: Path
) -> tuple[Path, list[dict]]:
    """Download one declared Release archive and verify it against the manifest."""
    archive = temporary / archive_name
    if not download_release_asset(RELEASE_ASSET_URL.format(gamever, archive_name), archive):
        raise InitGamebinError(f"published Release is missing its declared {archive_name} asset")
    expected = verify_declared_archive(manifest, archive_name, archive)
    return archive, expected


def download_verified_release_gamebin(gamever: str, temporary: Path) -> tuple[Path, list[dict]] | None:
    manifest = fetch_release_manifest(gamever, temporary)
    if manifest is None:
        return None
    return download_verified_release_archive(manifest, gamever, gamebin_archive_name(gamever), temporary)


def extract_archive(root: Path, archive: Path, destination: Path, expected: list[dict]) -> None:
    """Preflight and extract a verified Release archive into an isolated directory."""
    listing = run_command(
        ["7z", "l", "-slt", "-ba", str(archive)],
        root,
        capture=True,
        label=f"listing {archive.name}",
    )
    try:
        listed = listed_archive_files(listing.stdout)
    except ReleaseWorkflowError as exc:
        raise InitGamebinError(str(exc)) from exc
    expected_listing = sorted(
        ({"path": item["path"], "size": item["size"]} for item in expected),
        key=lambda item: item["path"],
    )
    if listed != expected_listing:
        raise InitGamebinError("gamebin archive listing differs from the Release manifest")
    destination.mkdir(parents=True, exist_ok=False)
    run_command(
        ["7z", "x", str(archive), f"-o{destination}", "-y"],
        root,
        label=f"extracting {archive.name}",
    )
    if file_inventory(destination) != expected:
        raise InitGamebinError("extracted gamebin bytes differ from the Release manifest")


def copy_new_file(source: Path, target: Path) -> bool:
    """Copy one file with exclusive creation; return False when it already exists."""
    target.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with source.open("rb") as input_handle:
            try:
                output_handle = target.open("xb")
            except FileExistsError:
                return False
            created = True
            with output_handle:
                shutil.copyfileobj(input_handle, output_handle, length=COPY_BUFFER_SIZE)
        shutil.copystat(source, target)
    except OSError as exc:
        if created:
            target.unlink(missing_ok=True)
        raise InitGamebinError(f"failed to copy {source} to {target}: {exc}") from exc
    return True


def merge_archive_bin(extract_root: Path, bin_root: Path, gamever: str) -> tuple[int, int]:
    """Merge only bin/GAMEVER from the archive without overwriting files."""
    source_root = extract_root / "bin" / gamever
    if not source_root.is_dir():
        raise InitGamebinError(f"archive does not contain bin/{gamever}")
    copied = skipped = total_files = 0
    for source in sorted(source_root.rglob("*")):
        if source.is_symlink():
            raise InitGamebinError(f"archive contains an unsupported symbolic link: {source}")
        relative = source.relative_to(source_root)
        target = bin_root / gamever / relative
        if source.is_dir():
            if target.exists() and not target.is_dir():
                raise InitGamebinError(f"cannot create directory because a file exists: {target}")
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not source.is_file():
            continue
        total_files += 1
        if target.exists():
            if not target.is_file():
                raise InitGamebinError(f"cannot copy file because a directory exists: {target}")
            skipped += 1
        elif copy_new_file(source, target):
            copied += 1
        else:
            skipped += 1
    if total_files == 0:
        raise InitGamebinError(f"archive bin/{gamever} contains no files")
    return copied, skipped


def depot_download_command(gamever: str, config_path: Path) -> list[str]:
    """Build the workflow-compatible depot command."""
    command = [
        "uv",
        "run",
        "download_depot.py",
        "-tag",
        gamever,
        "-depotdir",
        "cs2_depot",
        "-config",
        "download.yaml",
        "-configyaml",
        str(config_path),
    ]
    return command


def run_depot_fallback(root: Path, gamever: str, config_path: Path) -> None:
    """Download declared manifests and copy only missing configured binaries."""
    run_command(depot_download_command(gamever, config_path), root, label="download_depot.py")
    command = [
        "uv",
        "run",
        "copy_depot_bin.py",
        "-gamever",
        gamever,
        "-platform",
        "all-platform",
        "-config",
        str(config_path),
    ]
    run_command(command, root, label="copy_depot_bin.py")


def prepare(
    root: Path,
    requested: str,
    *,
    with_idb: bool = False,
) -> dict:
    """Prepare verified binaries and optionally merge published warm IDA databases."""
    versions = load_versions(root / "download.yaml")
    gamever = select_version(requested, versions)
    try:
        config_path = resolve_analysis_config(gamever, repo_root=root)
    except AnalysisConfigError as exc:
        raise InitGamebinError(str(exc)) from exc
    source = "existing local binaries"
    copied = skipped = 0
    idb_merge = None
    need_binaries = not check_binaries(root, gamever, config_path)
    if need_binaries or with_idb:
        with tempfile.TemporaryDirectory(prefix=f"init-gamebin-{gamever}-") as temp_dir:
            temporary = Path(temp_dir)
            manifest = fetch_release_manifest(gamever, temporary)
            if need_binaries:
                if manifest is not None:
                    archive, expected_files = download_verified_release_archive(
                        manifest, gamever, gamebin_archive_name(gamever), temporary
                    )
                    extracted = temporary / "extracted"
                    extract_archive(root, archive, extracted, expected_files)
                    copied, skipped = merge_archive_bin(extracted, root / "bin", gamever)
                    source = "release archive"
                    if not check_binaries(root, gamever, config_path):
                        print(
                            "Verified Release archive is missing configured binaries; supplementing from Steam depots"
                        )
                        run_depot_fallback(root, gamever, config_path)
                        source = "release archive + Steam depot fallback"
                else:
                    run_depot_fallback(root, gamever, config_path)
                    source = "Steam depot fallback"
            if with_idb:
                if manifest is None or not release_declares_idb_archive(manifest, gamever):
                    raise InitGamebinError(
                        f"the selected Release for GAMEVER {gamever} publishes no {idb_archive_name(gamever)}; "
                        "run the skill's check-idb probe before requesting a warm IDB download"
                    )
                idb_archive, idb_expected = download_verified_release_archive(
                    manifest, gamever, idb_archive_name(gamever), temporary
                )
                extracted = temporary / "extracted-idb"
                extract_archive(root, idb_archive, extracted, idb_expected)
                idb_merge = merge_archive_bin(extracted, root / "bin", gamever)
    if not check_binaries(root, gamever, config_path):
        raise InitGamebinError(f"configured binaries are still incomplete for GAMEVER {gamever}")
    try:
        binary_lock = verify_source_binary_root(
            repo_root=root,
            gamever=gamever,
            binary_root=root / "bin" / gamever,
            label="initialized binary tree",
        )
    except ReleaseWorkflowError as exc:
        raise InitGamebinError(f"configured binaries do not match the source binary lock: {exc}") from exc
    return {
        "gamever": gamever,
        "source": source,
        "copied": copied,
        "skipped": skipped,
        "idb": idb_merge,
        "binary_lock_sha256": binary_lock.sha256,
    }


def check_idb(gamever: str, temporary: Path | None = None) -> tuple[bool, str]:
    """Probe whether the published Release declares a warm IDB archive.

    Returns (True, "") when the archive is published, or (False, reason). Only
    the manifest and checksums are downloaded; never raises for a normal
    unavailability reason and never modifies the workspace.
    """
    try:
        if temporary is not None:
            return _check_idb(gamever, temporary)
        with tempfile.TemporaryDirectory(prefix=f"check-idb-{gamever}-") as temp_dir:
            return _check_idb(gamever, Path(temp_dir))
    except InitGamebinError as exc:
        return False, str(exc)


def _check_idb(gamever: str, temporary: Path) -> tuple[bool, str]:
    manifest = fetch_release_manifest(gamever, temporary)
    if manifest is None:
        return False, f"no published Release exists for GAMEVER {gamever}"
    if not release_declares_idb_archive(manifest, gamever):
        return False, f"the published Release for GAMEVER {gamever} does not declare a warm IDB archive"
    return True, ""


def print_versions(versions: list[str]) -> None:
    """Print all allowed versions while making the latest entry unambiguous."""
    print("Available GAMEVER values:")
    for version in versions:
        suffix = " (latest)" if version == versions[-1] else ""
        print(f"  {version}{suffix}")
    print(f"LATEST_GAMEVER={versions[-1]}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("versions", help="List GAMEVER values from download.yaml")
    check_idb_parser = commands.add_parser(
        "check-idb",
        help="Probe whether the published Release declares a warm IDB archive",
    )
    check_idb_parser.add_argument("gamever", help="Exact GAMEVER from download.yaml, or latest")
    prepare_parser = commands.add_parser("prepare", help="Prepare configured binaries")
    prepare_parser.add_argument("gamever", help="Exact GAMEVER from download.yaml, or latest")
    prepare_parser.add_argument(
        "--with-idb",
        action="store_true",
        help="Also download and merge the published warm IDA databases (skips local warmup)",
    )
    args = parser.parse_args(argv)
    try:
        root = repository_root()
        if args.command == "versions":
            print_versions(load_versions(root / "download.yaml"))
        elif args.command == "check-idb":
            gamever = select_version(args.gamever, load_versions(root / "download.yaml"))
            available, reason = check_idb(gamever)
            if available:
                print(f"Warm IDB archive available: {idb_archive_name(gamever)}")
                return 0
            print(f"Warm IDB archive unavailable: {reason}")
            return 1
        else:
            result = prepare(
                root,
                args.gamever,
                with_idb=args.with_idb,
            )
            print(f"Selected GAMEVER: {result['gamever']}")
            print(f"Binary source: {result['source']}")
            print(f"Archive merge: {result['copied']} copied, {result['skipped']} skipped")
            if result["idb"] is None:
                print("Warm IDB merge: skipped")
            else:
                idb_copied, idb_skipped = result["idb"]
                print(f"Warm IDB merge: {idb_copied} copied, {idb_skipped} skipped")
    except InitGamebinError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

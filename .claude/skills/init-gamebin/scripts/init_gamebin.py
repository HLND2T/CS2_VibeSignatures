#!/usr/bin/env python3
"""Idempotently initialize release binaries for one GAMEVER."""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import requests
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPOSITORY_ROOT))

from analysis_config import AnalysisConfigError, resolve_analysis_config  # noqa: E402

RELEASE_URL = "https://github.com/HLND2T/CS2_VibeSignatures/releases/download/{0}/gamebin-{0}.7z"
GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")
DOWNLOAD_TIMEOUT = (30, 300)
COPY_BUFFER_SIZE = 1024 * 1024


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
    expected = Path(__file__).resolve().parents[4]
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


def download_release_asset(url: str, destination: Path) -> bool:
    """Download one release asset; return False only for HTTP 404."""
    try:
        with requests.get(url, stream=True, allow_redirects=True, timeout=DOWNLOAD_TIMEOUT) as response:
            if response.status_code == 404:
                return False
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


def extract_archive(root: Path, archive: Path, destination: Path) -> None:
    """Extract a trusted release archive into an isolated temporary directory."""
    destination.mkdir(parents=True, exist_ok=True)
    run_command(
        ["7z", "x", str(archive), f"-o{destination}", "-y"],
        root,
        label=f"extracting {archive.name}",
    )


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


def prepare(root: Path, requested: str) -> dict:
    """Prepare configured binaries and return a summary."""
    versions = load_versions(root / "download.yaml")
    gamever = select_version(requested, versions)
    try:
        config_path = resolve_analysis_config(gamever, repo_root=root)
    except AnalysisConfigError as exc:
        raise InitGamebinError(str(exc)) from exc
    source = "existing local binaries"
    copied = skipped = 0
    if not check_binaries(root, gamever, config_path):
        with tempfile.TemporaryDirectory(prefix=f"init-gamebin-{gamever}-") as temp_dir:
            temporary = Path(temp_dir)
            archive = temporary / f"gamebin-{gamever}.7z"
            if download_release_asset(RELEASE_URL.format(gamever), archive):
                extracted = temporary / "extracted"
                extract_archive(root, archive, extracted)
                copied, skipped = merge_archive_bin(extracted, root / "bin", gamever)
                source = "release archive"
            else:
                run_depot_fallback(root, gamever, config_path)
                source = "Steam depot fallback"
    if not check_binaries(root, gamever, config_path):
        raise InitGamebinError(f"configured binaries are still incomplete for GAMEVER {gamever}")
    return {
        "gamever": gamever,
        "source": source,
        "copied": copied,
        "skipped": skipped,
    }


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
    prepare_parser = commands.add_parser("prepare", help="Prepare configured binaries")
    prepare_parser.add_argument("gamever", help="Exact GAMEVER from download.yaml, or latest")
    args = parser.parse_args(argv)
    try:
        root = repository_root()
        if args.command == "versions":
            print_versions(load_versions(root / "download.yaml"))
        else:
            result = prepare(root, args.gamever)
            print(f"Selected GAMEVER: {result['gamever']}")
            print(f"Binary source: {result['source']}")
            print(f"Archive merge: {result['copied']} copied, {result['skipped']} skipped")
    except InitGamebinError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

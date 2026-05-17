#!/usr/bin/env python3
"""Discover new CS2 depot manifests and append download.yaml entries."""

import argparse
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError
from ruamel.yaml.scalarstring import DoubleQuotedScalarString


DEFAULT_CONFIG_FILE = "download.yaml"
DEFAULT_DEPOT_DIR = "cs2_depot"
DEFAULT_APP_ID = "730"
DEFAULT_OS = "all-platform"
STEAM_INF_PATH = r"game\csgo\steam.inf"
DEFAULT_BRANCH_DEPOTS = ("2347771", "2347773")


class BumpError(Exception):
    """Raised when bump discovery or persistence fails."""


def patch_version_to_tag(patch_version: str) -> str:
    """Convert a four-part CS2 PatchVersion to the download tag."""
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", patch_version):
        raise BumpError(f"Invalid PatchVersion: {patch_version}")
    return patch_version.replace(".", "")


def find_manifest_id(depot_dir: Path, depot: str) -> str:
    """Find exactly one manifest id for a depot in an isolated directory."""
    matches = sorted(depot_dir.glob("manifest_*.txt"))
    if not matches:
        raise BumpError(f"Manifest file not found for depot {depot}")
    if len(matches) > 1:
        names = ", ".join(path.name for path in matches)
        raise BumpError(f"Multiple manifest files found for depot {depot}: {names}")

    name = matches[0].name
    prefix = f"manifest_{depot}_"
    if not name.startswith(prefix) or not name.endswith(".txt"):
        raise BumpError(f"Unexpected manifest filename for depot {depot}: {name}")
    manifest_id = name[len(prefix) : -len(".txt")]
    if not manifest_id.isdigit():
        raise BumpError(f"Invalid manifest id in filename: {name}")
    return manifest_id


def parse_patch_version(steam_inf_text: str) -> str:
    """Extract PatchVersion from steam.inf text."""
    for raw_line in steam_inf_text.splitlines():
        line = raw_line.strip()
        if line.startswith("PatchVersion="):
            value = line.split("=", 1)[1].strip()
            patch_version_to_tag(value)
            return value
    raise BumpError("PatchVersion not found in steam.inf")


def _append_auth_args(
    command: list[str],
    username: str | None,
    password: str | None,
    remember_password: bool,
) -> None:
    if username:
        command.extend(["-username", username])
    if password:
        command.extend(["-password", password])
    if remember_password:
        command.append("-remember-password")


def _redact_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for part in command:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        redacted.append(part)
        if part == "-password":
            skip_next = True
    return redacted


def run_command(command: list[str]) -> None:
    """Run a subprocess command and let callers normalize errors."""
    print(f"Running: {' '.join(_redact_command(command))}")
    subprocess.run(command, check=True)


def fetch_manifest_id(
    depot: str,
    app: str,
    os_name: str,
    output_dir: Path,
    username: str | None,
    password: str | None,
    remember_password: bool,
) -> str:
    """Run DepotDownloader -manifest-only in an isolated directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "DepotDownloader",
        "-app",
        str(app),
        "-depot",
        str(depot),
        "-os",
        str(os_name),
        "-dir",
        str(output_dir),
    ]
    _append_auth_args(command, username, password, remember_password)
    command.append("-manifest-only")
    run_command(command)
    return find_manifest_id(output_dir, depot)


def download_and_parse_steam_inf(
    manifest_id: str,
    app: str,
    os_name: str,
    depot_dir: Path,
    username: str | None,
    password: str | None,
    remember_password: bool,
) -> str:
    """Download only game\\csgo\\steam.inf from depot 2347770 and parse PatchVersion."""
    depot_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", delete=False, suffix=".txt"
    ) as handle:
        handle.write(f"{STEAM_INF_PATH}\n")
        filelist_path = Path(handle.name)
    try:
        command = [
            "DepotDownloader",
            "-app",
            str(app),
            "-depot",
            "2347770",
            "-os",
            str(os_name),
            "-dir",
            str(depot_dir),
            "-manifest",
            str(manifest_id),
            "-filelist",
            str(filelist_path),
        ]
        _append_auth_args(command, username, password, remember_password)
        run_command(command)
    finally:
        filelist_path.unlink(missing_ok=True)

    steam_inf_path = depot_dir / "game" / "csgo" / "steam.inf"
    if not steam_inf_path.is_file():
        raise BumpError(f"steam.inf not found: {steam_inf_path}")
    return parse_patch_version(steam_inf_path.read_text(encoding="utf-8"))


def discover_latest(
    app: str,
    os_name: str,
    depot_dir: Path,
    username: str | None,
    password: str | None,
    remember_password: bool,
) -> tuple[str, dict[str, str]]:
    """Discover PatchVersion and default-branch binary depot manifests."""
    with tempfile.TemporaryDirectory(prefix="cs2-manifests-") as tmp:
        manifest_dir = Path(tmp)
        base_manifest = fetch_manifest_id(
            depot="2347770",
            app=app,
            os_name=os_name,
            output_dir=manifest_dir / "2347770",
            username=username,
            password=password,
            remember_password=remember_password,
        )
        patch_version = download_and_parse_steam_inf(
            manifest_id=base_manifest,
            app=app,
            os_name=os_name,
            depot_dir=depot_dir,
            username=username,
            password=password,
            remember_password=remember_password,
        )
        manifests = {
            depot: fetch_manifest_id(
                depot=depot,
                app=app,
                os_name=os_name,
                output_dir=manifest_dir / depot,
                username=username,
                password=password,
                remember_password=remember_password,
            )
            for depot in DEFAULT_BRANCH_DEPOTS
        }
    return patch_version, manifests


@dataclass(frozen=True)
class BumpPlan:
    """Decision result for the current depot manifests."""

    updated: bool
    tag: str
    patch_version: str
    manifests: dict[str, str]
    repair_tag: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "manifests", dict(self.manifests))


def _default_branch_entries(
    downloads: list[dict[str, Any]], patch_version: str
) -> list[dict[str, Any]]:
    return [
        entry
        for entry in downloads
        if entry.get("name") == patch_version and "branch" not in entry
    ]


def _extract_manifest_pair(manifests: Any, label: str) -> tuple[str, ...]:
    if not isinstance(manifests, dict):
        raise BumpError(f"{label} must contain manifests mapping")

    pair = []
    for depot in DEFAULT_BRANCH_DEPOTS:
        if depot not in manifests:
            raise BumpError(f"{label} missing manifest for depot {depot}")
        pair.append(str(manifests[depot]))
    return tuple(pair)


def _manifest_pair(entry: dict[str, Any]) -> tuple[str, ...]:
    label = f"Download entry {entry.get('tag')}"
    return _extract_manifest_pair(entry.get("manifests"), label)


def _next_suffix_tag(base_tag: str, existing_tags: set[str]) -> str:
    if base_tag not in existing_tags:
        return base_tag
    suffix_code = ord("b")
    while suffix_code <= ord("z"):
        candidate = f"{base_tag}{chr(suffix_code)}"
        if candidate not in existing_tags:
            return candidate
        suffix_code += 1
    raise BumpError(f"No available suffix tag for {base_tag}")


def plan_download_entry(
    downloads: list[dict[str, Any]],
    patch_version: str,
    manifests: dict[str, str],
) -> BumpPlan:
    """Decide whether to append a new default-branch download entry."""
    base_tag = patch_version_to_tag(patch_version)
    existing_tags = {str(entry.get("tag")) for entry in downloads}
    target_pair = _extract_manifest_pair(manifests, "Current manifests")
    matching_entries = _default_branch_entries(downloads, patch_version)

    for entry in matching_entries:
        if _manifest_pair(entry) == target_pair:
            return BumpPlan(
                updated=False,
                tag=str(entry["tag"]),
                patch_version=patch_version,
                manifests=manifests,
            )

    return BumpPlan(
        updated=True,
        tag=_next_suffix_tag(base_tag, existing_tags),
        patch_version=patch_version,
        manifests=manifests,
    )

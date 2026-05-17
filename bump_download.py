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
    matches = sorted(depot_dir.glob(f"manifest_{depot}_*.txt"))
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


@dataclass(frozen=True)
class BumpPlan:
    """Decision result for the current depot manifests."""

    updated: bool
    tag: str
    patch_version: str
    manifests: dict[str, str]
    repair_tag: bool = False


def _default_branch_entries(
    downloads: list[dict[str, Any]], patch_version: str
) -> list[dict[str, Any]]:
    return [
        entry
        for entry in downloads
        if entry.get("name") == patch_version and "branch" not in entry
    ]


def _manifest_pair(entry: dict[str, Any]) -> tuple[str | None, str | None]:
    manifests = entry.get("manifests")
    if not isinstance(manifests, dict):
        raise BumpError(f"Download entry {entry.get('tag')} must contain manifests mapping")
    return str(manifests.get("2347771")), str(manifests.get("2347773"))


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
    target_pair = (str(manifests["2347771"]), str(manifests["2347773"]))
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

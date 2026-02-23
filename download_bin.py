#!/usr/bin/env python3
"""
Binary Download Script for CS2_VibeSignatures

Downloads CS2 binary files from AlliedMods SourceBins based on entries in config.yaml.

Usage:
    python download_bin.py -gamever=<version> [-bindir=bin] [-platform=windows|linux] [-sourcebinsurl=URL]

    -gamever: Game version subdirectory name (required)
    -bindir: Directory to save downloaded binaries (default: bin)
    -platform: Filter by platform (windows or linux). If not specified, downloads both.
    -sourcebinsurl: Base URL for SourceBins (default: https://sourcebins.alliedmods.net/cs2)

Requirements:
    uv sync
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import yaml
    import requests
except ImportError as e:
    print(f"Error: Missing required dependency: {e.name}")
    print("Please install required dependencies with: uv sync")
    sys.exit(1)


DEFAULT_SOURCEBINS_URL = "https://sourcebins.alliedmods.net/cs2"
DEFAULT_BIN_DIR = "bin"
DEFAULT_CONFIG_FILE = "config.yaml"


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Download CS2 binary files from AlliedMods SourceBins"
    )
    parser.add_argument(
        "-bindir",
        default=DEFAULT_BIN_DIR,
        help=f"Directory to save downloaded binaries (default: {DEFAULT_BIN_DIR})"
    )
    parser.add_argument(
        "-gamever",
        required=True,
        help="Game version subdirectory name (required)"
    )
    parser.add_argument(
        "-platform",
        choices=["windows", "linux"],
        default=None,
        help="Filter by platform (windows or linux). If not specified, downloads both."
    )
    parser.add_argument(
        "-sourcebinsurl",
        default=DEFAULT_SOURCEBINS_URL,
        help=f"Base URL for SourceBins (default: {DEFAULT_SOURCEBINS_URL})"
    )
    parser.add_argument(
        "-config",
        default=DEFAULT_CONFIG_FILE,
        help=f"Path to config.yaml file (default: {DEFAULT_CONFIG_FILE})"
    )

    args = parser.parse_args()

    # Remove trailing slash from URL
    args.sourcebinsurl = args.sourcebinsurl.rstrip("/")

    return args


def parse_config(config_path):
    """
    Parse the config.yaml file and extract module entries.

    Args:
        config_path: Path to the config.yaml file

    Returns:
        List of dictionaries containing module data
    """
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    modules = []
    for module in config.get("modules", []):
        name = module.get("name")
        path_windows = module.get("path_windows")
        path_linux = module.get("path_linux")

        if not name:
            print(f"  Warning: Skipping module without name")
            continue

        modules.append({
            "name": name,
            "path_windows": path_windows,
            "path_linux": path_linux
        })

    return modules


def build_download_url(base_url, path):
    """
    Build the download URL for a binary file.

    Args:
        base_url: Base URL for SourceBins
        path: File path within SourceBins

    Returns:
        Full download URL
    """
    return f"{base_url}/{path}"


def download_file(url, target_path):
    """
    Download a file from URL to target path.

    Downloads the entire file content to memory first, then writes to disk
    to prevent corrupted files from incomplete downloads.

    Args:
        url: Download URL
        target_path: Local path to save the file

    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"  Downloading: {url}")
        response = requests.get(url, timeout=120)
        response.raise_for_status()

        # Cache content in memory first
        content = response.content

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        # Write to file only after full download completed
        with open(target_path, "wb") as f:
            f.write(content)

        print(f"  Saved to: {target_path}")
        return True

    except requests.exceptions.RequestException as e:
        print(f"  Download failed: {e}")
        return False


def process_module(module, bin_dir, gamever, platform_filter, base_url):
    """
    Process a single module: download binary files for specified platforms.

    Args:
        module: Dictionary with module info (name, path_windows, path_linux)
        bin_dir: Base directory to save binaries
        gamever: Game version subdirectory name
        platform_filter: Optional platform filter (windows, linux, or None for both)
        base_url: Base URL for SourceBins

    Returns:
        Tuple of (success_count, fail_count)
    """
    name = module["name"]
    success_count = 0
    fail_count = 0

    platforms = []
    if platform_filter:
        platforms = [platform_filter]
    else:
        platforms = ["windows", "linux"]

    for platform in platforms:
        path_key = f"path_{platform}"
        path = module.get(path_key)

        if not path:
            print(f"  Skipping {name} ({platform}): no path defined")
            continue

        # Extract filename from path
        filename = Path(path).name

        # Build target path: {bin_dir}/{gamever}/{module_name}/{filename}
        target_dir = os.path.join(bin_dir, gamever, name)
        target_path = os.path.join(target_dir, filename)

        print(f"\nProcessing: {name} ({platform})")

        # Skip if already exists
        if os.path.exists(target_path):
            print(f"  [SKIP] File already exists, skipping download: {target_path}")
            success_count += 1
            continue

        # Download file
        url = build_download_url(base_url, path)
        if download_file(url, target_path):
            success_count += 1
        else:
            fail_count += 1

    return success_count, fail_count


def main():
    """Main entry point."""
    args = parse_args()

    config_path = args.config
    bin_dir = args.bindir
    gamever = args.gamever
    platform_filter = args.platform
    base_url = args.sourcebinsurl

    # Validate config file exists
    if not os.path.exists(config_path):
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)

    # Create bin directory if needed
    os.makedirs(bin_dir, exist_ok=True)

    print(f"Config file: {config_path}")
    print(f"Binary directory: {bin_dir}")
    print(f"Game version: {gamever}")
    print(f"Source URL: {base_url}")
    if platform_filter:
        print(f"Platform filter: {platform_filter}")

    # Parse config
    print("\nParsing config...")
    modules = parse_config(config_path)
    print(f"Found {len(modules)} modules to process")

    if not modules:
        print("No modules found in config.")
        sys.exit(0)

    # Process each module
    total_success = 0
    total_fail = 0

    for module in modules:
        success, fail = process_module(module, bin_dir, gamever, platform_filter, base_url)
        total_success += success
        total_fail += fail

    # Summary
    print(f"\n{'='*50}")
    print(f"Completed: {total_success} successful, {total_fail} failed")

    if total_fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

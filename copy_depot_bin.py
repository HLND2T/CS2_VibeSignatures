#!/usr/bin/env python3
"""
Depot Binary Copy Script for CS2_VibeSignatures

Copies CS2 binary files from a local Steam depot directory based on entries in config.yaml.

Usage:
    python copy_depot_bin.py -gamever=<version> [-bindir=bin] [-platform=windows|linux] [-depotdir=cs2_depot]

    -gamever: Game version subdirectory name (required)
    -bindir: Directory to save copied binaries (default: bin)
    -platform: Filter by platform (windows or linux). If not specified, copies both.
    -depotdir: Local depot root directory (default: cs2_depot)

Requirements:
    uv sync
"""

import argparse
import os
import shutil
import sys
from pathlib import Path

try:
    import yaml
except ImportError as e:
    print(f"Error: Missing required dependency: {e.name}")
    print("Please install required dependencies with: uv sync")
    sys.exit(1)


DEFAULT_DEPOT_DIR = "cs2_depot"
DEFAULT_BIN_DIR = "bin"
DEFAULT_CONFIG_FILE = "config.yaml"


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Copy CS2 binary files from a local Steam depot directory"
    )
    parser.add_argument(
        "-bindir",
        default=DEFAULT_BIN_DIR,
        help=f"Directory to save copied binaries (default: {DEFAULT_BIN_DIR})"
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
        help="Filter by platform (windows or linux). If not specified, copies both."
    )
    parser.add_argument(
        "-depotdir",
        default=DEFAULT_DEPOT_DIR,
        help=f"Local depot root directory (default: {DEFAULT_DEPOT_DIR})"
    )
    parser.add_argument(
        "-config",
        default=DEFAULT_CONFIG_FILE,
        help=f"Path to config.yaml file (default: {DEFAULT_CONFIG_FILE})"
    )

    return parser.parse_args()


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


def build_source_path(depot_dir, platform, path):
    """
    Build the source file path within the depot directory.

    Args:
        depot_dir: Root depot directory
        platform: Platform name (windows or linux)
        path: Relative file path within the platform depot

    Returns:
        Full source file path
    """
    return os.path.join(depot_dir, platform, path)


def copy_file(source_path, target_path):
    """
    Copy a file from source path to target path.

    Args:
        source_path: Local source file path
        target_path: Local target file path

    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"  Copying: {source_path}")

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        shutil.copy2(source_path, target_path)

        print(f"  Saved to: {target_path}")
        return True

    except OSError as e:
        print(f"  Copy failed: {e}")
        return False


def process_module(module, bin_dir, gamever, platform_filter, depot_dir):
    """
    Process a single module: copy binary files for specified platforms.

    Args:
        module: Dictionary with module info (name, path_windows, path_linux)
        bin_dir: Base directory to save binaries
        gamever: Game version subdirectory name
        platform_filter: Optional platform filter (windows, linux, or None for both)
        depot_dir: Root depot directory

    Returns:
        Tuple of (success_count, fail_count)
    """
    name = module["name"]
    success_count = 0
    fail_count = 0

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
            print(f"  [SKIP] File already exists, skipping copy: {target_path}")
            success_count += 1
            continue

        # Build source path and verify it exists
        source_path = build_source_path(depot_dir, platform, path)
        if not os.path.exists(source_path):
            print(f"  [ERROR] Source file not found in depot: {source_path}")
            fail_count += 1
            continue

        # Copy file
        if copy_file(source_path, target_path):
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
    depot_dir = args.depotdir

    # Validate config file exists
    if not os.path.exists(config_path):
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)

    # Validate depot directory exists
    if not os.path.isdir(depot_dir):
        print(f"Error: Depot directory not found: {depot_dir}")
        sys.exit(1)

    # Create bin directory if needed
    os.makedirs(bin_dir, exist_ok=True)

    print(f"Config file: {config_path}")
    print(f"Binary directory: {bin_dir}")
    print(f"Game version: {gamever}")
    print(f"Depot directory: {depot_dir}")
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
        success, fail = process_module(module, bin_dir, gamever, platform_filter, depot_dir)
        total_success += success
        total_fail += fail

    # Summary
    print(f"\n{'='*50}")
    print(f"Completed: {total_success} successful, {total_fail} failed")

    if total_fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

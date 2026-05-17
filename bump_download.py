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


def _yaml() -> YAML:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    return yaml


def load_config(config_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load download.yaml while preserving comments for later writeback."""
    if not config_path.is_file():
        raise BumpError(f"Config file not found: {config_path}")
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            data = _yaml().load(handle) or {}
    except YAMLError as exc:
        raise BumpError(f"Invalid YAML in config file: {config_path}") from exc
    except OSError as exc:
        raise BumpError(f"Failed to read config file: {config_path}") from exc

    if not isinstance(data, dict):
        raise BumpError("Config root must be a mapping/object")
    downloads = data.get("downloads")
    if not isinstance(downloads, list):
        raise BumpError("Config field 'downloads' must be a list")

    seen_tags: set[str] = set()
    for index, entry in enumerate(downloads):
        if not isinstance(entry, dict):
            raise BumpError(f"downloads[{index}] must be a mapping/object")
        tag = entry.get("tag")
        if not tag:
            raise BumpError(f"downloads[{index}] missing tag")
        if str(tag) in seen_tags:
            raise BumpError(f"Duplicate tag in downloads config: {tag}")
        seen_tags.add(str(tag))
        if "name" not in entry:
            raise BumpError(f"downloads[{index}] missing name")
        if not isinstance(entry.get("manifests"), dict):
            raise BumpError(f"downloads[{index}] missing manifests mapping")
    return data, downloads


def append_download_entry(downloads: list[dict[str, Any]], plan: BumpPlan) -> None:
    """Append a default-branch download entry."""
    entry = CommentedMap()
    entry["tag"] = DoubleQuotedScalarString(plan.tag)
    entry["name"] = plan.patch_version
    manifests = CommentedMap()
    manifests[DoubleQuotedScalarString("2347771")] = DoubleQuotedScalarString(
        str(plan.manifests["2347771"])
    )
    manifests[DoubleQuotedScalarString("2347773")] = DoubleQuotedScalarString(
        str(plan.manifests["2347773"])
    )
    entry["manifests"] = manifests
    downloads.append(entry)


def save_config(config_path: Path, data: dict[str, Any]) -> None:
    """Save download.yaml with ruamel comment preservation."""
    with config_path.open("w", encoding="utf-8") as handle:
        _yaml().dump(data, handle)


def write_github_output(output_path: Path | None, updated: bool, tag: str | None) -> None:
    """Write GitHub Actions step outputs when requested."""
    if output_path is None:
        return
    lines = [f"updated={'true' if updated else 'false'}"]
    if updated and tag:
        lines.append(f"tag={tag}")
    with output_path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def git_output(command: list[str]) -> str:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    return completed.stdout.strip()


def local_tag_exists(tag: str) -> bool:
    completed = subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"],
        check=False,
    )
    return completed.returncode == 0


def remote_tag_exists(tag: str) -> bool:
    completed = subprocess.run(
        ["git", "ls-remote", "--exit-code", "--tags", "origin", tag],
        check=False,
    )
    return completed.returncode == 0


def ensure_clean_worktree() -> None:
    status = git_output(["git", "status", "--porcelain"])
    if status:
        raise BumpError("Working tree has uncommitted changes")


def create_commit_and_tag(config_path: Path, tag: str, patch_version: str) -> None:
    subprocess.run(["git", "add", str(config_path)], check=True)
    subprocess.run(
        ["git", "commit", "-m", f"chore(download): 更新 {patch_version} 下载清单"],
        check=True,
    )
    subprocess.run(["git", "tag", tag], check=True)


def create_repair_tag(tag: str) -> None:
    if not local_tag_exists(tag):
        subprocess.run(["git", "tag", tag], check=True)


def ensure_local_tag_matches_head(tag: str) -> None:
    if not local_tag_exists(tag):
        return
    tag_commit = git_output(["git", "rev-list", "-n", "1", tag])
    head_commit = git_output(["git", "rev-parse", "HEAD"])
    if tag_commit != head_commit:
        raise BumpError(f"Local tag {tag} does not point to HEAD")


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


def plan_tag_repair(
    downloads: list[dict[str, Any]],
    patch_version: str,
    manifests: dict[str, str],
) -> BumpPlan | None:
    """Return a repair plan when config has the entry but remote tag is missing."""
    no_update_plan = plan_download_entry(downloads, patch_version, manifests)
    if no_update_plan.updated:
        return None
    if remote_tag_exists(no_update_plan.tag):
        return None
    return BumpPlan(
        updated=True,
        tag=no_update_plan.tag,
        patch_version=patch_version,
        manifests=manifests,
        repair_tag=True,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Discover CS2 default-branch depot manifests and update download.yaml."
    )
    parser.add_argument("-config", default=DEFAULT_CONFIG_FILE)
    parser.add_argument("-depotdir", default=DEFAULT_DEPOT_DIR)
    parser.add_argument("-app", default=DEFAULT_APP_ID)
    parser.add_argument("-os", default=DEFAULT_OS)
    parser.add_argument("-username", default=None)
    parser.add_argument("-password", default=None)
    parser.add_argument("-remember-password", action="store_true")
    parser.add_argument("-github-output", default=None)
    parser.add_argument("-dry-run", action="store_true")
    return parser.parse_args()


def run(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    depot_dir = Path(args.depotdir)
    patch_version, manifests = discover_latest(
        app=args.app,
        os_name=args.os,
        depot_dir=depot_dir,
        username=args.username,
        password=args.password,
        remember_password=args.remember_password,
    )
    data, downloads = load_config(config_path)
    plan = plan_download_entry(downloads, patch_version, manifests)
    output_path = Path(args.github_output) if args.github_output else None

    if args.dry_run:
        if not plan.updated:
            print(f"No update for {patch_version}: {manifests}")
            write_github_output(output_path, updated=False, tag=None)
        else:
            print(f"Would update download.yaml with tag {plan.tag}: {manifests}")
            write_github_output(output_path, updated=True, tag=plan.tag)
        return 0

    if not plan.updated:
        repair_plan = plan_tag_repair(downloads, patch_version, manifests)
        if repair_plan is None:
            print(f"No update for {patch_version}: {manifests}")
            write_github_output(output_path, updated=False, tag=None)
            return 0
        plan = repair_plan

    ensure_clean_worktree()
    if plan.repair_tag:
        ensure_local_tag_matches_head(plan.tag)
        create_repair_tag(plan.tag)
    else:
        if local_tag_exists(plan.tag) or remote_tag_exists(plan.tag):
            raise BumpError(f"Tag already exists: {plan.tag}")
        append_download_entry(downloads, plan)
        save_config(config_path, data)
        create_commit_and_tag(config_path, plan.tag, plan.patch_version)
    write_github_output(output_path, updated=True, tag=plan.tag)
    print(f"Prepared bump tag {plan.tag} for {patch_version}")
    return 0


def main() -> int:
    args = parse_args()
    try:
        return run(args)
    except BumpError as exc:
        print(f"Error: {exc}")
        return 1
    except FileNotFoundError:
        print("Error: DepotDownloader executable not found in PATH")
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"Error: command failed with exit code {exc.returncode}")
        return exc.returncode or 1


if __name__ == "__main__":
    sys.exit(main())

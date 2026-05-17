# Bump Download Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an automated CS2 default-branch version discovery flow that appends `download.yaml`, creates a local commit/tag, and lets GitHub Actions push them to `main`.

**Architecture:** Add `bump_download.py` as a focused Python CLI with small testable units for DepotDownloader calls, manifest parsing, `steam.inf` parsing, tag selection, comment-preserving YAML append, git operations, and GitHub Actions output. Add `tests/test_bump_download.py` for unit-level behavior with mocked subprocess calls, update dependencies for `ruamel.yaml`, and add a self-hosted Windows workflow that runs every 6 hours and only pushes when the script reports an update.

**Tech Stack:** Python 3.10, `argparse`, `subprocess`, `tempfile`, `pathlib`, `ruamel.yaml`, `unittest`, `unittest.mock`, GitHub Actions YAML, PowerShell, `uv`, DepotDownloader, Git

---

## File Map

- Create: `bump_download.py`
  Responsibility: discover latest CS2 default public branch manifests, decide whether a new `download.yaml` entry or tag repair is needed, preserve YAML comments while appending, create local commit/tag, and write GitHub Actions outputs.
- Create: `tests/test_bump_download.py`
  Responsibility: cover tag/version logic, manifest filename parsing, `steam.inf` parsing, DepotDownloader command construction, dry-run behavior, YAML comment preservation, git command order, GitHub output, and tag repair mode without touching Steam.
- Modify: `pyproject.toml`
  Responsibility: add `ruamel.yaml` to project dependencies.
- Modify: `uv.lock`
  Responsibility: lock the new dependency added through `uv`.
- Create: `.github/workflows/bump-download.yml`
  Responsibility: schedule the bump job every 6 hours, run on self-hosted Windows with `win64` environment secrets, call `bump_download.py`, and push `main` plus the reported tag only when needed.
- Reference: `docs/superpowers/specs/2026-05-17-bump-download-design.md`
  Responsibility: accepted design and behavior contract.
- Reference: `download_depot.py`
  Responsibility: existing CLI style for DepotDownloader subprocess arguments, config errors, and credential passthrough.
- Reference: `tests/test_download_depot.py`
  Responsibility: existing `unittest` and `unittest.mock` style.

## Validation Notes

- This plan includes exact local validation commands for the implementation worker. The repository-level user instruction says not to run tests/build commands unless explicitly requested; get confirmation before executing them if that instruction is still active.
- Unit tests must mock `subprocess.run`; they must not call Steam or DepotDownloader.
- A full end-to-end workflow run requires the real self-hosted Windows runner and GitHub secrets, so local verification stops at unit tests and YAML syntax/load checks.
- Do not commit or push runtime-created game version tags while implementing. Git tag creation must be mocked in tests.

### Task 1: Add Dependency And Skeleton Module

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `bump_download.py`
- Create: `tests/test_bump_download.py`

- [ ] **Step 1: Add `ruamel.yaml` to project dependencies**

Run:

```powershell
uv add ruamel.yaml
```

Expected:

```text
pyproject.toml and uv.lock are updated
```

Implementation notes:

- `pyproject.toml` should contain `"ruamel.yaml"` in `[project].dependencies`.
- Let `uv` update `uv.lock`; do not hand-edit the lockfile.

- [ ] **Step 2: Create the initial failing import test**

Add `tests/test_bump_download.py`:

```python
import unittest

import bump_download


class TestBumpDownload(unittest.TestCase):
    def test_patch_version_to_tag_removes_dots(self) -> None:
        self.assertEqual("14161", bump_download.patch_version_to_tag("1.41.6.1"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run the focused test and verify it fails before the module exists**

Run:

```powershell
uv run python -m unittest tests.test_bump_download -v
```

Expected:

```text
ModuleNotFoundError: No module named 'bump_download'
```

- [ ] **Step 4: Create `bump_download.py` with constants, error type, and version conversion**

Add:

```python
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
```

- [ ] **Step 5: Run the focused test and verify it passes**

Run:

```powershell
uv run python -m unittest tests.test_bump_download -v
```

Expected:

```text
OK
```

- [ ] **Step 6: Commit dependency and skeleton**

Run:

```powershell
git add pyproject.toml uv.lock bump_download.py tests/test_bump_download.py
git commit -m "feat(download): 添加自动登记脚本骨架"
```

### Task 2: Implement Pure Parsing And Tag Decision Logic

**Files:**
- Modify: `bump_download.py`
- Modify: `tests/test_bump_download.py`

- [ ] **Step 1: Add failing tests for manifest filename and steam.inf parsing**

Append tests:

```python
from pathlib import Path
import tempfile


class TestBumpDownload(unittest.TestCase):
    # keep existing tests

    def test_parse_manifest_id_from_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest_2347771_6999933698852825529.txt"
            path.write_text("Content Manifest for Depot 2347771\n", encoding="utf-8")

            self.assertEqual(
                "6999933698852825529",
                bump_download.find_manifest_id(Path(tmp), "2347771"),
            )

    def test_parse_patch_version_from_steam_inf(self) -> None:
        text = "\n".join(
            [
                "ClientVersion=2000777",
                "ServerVersion=2000777",
                "PatchVersion=1.41.6.1",
                "ProductName=cs2",
            ]
        )

        self.assertEqual("1.41.6.1", bump_download.parse_patch_version(text))
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```powershell
uv run python -m unittest tests.test_bump_download -v
```

Expected:

```text
AttributeError for find_manifest_id and parse_patch_version
```

- [ ] **Step 3: Implement isolated manifest and steam.inf parsing**

Add to `bump_download.py`:

```python
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
```

- [ ] **Step 4: Add failing tests for tag decision cases**

Append tests:

```python
    def test_plan_new_entry_for_new_patch_version(self) -> None:
        downloads = [
            {"tag": "14160", "name": "1.41.6.0", "manifests": {"2347771": "1", "2347773": "2"}}
        ]

        plan = bump_download.plan_download_entry(
            downloads,
            patch_version="1.41.6.1",
            manifests={"2347771": "11", "2347773": "22"},
        )

        self.assertTrue(plan.updated)
        self.assertEqual("14161", plan.tag)

    def test_plan_suffix_for_same_version_new_manifests(self) -> None:
        downloads = [
            {"tag": "14161", "name": "1.41.6.1", "manifests": {"2347771": "11", "2347773": "22"}},
            {"tag": "14161b", "name": "1.41.6.1", "manifests": {"2347771": "33", "2347773": "44"}},
        ]

        plan = bump_download.plan_download_entry(
            downloads,
            patch_version="1.41.6.1",
            manifests={"2347771": "55", "2347773": "66"},
        )

        self.assertTrue(plan.updated)
        self.assertEqual("14161c", plan.tag)

    def test_plan_no_update_for_existing_manifest_pair(self) -> None:
        downloads = [
            {"tag": "14161", "name": "1.41.6.1", "manifests": {"2347771": "11", "2347773": "22"}}
        ]

        plan = bump_download.plan_download_entry(
            downloads,
            patch_version="1.41.6.1",
            manifests={"2347771": "11", "2347773": "22"},
        )

        self.assertFalse(plan.updated)
        self.assertEqual("14161", plan.tag)

    def test_branch_entries_do_not_dedupe_default_branch(self) -> None:
        downloads = [
            {
                "tag": "14161",
                "name": "1.41.6.1",
                "branch": "animgraph_2_beta",
                "manifests": {"2347771": "11", "2347773": "22"},
            }
        ]

        plan = bump_download.plan_download_entry(
            downloads,
            patch_version="1.41.6.1",
            manifests={"2347771": "11", "2347773": "22"},
        )

        self.assertTrue(plan.updated)
        self.assertEqual("14161b", plan.tag)
```

Implementation note:

- Entries with `branch` do not count as default-branch manifest matches.
- Tags are still globally unique across the whole file. If a branch entry already uses the base tag, the new default-branch entry must use the next available suffix.

- [ ] **Step 5: Implement `BumpPlan` and tag decision logic**

Add:

```python
@dataclass(frozen=True)
class BumpPlan:
    """Decision result for the current depot manifests."""

    updated: bool
    tag: str
    patch_version: str
    manifests: dict[str, str]
    repair_tag: bool = False


def _default_branch_entries(downloads: list[dict[str, Any]], patch_version: str) -> list[dict[str, Any]]:
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
```

- [ ] **Step 6: Run pure logic tests**

Run:

```powershell
uv run python -m unittest tests.test_bump_download -v
```

Expected:

```text
OK
```

- [ ] **Step 7: Commit parsing and decision logic**

Run:

```powershell
git add bump_download.py tests/test_bump_download.py
git commit -m "feat(download): 计算自动登记标签"
```

### Task 3: Implement DepotDownloader Command Layer

**Files:**
- Modify: `bump_download.py`
- Modify: `tests/test_bump_download.py`

- [ ] **Step 1: Add failing tests for command construction**

Append tests:

```python
from unittest.mock import call, patch


class TestBumpDownload(unittest.TestCase):
    # keep existing tests

    @patch("bump_download.subprocess.run")
    def test_fetch_manifest_only_uses_isolated_directory(self, mock_run) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            isolated = Path(tmp) / "manifest"
            isolated.mkdir()
            (isolated / "manifest_2347771_12345.txt").write_text("", encoding="utf-8")

            manifest_id = bump_download.fetch_manifest_id(
                depot="2347771",
                app="730",
                os_name="all-platform",
                output_dir=isolated,
                username="user",
                password="pass",
                remember_password=True,
            )

        self.assertEqual("12345", manifest_id)
        self.assertEqual(
            [
                "DepotDownloader",
                "-app",
                "730",
                "-depot",
                "2347771",
                "-os",
                "all-platform",
                "-dir",
                str(isolated),
                "-username",
                "user",
                "-password",
                "pass",
                "-remember-password",
                "-manifest-only",
            ],
            mock_run.call_args.args[0],
        )

    @patch("bump_download.subprocess.run")
    def test_download_steam_inf_uses_manifest_and_filelist(self, mock_run) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            depot_dir = Path(tmp)
            steam_inf = depot_dir / "game" / "csgo" / "steam.inf"
            steam_inf.parent.mkdir(parents=True)
            steam_inf.write_text("PatchVersion=1.41.6.1\n", encoding="utf-8")

            patch_version = bump_download.download_and_parse_steam_inf(
                manifest_id="999",
                app="730",
                os_name="all-platform",
                depot_dir=depot_dir,
                username=None,
                password=None,
                remember_password=False,
            )

        self.assertEqual("1.41.6.1", patch_version)
        command = mock_run.call_args.args[0]
        self.assertIn("-manifest", command)
        self.assertIn("999", command)
        self.assertIn("-filelist", command)
```

- [ ] **Step 2: Implement DepotDownloader helpers**

Add:

```python
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


def run_command(command: list[str]) -> None:
    """Run a subprocess command and let callers normalize errors."""
    print(f"Running: {' '.join(command)}")
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
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".txt") as handle:
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
```

- [ ] **Step 3: Add the orchestration helper for discovery**

Add:

```python
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
```

- [ ] **Step 4: Run command-layer tests**

Run:

```powershell
uv run python -m unittest tests.test_bump_download -v
```

Expected:

```text
OK
```

- [ ] **Step 5: Commit command layer**

Run:

```powershell
git add bump_download.py tests/test_bump_download.py
git commit -m "feat(download): 查询 depot manifest"
```

### Task 4: Implement YAML Loading, Comment-Preserving Append, And Outputs

**Files:**
- Modify: `bump_download.py`
- Modify: `tests/test_bump_download.py`

- [ ] **Step 1: Add failing tests for YAML load, append, and comment preservation**

Append tests:

```python
    def test_append_download_entry_preserves_existing_inline_comment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            config.write_text(
                "\n".join(
                    [
                        "downloads:",
                        '  - tag: "14160" # keep me',
                        "    name: 1.41.6.0",
                        "    manifests:",
                        '      "2347771": "1"',
                        '      "2347773": "2"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            data, downloads = bump_download.load_config(config)
            bump_download.append_download_entry(
                downloads,
                bump_download.BumpPlan(
                    updated=True,
                    tag="14161",
                    patch_version="1.41.6.1",
                    manifests={"2347771": "11", "2347773": "22"},
                ),
            )
            bump_download.save_config(config, data)

            text = config.read_text(encoding="utf-8")

        self.assertIn("# keep me", text)
        self.assertIn('tag: "14161"', text)
        self.assertIn('name: 1.41.6.1', text)

    def test_write_github_output_for_update_and_no_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out.txt"
            bump_download.write_github_output(output, updated=True, tag="14161")
            self.assertEqual("updated=true\ntag=14161\n", output.read_text(encoding="utf-8"))

            bump_download.write_github_output(output, updated=False, tag=None)
            self.assertEqual("updated=false\n", output.read_text(encoding="utf-8"))

    def test_load_config_wraps_invalid_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            config.write_text("downloads:\n  - tag: [broken\n", encoding="utf-8")

            with self.assertRaises(bump_download.BumpError):
                bump_download.load_config(config)
```

- [ ] **Step 2: Implement `ruamel.yaml` load/save and append**

Add:

```python
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
    manifests[DoubleQuotedScalarString("2347771")] = DoubleQuotedScalarString(str(plan.manifests["2347771"]))
    manifests[DoubleQuotedScalarString("2347773")] = DoubleQuotedScalarString(str(plan.manifests["2347773"]))
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
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
```

- [ ] **Step 3: Run YAML/output tests**

Run:

```powershell
uv run python -m unittest tests.test_bump_download -v
```

Expected:

```text
OK
```

- [ ] **Step 4: Commit YAML layer**

Run:

```powershell
git add bump_download.py tests/test_bump_download.py
git commit -m "feat(download): 保留注释追加下载清单"
```

### Task 5: Implement Git Operations, Tag Repair, CLI, And Main Flow

**Files:**
- Modify: `bump_download.py`
- Modify: `tests/test_bump_download.py`

- [ ] **Step 1: Add failing tests for dry-run and git command order**

Append tests:

```python
    @patch("bump_download.subprocess.run")
    def test_create_commit_and_tag_runs_expected_git_commands(self, mock_run) -> None:
        bump_download.create_commit_and_tag(
            config_path=Path("download.yaml"),
            tag="14161",
            patch_version="1.41.6.1",
        )

        self.assertEqual(
            [
                call(["git", "add", "download.yaml"], check=True),
                call(["git", "commit", "-m", "chore(download): 更新 1.41.6.1 下载清单"], check=True),
                call(["git", "tag", "14161"], check=True),
            ],
            mock_run.call_args_list,
        )

    @patch("bump_download.create_commit_and_tag")
    @patch("bump_download.discover_latest", return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}))
    def test_dry_run_does_not_commit(self, _discover, commit) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            config.write_text(
                "downloads:\n"
                '  - tag: "14160"\n'
                "    name: 1.41.6.0\n"
                "    manifests:\n"
                '      "2347771": "1"\n'
                '      "2347773": "2"\n',
                encoding="utf-8",
            )
            args = argparse.Namespace(
                config=str(config),
                depotdir=str(Path(tmp) / "depot"),
                app="730",
                os="all-platform",
                username=None,
                password=None,
                remember_password=False,
                github_output=None,
                dry_run=True,
            )

            self.assertEqual(0, bump_download.run(args))

        commit.assert_not_called()

    @patch("bump_download.remote_tag_exists")
    @patch("bump_download.local_tag_exists")
    @patch("bump_download.create_commit_and_tag")
    @patch("bump_download.discover_latest", return_value=("1.41.6.1", {"2347771": "11", "2347773": "22"}))
    def test_dry_run_existing_entry_does_not_check_git(
        self,
        _discover,
        commit,
        local_tag_exists,
        remote_tag_exists,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "download.yaml"
            config.write_text(
                "downloads:\n"
                '  - tag: "14161"\n'
                "    name: 1.41.6.1\n"
                "    manifests:\n"
                '      "2347771": "11"\n'
                '      "2347773": "22"\n',
                encoding="utf-8",
            )
            args = argparse.Namespace(
                config=str(config),
                depotdir=str(Path(tmp) / "depot"),
                app="730",
                os="all-platform",
                username=None,
                password=None,
                remember_password=False,
                github_output=None,
                dry_run=True,
            )

            self.assertEqual(0, bump_download.run(args))

        commit.assert_not_called()
        local_tag_exists.assert_not_called()
        remote_tag_exists.assert_not_called()
```

Implementation note:

- Merge these snippets into the existing `TestBumpDownload` class. Keep imports consolidated at the top of `tests/test_bump_download.py`; this task needs `argparse`, `call`, and `patch` in addition to the imports from earlier tasks.
- `-dry-run` must not call any git helper, including `git ls-remote`. It may discover DepotDownloader state because the purpose of dry-run is to preview what the current Steam manifests would do.

- [ ] **Step 2: Add failing tests for tag repair mode**

Append:

```python
    @patch("bump_download.remote_tag_exists", return_value=False)
    @patch("bump_download.local_tag_exists", return_value=False)
    def test_tag_repair_when_entry_exists_but_remote_tag_missing(self, _local, _remote) -> None:
        downloads = [
            {"tag": "14161", "name": "1.41.6.1", "manifests": {"2347771": "11", "2347773": "22"}}
        ]

        plan = bump_download.plan_tag_repair(
            downloads,
            patch_version="1.41.6.1",
            manifests={"2347771": "11", "2347773": "22"},
        )

        self.assertTrue(plan.updated)
        self.assertTrue(plan.repair_tag)
        self.assertEqual("14161", plan.tag)
```

- [ ] **Step 3: Implement git helpers and tag checks**

Add:

```python
def git_output(command: list[str]) -> str:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    return completed.stdout.strip()


def local_tag_exists(tag: str) -> bool:
    completed = subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"], check=False)
    return completed.returncode == 0


def remote_tag_exists(tag: str) -> bool:
    completed = subprocess.run(["git", "ls-remote", "--exit-code", "--tags", "origin", tag], check=False)
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
```

- [ ] **Step 4: Implement tag repair decision**

Add:

```python
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
```

Implementation note:

- The local tag safety check is required by the spec. Add this helper and call it before outputting repair mode:

```python
def ensure_local_tag_matches_head(tag: str) -> None:
    if not local_tag_exists(tag):
        return
    tag_commit = git_output(["git", "rev-list", "-n", "1", tag])
    head_commit = git_output(["git", "rev-parse", "HEAD"])
    if tag_commit != head_commit:
        raise BumpError(f"Local tag {tag} does not point to HEAD")
```

- [ ] **Step 5: Implement CLI parser and `run()`**

Add:

```python
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
```

- [ ] **Step 6: Run focused tests**

Run:

```powershell
uv run python -m unittest tests.test_bump_download -v
```

Expected:

```text
OK
```

- [ ] **Step 7: Commit CLI and git behavior**

Run:

```powershell
git add bump_download.py tests/test_bump_download.py
git commit -m "feat(download): 创建本地提交和标签"
```

### Task 6: Add Scheduled GitHub Action

**Files:**
- Create: `.github/workflows/bump-download.yml`
- Modify: `tests/test_bump_download.py` only if workflow validation helper tests are added

- [ ] **Step 1: Create `.github/workflows/bump-download.yml`**

Add:

```yaml
name: Bump Download

on:
  schedule:
    - cron: "0 */6 * * *"
  workflow_dispatch:

permissions:
  contents: write

concurrency:
  group: bump-download-${{ github.repository }}
  cancel-in-progress: false

jobs:
  bump:
    if: github.repository == 'HLND2T/CS2_VibeSignatures' || github.repository == 'hzqst/CS2_VibeSignatures'
    environment: win64
    runs-on: [self-hosted, windows, x64]
    env:
      STEAM_USERNAME: ${{ secrets.STEAM_USERNAME }}
      STEAM_PASSWORD: ${{ secrets.STEAM_PASSWORD }}
    steps:
      - name: Checkout main
        uses: actions/checkout@v4
        with:
          ref: main
          fetch-depth: 0
          submodules: true

      - name: Configure git
        shell: pwsh
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"

      - name: Bump download config
        id: bump
        shell: pwsh
        run: |
          uv run bump_download.py -config download.yaml -depotdir cs2_depot -username "$env:STEAM_USERNAME" -password "$env:STEAM_PASSWORD" -remember-password -github-output "$env:GITHUB_OUTPUT"

      - name: Push bump commit and tag
        if: steps.bump.outputs.updated == 'true'
        shell: pwsh
        run: |
          git push origin HEAD:main
          git push origin "${{ steps.bump.outputs.tag }}"
```

Implementation notes:

- `concurrency` is included to avoid overlapping scheduled/manual runs on the same repository.
- Do not include `PERSISTED_WORKSPACE`; this workflow only needs DepotDownloader metadata and `steam.inf`.
- Keep `environment: win64` so `STEAM_USERNAME` and `STEAM_PASSWORD` are read from the same environment as the build workflow.

- [ ] **Step 2: Validate workflow YAML can be parsed**

Run:

```powershell
uv run python -c "from pathlib import Path; import yaml; yaml.safe_load(Path('.github/workflows/bump-download.yml').read_text(encoding='utf-8')); print('BUMP_WORKFLOW_YAML_OK')"
```

Expected:

```text
BUMP_WORKFLOW_YAML_OK
```

- [ ] **Step 3: Commit workflow**

Run:

```powershell
git add .github/workflows/bump-download.yml
git commit -m "feat(download): 定时登记下载清单"
```

### Task 7: Final Targeted Verification And Documentation Sync

**Files:**
- Modify: `README.md` or `README_CN.md` only if implementation discovers an existing usage section that should mention `bump_download.py`
- Reference: `docs/superpowers/specs/2026-05-17-bump-download-design.md`
- Reference: `docs/TODO_bump_download.md`

- [ ] **Step 1: Run focused unit tests**

Run:

```powershell
uv run python -m unittest tests.test_bump_download tests.test_download_depot -v
```

Expected:

```text
OK
```

- [ ] **Step 2: Validate YAML files load**

Run:

```powershell
uv run python -c "from pathlib import Path; import yaml; [yaml.safe_load(Path(p).read_text(encoding='utf-8')) for p in ['download.yaml', '.github/workflows/build-on-self-runner.yml', '.github/workflows/bump-download.yml']]; print('YAML_OK')"
```

Expected:

```text
YAML_OK
```

- [ ] **Step 3: Confirm no accidental runtime tag was created during tests**

Run:

```powershell
git tag --list 14161 14161b 14161c
```

Expected:

```text
No output unless those tags already existed before this task
```

- [ ] **Step 4: Review working tree**

Run:

```powershell
git status --short
```

Expected:

```text
Only intentional changes remain; existing untracked docs/TODO_bump_download.md may still be present if it was present before implementation
```

- [ ] **Step 5: Commit any final documentation adjustment**

If README or docs changed:

```powershell
git add README.md README_CN.md docs/superpowers/plans/2026-05-17-bump-download.md
git commit -m "docs(download): 说明自动登记流程"
```

If no docs changed, skip this step.

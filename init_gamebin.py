#!/usr/bin/env python3
"""Idempotently initialize release binaries for one GAMEVER."""

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import requests
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from analysis_config import AnalysisConfigError, resolve_analysis_config  # noqa: E402

RELEASE_URL = "https://github.com/HLND2T/CS2_VibeSignatures/releases/download/{0}/gamebin-{0}.7z"
GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")
DOWNLOAD_TIMEOUT = (30, 300)
COPY_BUFFER_SIZE = 1024 * 1024
GITHUB_OWNER = "HLND2T"
BINSYNC_ROOT_BRANCH = "binsync/__root__"
BINSYNC_SIDECAR_FIELDS = frozenset({"user", "remote", "repo_path", "expected_md5", "force_user", "auto_clone"})


class InitGamebinError(Exception):
    """Raised when gamebin initialization cannot safely continue."""


@dataclass(frozen=True)
class RemoteState:
    """Describe the state of one expected GitHub BinSync repository."""

    status: str
    default_branch: str | None = None


@dataclass(frozen=True)
class BinSyncPlan:
    """Describe one fully preflighted binary and its BinSync recovery state."""

    binary_path: Path
    binary_md5: str
    repo_name: str
    remote_url: str
    repo_path: Path
    sidecar_path: Path
    sidecar_data: dict
    sidecar_exists: bool
    local_repo_exists: bool
    local_repo_locked: bool
    remote_state: RemoteState


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


def file_md5(path: Path) -> str:
    """Return the lowercase MD5 used by BinSync to identify one binary."""
    digest = hashlib.md5(usedforsecurity=False)
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(COPY_BUFFER_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        raise InitGamebinError(f"unable to hash binary {path}: {exc}") from exc
    return digest.hexdigest()


def binsync_user(root: Path) -> str:
    """Resolve and validate the OS user used for new BinSync user branches."""
    try:
        user = getpass.getuser()
    except Exception as exc:
        raise InitGamebinError(f"unable to resolve the current OS user: {exc}") from exc
    if not user or user.endswith("/") or "__root__" in user:
        raise InitGamebinError(f"current OS user is not a valid BinSync user: {user!r}")
    result = run_command(
        ["git", "check-ref-format", f"refs/heads/binsync/{user}"],
        root,
        allowed=(0, 1),
        capture=True,
        label="validating the BinSync user branch",
    )
    if result.returncode != 0:
        raise InitGamebinError(f"current OS user cannot be used as a BinSync branch: {user!r}")
    return user


def configured_binary_paths(root: Path, gamever: str, config_path: Path) -> list[Path]:
    """Return unique configured Windows/Linux binaries in first-seen order."""
    document = load_yaml_document(config_path, "analysis config")
    modules = document.get("modules")
    if not isinstance(modules, list):
        raise InitGamebinError("analysis config field 'modules' must be a list")

    gamever_root = (root / "bin" / gamever).resolve()
    paths = []
    seen_paths = set()
    filename_paths = {}
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
            if not binary_path.is_file():
                raise InitGamebinError(f"configured binary is missing after preparation: {binary_path}")

            path_key = os.path.normcase(str(binary_path))
            if path_key in seen_paths:
                continue
            filename_key = binary_name.casefold()
            previous = filename_paths.get(filename_key)
            if previous is not None and previous != path_key:
                raise InitGamebinError(
                    f"BinSync repository name collision for {binary_name}: {previous} and {binary_path}"
                )
            filename_paths[filename_key] = path_key
            seen_paths.add(path_key)
            paths.append(binary_path)
    if not paths:
        raise InitGamebinError(f"analysis config contains no Windows or Linux binaries for GAMEVER {gamever}")
    return paths


def expected_sidecar(binary_path: Path, binary_md5: str, gamever: str, user: str) -> tuple[str, str, Path, dict]:
    """Build the canonical remote, local repo path, and strict sidecar object."""
    repo_name = f"CS2_VibeSignatures_binsync_{gamever}_{binary_path.name}"
    remote_url = f"https://github.com/{GITHUB_OWNER}/{repo_name}"
    relative_repo_path = f"{binary_path.name}.bsproj"
    repo_path = binary_path.parent / relative_repo_path
    sidecar_data = {
        "user": user,
        "remote": remote_url,
        "repo_path": relative_repo_path,
        "expected_md5": binary_md5,
        "force_user": False,
        "auto_clone": True,
    }
    return repo_name, remote_url, repo_path, sidecar_data


def validate_sidecar(sidecar_path: Path, expected: dict) -> bool:
    """Return whether a strict matching sidecar exists; reject every conflict."""
    if not sidecar_path.exists():
        return False
    if not sidecar_path.is_file():
        raise InitGamebinError(f"BinSync sidecar path is not a file: {sidecar_path}")
    try:
        actual = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InitGamebinError(f"unable to read BinSync sidecar {sidecar_path}: {exc}") from exc
    if not isinstance(actual, dict) or set(actual) != BINSYNC_SIDECAR_FIELDS:
        raise InitGamebinError(f"BinSync sidecar has a conflicting schema: {sidecar_path}")
    for field, expected_value in expected.items():
        actual_value = actual[field]
        if type(actual_value) is not type(expected_value) or actual_value != expected_value:
            raise InitGamebinError(f"BinSync sidecar field {field!r} conflicts with the expected value: {sidecar_path}")
    return True


def normalize_github_remote(remote_url: str) -> tuple[str, str] | None:
    """Normalize the accepted HTTPS and SSH spellings of one GitHub repository."""
    patterns = (
        r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
        r"^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, remote_url.strip(), flags=re.IGNORECASE)
        if match:
            return match.group(1).casefold(), match.group(2).casefold()
    return None


def git_output(command: list[str], cwd: Path, label: str) -> str:
    """Run one Git command and return stripped stdout."""
    return run_command(command, cwd, capture=True, label=label).stdout.strip()


def validate_local_binsync_repo(repo_path: Path, binary_md5: str, repo_name: str) -> tuple[bool, bool]:
    """Validate an existing local BinSync repo without modifying it."""
    if not repo_path.exists():
        return False, False
    if not repo_path.is_dir():
        raise InitGamebinError(f"BinSync repo path is not a directory: {repo_path}")
    top_level = Path(
        git_output(["git", "rev-parse", "--show-toplevel"], repo_path, f"validating local BinSync repo {repo_path}")
    ).resolve()
    if top_level != repo_path.resolve():
        raise InitGamebinError(f"BinSync repo path is not the Git repository root: {repo_path}")
    root_ref = f"refs/heads/{BINSYNC_ROOT_BRANCH}"
    result = run_command(
        ["git", "show-ref", "--verify", "--quiet", root_ref],
        repo_path,
        allowed=(0, 1),
        capture=True,
        label=f"validating {BINSYNC_ROOT_BRANCH} in {repo_path}",
    )
    if result.returncode != 0:
        raise InitGamebinError(f"local BinSync repo is missing {BINSYNC_ROOT_BRANCH}: {repo_path}")
    stored_hash = git_output(
        ["git", "show", f"{root_ref}:binary_hash"],
        repo_path,
        f"reading binary_hash from {repo_path}",
    ).lower()
    if stored_hash != binary_md5:
        raise InitGamebinError(
            f"local BinSync repo binary_hash mismatch for {repo_path}: expected {binary_md5}, got {stored_hash}"
        )
    origin = git_output(["git", "remote", "get-url", "origin"], repo_path, f"reading origin from {repo_path}")
    normalized = normalize_github_remote(origin)
    expected = (GITHUB_OWNER.casefold(), repo_name.casefold())
    if normalized != expected:
        raise InitGamebinError(f"local BinSync repo origin conflicts with the expected remote: {repo_path}")
    git_dir_text = git_output(["git", "rev-parse", "--git-dir"], repo_path, f"locating Git metadata for {repo_path}")
    git_dir = Path(git_dir_text)
    if not git_dir.is_absolute():
        git_dir = repo_path / git_dir
    return True, (git_dir / "binsync.lock").exists()


def command_detail(result) -> str:
    """Return the most useful captured command failure detail."""
    return (result.stderr or result.stdout or "").strip()


def is_http_404(result) -> bool:
    """Return whether gh explicitly reported HTTP 404."""
    return result.returncode != 0 and re.search(r"\bHTTP\s+404\b", command_detail(result), re.IGNORECASE) is not None


def probe_binsync(root: Path) -> tuple[bool, str]:
    """Probe whether BinSync initialization can run in this environment.

    Returns (True, "") when usable, or (False, reason) when unavailable.
    Never raises and never modifies anything.
    """
    if shutil.which("gh") is None:
        return False, "GitHub CLI (gh) is not installed or not on PATH"
    try:
        auth = run_command(
            ["gh", "auth", "status", "--hostname", "github.com"],
            root,
            allowed=(0, 1),
            capture=True,
            label="checking gh authentication",
        )
    except InitGamebinError as exc:
        return False, str(exc)
    if auth.returncode != 0:
        detail = command_detail(auth) or f"exit code {auth.returncode}"
        return False, f"gh is not authenticated to github.com: {detail}"
    try:
        api = run_command(
            ["gh", "api", "user", "--jq", ".login"],
            root,
            allowed=(0, 1),
            capture=True,
            label="checking GitHub API reachability",
        )
    except InitGamebinError as exc:
        return False, str(exc)
    if api.returncode != 0:
        detail = command_detail(api) or f"exit code {api.returncode}"
        return False, f"cannot reach the GitHub API: {detail}"
    try:
        org = run_command(
            ["gh", "api", f"orgs/{GITHUB_OWNER}", "--jq", ".login"],
            root,
            allowed=(0, 1),
            capture=True,
            label=f"checking access to the {GITHUB_OWNER} organization",
        )
    except InitGamebinError as exc:
        return False, str(exc)
    if org.returncode != 0:
        detail = command_detail(org) or f"exit code {org.returncode}"
        return False, (
            f"authenticated GitHub account does not have access to the {GITHUB_OWNER} organization: {detail}"
        )
    if org.stdout.strip().casefold() != GITHUB_OWNER.casefold():
        return False, (f"authenticated GitHub account does not have access to the {GITHUB_OWNER} organization")
    return True, ""


def gh_api(root: Path, endpoint: str, *, method="GET", fields=None, allow_404=False):
    """Call gh api and distinguish explicit HTTP 404 from every other failure."""
    command = ["gh", "api", "--method", method, endpoint]
    for key, value in (fields or {}).items():
        command.extend(["-f", f"{key}={value}"])
    result = run_command(command, root, allowed=(0, 1), capture=True, label=f"gh api {endpoint}")
    if result.returncode == 0:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise InitGamebinError(f"gh api returned invalid JSON for {endpoint}: {exc}") from exc
    if allow_404 and is_http_404(result):
        return None
    detail = command_detail(result) or f"exit code {result.returncode}"
    raise InitGamebinError(f"gh api failed for {endpoint}: {detail}")


def inspect_remote(root: Path, repo_name: str, binary_md5: str) -> RemoteState:
    """Classify a missing, empty, or valid remote BinSync repository."""
    repository = gh_api(root, f"repos/{GITHUB_OWNER}/{repo_name}", allow_404=True)
    if repository is None:
        return RemoteState("missing")
    if not isinstance(repository, dict):
        raise InitGamebinError(f"GitHub returned invalid repository metadata for {GITHUB_OWNER}/{repo_name}")
    if repository.get("private") is not False:
        raise InitGamebinError(f"existing BinSync remote {GITHUB_OWNER}/{repo_name} is not public")

    branches = gh_api(root, f"repos/{GITHUB_OWNER}/{repo_name}/branches?per_page=1")
    if not isinstance(branches, list):
        raise InitGamebinError(f"GitHub returned invalid branch metadata for {GITHUB_OWNER}/{repo_name}")
    if not branches:
        return RemoteState("empty", repository.get("default_branch"))

    default_branch = repository.get("default_branch")
    if default_branch != BINSYNC_ROOT_BRANCH:
        raise InitGamebinError(
            f"existing BinSync remote {GITHUB_OWNER}/{repo_name} has default branch {default_branch!r}, "
            f"expected {BINSYNC_ROOT_BRANCH!r}"
        )
    content = gh_api(
        root,
        f"repos/{GITHUB_OWNER}/{repo_name}/contents/binary_hash",
        fields={"ref": BINSYNC_ROOT_BRANCH},
        allow_404=True,
    )
    if content is None:
        raise InitGamebinError(
            f"existing BinSync remote {GITHUB_OWNER}/{repo_name} is missing binary_hash on {BINSYNC_ROOT_BRANCH}"
        )
    if (
        not isinstance(content, dict)
        or content.get("encoding") != "base64"
        or not isinstance(content.get("content"), str)
    ):
        raise InitGamebinError(f"GitHub returned invalid binary_hash content for {GITHUB_OWNER}/{repo_name}")
    try:
        encoded_hash = "".join(content["content"].split())
        stored_hash = base64.b64decode(encoded_hash, validate=True).decode("utf-8").strip().lower()
    except (binascii.Error, ValueError, UnicodeError) as exc:
        raise InitGamebinError(f"unable to decode remote binary_hash for {GITHUB_OWNER}/{repo_name}: {exc}") from exc
    if stored_hash != binary_md5:
        raise InitGamebinError(
            f"remote BinSync repo binary_hash mismatch for {GITHUB_OWNER}/{repo_name}: "
            f"expected {binary_md5}, got {stored_hash}"
        )
    return RemoteState("valid", default_branch)


def preflight_binsync(root: Path, gamever: str, config_path: Path, user: str | None = None) -> list[BinSyncPlan]:
    """Validate all existing local and remote state before making any BinSync changes."""
    user = user or binsync_user(root)
    plans = []
    for binary_path in configured_binary_paths(root, gamever, config_path):
        binary_md5 = file_md5(binary_path)
        repo_name, remote_url, repo_path, sidecar_data = expected_sidecar(binary_path, binary_md5, gamever, user)
        sidecar_path = Path(f"{binary_path}.binsync.json")
        sidecar_exists = validate_sidecar(sidecar_path, sidecar_data)
        try:
            local_repo_exists, local_repo_locked = validate_local_binsync_repo(repo_path, binary_md5, repo_name)
            remote_state = inspect_remote(root, repo_name, binary_md5)
        except InitGamebinError as exc:
            raise InitGamebinError(f"BinSync preflight failed for {binary_path}: {exc}") from exc
        if local_repo_locked and remote_state.status in {"missing", "empty"}:
            raise InitGamebinError(
                f"BinSync preflight failed for {binary_path}: local repo is locked and cannot restore the remote: "
                f"{repo_path}"
            )
        plans.append(
            BinSyncPlan(
                binary_path=binary_path,
                binary_md5=binary_md5,
                repo_name=repo_name,
                remote_url=remote_url,
                repo_path=repo_path,
                sidecar_path=sidecar_path,
                sidecar_data=sidecar_data,
                sidecar_exists=sidecar_exists,
                local_repo_exists=local_repo_exists,
                local_repo_locked=local_repo_locked,
                remote_state=remote_state,
            )
        )
    return plans


def create_public_remote(root: Path, repo_name: str) -> None:
    """Create one missing public GitHub repository via the REST API.

    The REST `POST /orgs/{org}/repos` endpoint works with fine-grained PATs that
    hold `Administration: Write` on the org, unlike `gh repo create` which uses the
    GraphQL `createRepository` mutation and rejects fine-grained tokens.
    """
    run_command(
        [
            "gh",
            "api",
            "--method",
            "POST",
            f"orgs/{GITHUB_OWNER}/repos",
            "-f",
            f"name={repo_name}",
            "-f",
            "visibility=public",
        ],
        root,
        capture=True,
        label=f"creating public GitHub repository {GITHUB_OWNER}/{repo_name}",
    )


def local_binsync_refs(repo_path: Path) -> list[str]:
    """List all local BinSync branches with the root branch first."""
    output = git_output(
        ["git", "for-each-ref", "--format=%(refname)", "refs/heads/binsync/"],
        repo_path,
        f"listing BinSync branches in {repo_path}",
    )
    refs = [line for line in output.splitlines() if line]
    root_ref = f"refs/heads/{BINSYNC_ROOT_BRANCH}"
    if root_ref not in refs:
        raise InitGamebinError(f"local BinSync repo is missing {BINSYNC_ROOT_BRANCH}: {repo_path}")
    return sorted(refs, key=lambda ref: (ref != root_ref, ref))


def push_local_binsync_history(repo_path: Path) -> None:
    """Push every local binsync/* branch to an empty expected origin.

    The root branch is pushed first, on its own, so that an empty remote adopts it
    as the default branch. GitHub names the default branch after the first branch
    pushed to a repository with no commits; pushing every branch in one `--atomic`
    push lets GitHub pick alphabetically, which prefers ``binsync/WindowsRunner``
    over ``binsync/__root__``. Relying on ``gh repo edit --default-branch`` to undo
    that is not reliable, so make the root branch land first instead.
    """
    refs = local_binsync_refs(repo_path)
    root_ref = f"refs/heads/{BINSYNC_ROOT_BRANCH}"
    run_command(
        ["git", "push", "origin", f"{root_ref}:{root_ref}"],
        repo_path,
        capture=True,
        label=f"pushing {BINSYNC_ROOT_BRANCH} from {repo_path}",
    )
    remaining_refspecs = [f"{ref}:{ref}" for ref in refs if ref != root_ref]
    if remaining_refspecs:
        run_command(
            ["git", "push", "--atomic", "origin", *remaining_refspecs],
            repo_path,
            capture=True,
            label=f"restoring remaining BinSync history from {repo_path}",
        )


def initialize_minimal_binsync_repo(repo_path: Path, binary_md5: str, repo_name: str, user: str) -> None:
    """Create the same local root and user branches as BinSync Client(init_repo=True)."""
    run_command(["git", "init"], repo_path, capture=True, label=f"initializing {repo_name}")
    try:
        (repo_path / ".gitignore").write_text(".git/*\n", encoding="utf-8")
        (repo_path / "binary_hash").write_text(binary_md5, encoding="utf-8")
    except OSError as exc:
        raise InitGamebinError(f"unable to write the BinSync root files for {repo_name}: {exc}") from exc
    run_command(["git", "add", ".gitignore", "binary_hash"], repo_path, label=f"staging {repo_name}")
    run_command(
        [
            "git",
            "-c",
            f"user.name={user}",
            "-c",
            f"user.email={user}@binsync.local",
            "commit",
            "-m",
            "Root commit",
        ],
        repo_path,
        capture=True,
        label=f"creating the BinSync root commit for {repo_name}",
    )
    run_command(
        ["git", "branch", "-M", BINSYNC_ROOT_BRANCH],
        repo_path,
        label=f"creating {BINSYNC_ROOT_BRANCH} for {repo_name}",
    )
    run_command(
        ["git", "branch", f"binsync/{user}"],
        repo_path,
        label=f"creating binsync/{user} for {repo_name}",
    )


def initialize_minimal_binsync_remote(root: Path, plan: BinSyncPlan, user: str) -> None:
    """Create and push a minimal BinSync repository for one empty remote."""
    with tempfile.TemporaryDirectory(prefix=f"init-binsync-{plan.binary_path.name}-") as temp_dir:
        repo_path = Path(temp_dir)
        initialize_minimal_binsync_repo(repo_path, plan.binary_md5, plan.repo_name, user)
        run_command(["git", "remote", "add", "origin", plan.remote_url], repo_path, label="adding BinSync origin")
        push_local_binsync_history(repo_path)


def set_remote_default_branch(root: Path, repo_name: str) -> None:
    """Set the default branch only for a newly created or previously empty remote."""
    run_command(
        ["gh", "repo", "edit", f"{GITHUB_OWNER}/{repo_name}", "--default-branch", BINSYNC_ROOT_BRANCH],
        root,
        capture=True,
        label=f"setting the default branch for {GITHUB_OWNER}/{repo_name}",
    )


def write_sidecar_atomic(path: Path, data: dict) -> None:
    """Atomically write one preflighted, previously missing sidecar."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=4, ensure_ascii=False) + "\n"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            temporary.unlink(missing_ok=True)
            raise InitGamebinError(
                f"BinSync sidecar appeared after preflight; refusing to overwrite it: {path}"
            ) from exc
        temporary.unlink()
    except OSError as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise InitGamebinError(f"unable to write BinSync sidecar {path}: {exc}") from exc


def format_binsync_summary(summary: dict) -> str:
    """Format the durable BinSync work completed so far."""
    return (
        f"{summary['targets']} targets, {summary['remote_verified']} remotes verified, "
        f"{summary['remote_created']} remotes created, {summary['remote_restored']} restored from local history, "
        f"{summary['remote_initialized']} minimally initialized, {summary['sidecar_created']} sidecars created, "
        f"{summary['sidecar_existing']} existing sidecars matched"
    )


def execute_binsync_plans(root: Path, plans: list[BinSyncPlan], user: str) -> dict:
    """Apply fully preflighted BinSync plans and return a stable summary."""
    summary = {
        "targets": len(plans),
        "remote_verified": 0,
        "remote_created": 0,
        "remote_restored": 0,
        "remote_initialized": 0,
        "sidecar_created": 0,
        "sidecar_existing": 0,
    }
    for plan in plans:
        try:
            current_md5 = file_md5(plan.binary_path)
            if current_md5 != plan.binary_md5:
                raise InitGamebinError(f"binary changed after preflight: expected {plan.binary_md5}, got {current_md5}")
            remote_state = inspect_remote(root, plan.repo_name, plan.binary_md5)
            if remote_state.status == "missing":
                create_public_remote(root, plan.repo_name)
                summary["remote_created"] += 1
                remote_state = inspect_remote(root, plan.repo_name, plan.binary_md5)
            if remote_state.status == "empty":
                if plan.local_repo_exists:
                    local_repo_exists, local_repo_locked = validate_local_binsync_repo(
                        plan.repo_path, plan.binary_md5, plan.repo_name
                    )
                    if not local_repo_exists:
                        raise InitGamebinError(f"local BinSync repo disappeared after preflight: {plan.repo_path}")
                    if local_repo_locked:
                        raise InitGamebinError(f"local BinSync repo became locked after preflight: {plan.repo_path}")
                    push_local_binsync_history(plan.repo_path)
                    summary["remote_restored"] += 1
                else:
                    initialize_minimal_binsync_remote(root, plan, user)
                    summary["remote_initialized"] += 1
                set_remote_default_branch(root, plan.repo_name)
                remote_state = inspect_remote(root, plan.repo_name, plan.binary_md5)
            if remote_state.status != "valid":
                raise InitGamebinError(f"unexpected remote state after provisioning: {remote_state.status}")
            summary["remote_verified"] += 1

            if validate_sidecar(plan.sidecar_path, plan.sidecar_data):
                summary["sidecar_existing"] += 1
            else:
                write_sidecar_atomic(plan.sidecar_path, plan.sidecar_data)
                summary["sidecar_created"] += 1
        except InitGamebinError as exc:
            raise InitGamebinError(
                f"BinSync provisioning failed for {plan.binary_path}: {exc}; completed work: "
                f"{format_binsync_summary(summary)}"
            ) from exc
    return summary


def prepare_binsync_projects(root: Path, gamever: str, config_path: Path) -> dict:
    """Preflight every target, then provision recovery metadata and remotes."""
    user = binsync_user(root)
    plans = preflight_binsync(root, gamever, config_path, user)
    return execute_binsync_plans(root, plans, user)


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


def prepare(root: Path, requested: str, *, binsync_mode: str = "skip") -> dict:
    """Prepare configured binaries and return a summary.

    BinSync recovery is opt-in: the default "skip" mode never probes or
    provisions; "enable" probes availability first and fails loudly when the
    environment cannot run BinSync (used by CI).
    """
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
    binsync = None
    if binsync_mode == "enable":
        available, reason = probe_binsync(root)
        if not available:
            raise InitGamebinError(f"BinSync initialization is unavailable and was requested: {reason}")
        binsync = prepare_binsync_projects(root, gamever, config_path)
    return {
        "gamever": gamever,
        "source": source,
        "copied": copied,
        "skipped": skipped,
        "binsync": binsync,
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
    commands.add_parser("check-binsync", help="Probe whether BinSync initialization is available")
    prepare_parser = commands.add_parser("prepare", help="Prepare configured binaries")
    prepare_parser.add_argument("gamever", help="Exact GAMEVER from download.yaml, or latest")
    prepare_parser.add_argument(
        "--binsync",
        choices=["enable", "skip"],
        default="skip",
        help="Enable or skip BinSync recovery (default: skip)",
    )
    args = parser.parse_args(argv)
    try:
        root = repository_root()
        if args.command == "versions":
            print_versions(load_versions(root / "download.yaml"))
        elif args.command == "check-binsync":
            available, reason = probe_binsync(root)
            if available:
                print("BinSync available")
                return 0
            print(f"BinSync unavailable: {reason}")
            return 1
        else:
            result = prepare(root, args.gamever, binsync_mode=args.binsync)
            print(f"Selected GAMEVER: {result['gamever']}")
            print(f"Binary source: {result['source']}")
            print(f"Archive merge: {result['copied']} copied, {result['skipped']} skipped")
            if result["binsync"] is None:
                print("BinSync recovery: skipped")
            else:
                print(f"BinSync recovery: {format_binsync_summary(result['binsync'])}")
    except InitGamebinError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

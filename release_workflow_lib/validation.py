import subprocess
import tempfile
from pathlib import Path

import yaml

from analysis_config import AnalysisConfigError, analysis_config_repo_path, read_analysis_config_at_revision
from analysis_output_contract import ANALYSIS_OUTPUT_CONTRACT_MISMATCH_REASON
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotError, SnapshotMismatchError
from gamesymbol_snapshot_lib.operations import load_snapshot_context, restore_snapshot
from gamesymbol_snapshot_lib.paths import ensure_real_tree, iter_yaml_paths, path_from_key
from gamesymbol_snapshot_lib.pr_validation import build_invalidation_plan
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.manifests import (
    ALLOWED_REPOSITORIES,
    GAMEVER_RE,
    load_tracked_manifest,
    manifest_config_digest_version,
    require_gamever,
    require_mode,
    require_sha,
)


def git_output(arguments: list[str], *, text: bool = True):
    result = subprocess.run(["git", *arguments], capture_output=True, text=text, check=False)
    if result.returncode != 0:
        stderr = result.stderr.strip() if text else result.stderr.decode(errors="replace").strip()
        raise ReleaseWorkflowError(stderr or f"git {' '.join(arguments)} failed")
    return result.stdout.strip() if text else result.stdout


def validate_build_input(*, repository: str, gamever: str, source_sha: str, mode: str, default_ref: str) -> None:
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    gamever = require_gamever(gamever)
    source_sha = require_sha(source_sha, "SOURCE_SHA")
    require_mode(mode)
    git_output(["cat-file", "-e", f"{source_sha}^{{commit}}"])
    result = subprocess.run(["git", "merge-base", "--is-ancestor", source_sha, default_ref], check=False)
    if result.returncode != 0:
        raise ReleaseWorkflowError(f"SOURCE_SHA is not reachable from {default_ref}: {source_sha}")
    raw = git_output(["show", f"{source_sha}:download.yaml"], text=False)
    try:
        downloads = yaml.safe_load(raw).get("downloads", [])
    except (AttributeError, yaml.YAMLError) as exc:
        raise ReleaseWorkflowError("download.yaml at SOURCE_SHA is invalid") from exc
    if gamever not in {str(item.get("tag", "")) for item in downloads if isinstance(item, dict)}:
        raise ReleaseWorkflowError(f"GAMEVER {gamever} is absent from download.yaml at SOURCE_SHA")
    config_repo_path = analysis_config_repo_path(gamever)
    try:
        config_data = yaml.safe_load(git_output(["show", f"{source_sha}:{config_repo_path}"], text=False)) or {}
    except (ReleaseWorkflowError, yaml.YAMLError, UnicodeError) as exc:
        raise ReleaseWorkflowError(
            f"analysis config {config_repo_path} is missing or unreadable at SOURCE_SHA"
        ) from exc
    if not isinstance(config_data, dict) or not isinstance(config_data.get("modules"), list):
        raise ReleaseWorkflowError(f"analysis config configs/{gamever}.yaml must contain a modules list")
    tag_exists = (
        subprocess.run(["git", "show-ref", "--verify", "--quiet", f"refs/tags/{gamever}"], check=False).returncode == 0
    )
    if mode == "new" and tag_exists:
        raise ReleaseWorkflowError(f"mode=new requires tag {gamever} to be absent")
    if mode == "republish" and not tag_exists:
        raise ReleaseWorkflowError(f"mode=republish requires tag {gamever} to exist")


def _changed_files(repo_root: Path, base_sha: str, source_sha: str) -> list[str]:
    output = git_output(["-C", str(repo_root), "diff", "--name-only", base_sha, source_sha, "--"])
    return [line for line in output.splitlines() if line]


def _require_ancestor(repo_root: Path, base_sha: str, source_sha: str, label: str) -> None:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", base_sha, source_sha],
        check=False,
    )
    if result.returncode != 0:
        raise ReleaseWorkflowError(f"{label} is not an ancestor of the rebuild SOURCE_SHA")


def _git_blob(repo_root: Path, revision: str, repository_path: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"{revision}:{repository_path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip()
        raise ReleaseWorkflowError(stderr or f"unable to read {repository_path} at {revision}")
    return result.stdout


def _gamever_key(gamever: str) -> tuple[int, int]:
    if not GAMEVER_RE.fullmatch(str(gamever)):
        raise ReleaseWorkflowError(f"invalid GAMEVER: {gamever!r}")
    suffix = gamever[-1] if gamever[-1].isalpha() else ""
    base = gamever[:-1] if suffix else gamever
    return int(base), ord(suffix) - ord("a") + 1 if suffix else 0


def prepare_oldgamever_baseline(
    *,
    repo_root: str | Path,
    gamever: str,
    bindir: str | Path,
    artifactdir: str | Path = "bin_artifacts",
) -> dict:
    repo_root = Path(repo_root).resolve()
    gamever = require_gamever(gamever)
    bindir = Path(bindir)
    if not bindir.is_absolute():
        bindir = repo_root / bindir
    artifactdir = Path(artifactdir)
    if not artifactdir.is_absolute():
        artifactdir = repo_root / artifactdir

    download_path = repo_root / "download.yaml"
    try:
        download = yaml.safe_load(download_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ReleaseWorkflowError(f"unable to read {download_path}: {exc}") from exc
    if not isinstance(download, dict):
        raise ReleaseWorkflowError("download.yaml top level must be a mapping")
    downloads = download.get("downloads")
    if not isinstance(downloads, list):
        raise ReleaseWorkflowError("download.yaml must contain a downloads list")
    item = next(
        (entry for entry in downloads if isinstance(entry, dict) and str(entry.get("tag", "")) == gamever),
        None,
    )
    if item is None:
        raise ReleaseWorkflowError(f"GAMEVER not found in download.yaml: {gamever}")
    if item.get("major_update") is True:
        return {"oldgamever": "none", "snapshot": None, "config": None}

    current_key = _gamever_key(gamever)
    snapshot_root = repo_root / "gamesymbols"
    candidates = []
    if snapshot_root.is_dir():
        for snapshot in snapshot_root.glob("*.yaml"):
            candidate = snapshot.stem
            if GAMEVER_RE.fullmatch(candidate) and _gamever_key(candidate) < current_key:
                candidates.append((candidate, snapshot))
    if not candidates:
        raise ReleaseWorkflowError(f"no trusted old-version snapshot is available for non-major update {gamever}")

    oldgamever, snapshot = max(candidates, key=lambda candidate: _gamever_key(candidate[0]))
    config = repo_root / analysis_config_repo_path(oldgamever)
    if not config.is_file():
        raise ReleaseWorkflowError(f"old-version analysis config is missing: {config}")
    try:
        restore_snapshot(
            oldgamever,
            str(bindir),
            str(config),
            str(snapshot),
            replace=True,
            artifactdir=artifactdir,
        )
    except (SnapshotError, OSError, UnicodeError) as exc:
        raise ReleaseWorkflowError(f"unable to restore trusted snapshot for {oldgamever}: {exc}") from exc
    return {
        "oldgamever": oldgamever,
        "snapshot": str(snapshot),
        "config": str(config),
    }


def _invalidate_yaml_baseline(artifactdir: Path, gamever: str) -> int:
    game_root = artifactdir / gamever
    ensure_real_tree(artifactdir, game_root)
    paths = list(iter_yaml_paths(game_root))
    for path in paths:
        path.unlink()
    print(f"No accepted release manifest exists; conservative baseline invalidated {len(paths)} YAML file(s)")
    return len(paths)


def _delete_planned_outputs(plan, game_root: Path) -> int:
    ensure_real_tree(game_root.parent, game_root)
    deleted = 0
    for key in sorted(plan.paths):
        target = path_from_key(game_root, key)
        if target.is_file():
            target.unlink()
            deleted += 1
    for reason in plan.reasons:
        print(reason)
    print(f"Invalidated {len(plan.paths)} affected output(s); deleted {deleted} YAML file(s)")
    return deleted


def _latest_path_commit(repo_root: Path, source_sha: str, repository_path: str, label: str) -> str:
    try:
        commit = git_output(["-C", str(repo_root), "log", "-1", "--format=%H", source_sha, "--", repository_path])
    except ReleaseWorkflowError as exc:
        raise ReleaseWorkflowError(f"{label} is missing: {repository_path}") from exc
    if not commit:
        raise ReleaseWorkflowError(f"{label} is missing: {repository_path}")
    return require_sha(commit, f"{label} SHA")


def _invalidate_from_accepted_manifest(
    repo_root: Path,
    gamever: str,
    source_sha: str,
    bindir: Path,
    artifactdir: Path,
    manifest_path: Path,
) -> int:
    manifest = load_tracked_manifest(manifest_path)
    base_sha = require_sha(manifest["source_sha"], "previous SOURCE_SHA")
    if base_sha == source_sha:
        raise ReleaseWorkflowError("republish SOURCE_SHA must be newer than the accepted generator source")
    _require_ancestor(repo_root, base_sha, source_sha, "previous accepted SOURCE_SHA")
    snapshot_repo_path = f"gamesymbols/{gamever}.yaml"
    manifest_repo_path = f"release-manifests/{gamever}.json"
    accepted_manifest_sha = _latest_path_commit(repo_root, source_sha, manifest_repo_path, "accepted manifest")
    snapshot_sha = _latest_path_commit(repo_root, source_sha, snapshot_repo_path, "tracked snapshot")
    with tempfile.TemporaryDirectory(prefix="release-base-") as temp_dir:
        accepted_config = Path(temp_dir) / "accepted.yaml"
        snapshot_config = Path(temp_dir) / "snapshot.yaml"
        head_config = Path(temp_dir) / "head.yaml"
        accepted_snapshot = Path(temp_dir) / "accepted-snapshot.yaml"
        snapshot = Path(temp_dir) / f"{gamever}.yaml"
        try:
            accepted_history = read_analysis_config_at_revision(
                base_sha,
                gamever,
                allow_legacy_root=True,
                repo_root=repo_root,
            )
            snapshot_history = read_analysis_config_at_revision(
                snapshot_sha,
                gamever,
                allow_legacy_root=True,
                repo_root=repo_root,
            )
            head_history = read_analysis_config_at_revision(
                source_sha,
                gamever,
                allow_legacy_root=False,
                repo_root=repo_root,
            )
        except AnalysisConfigError as exc:
            raise ReleaseWorkflowError(str(exc)) from exc
        accepted_config.write_bytes(accepted_history.data)
        snapshot_config.write_bytes(snapshot_history.data)
        head_config.write_bytes(head_history.data)
        accepted_snapshot.write_bytes(_git_blob(repo_root, accepted_manifest_sha, snapshot_repo_path))
        snapshot.write_bytes(_git_blob(repo_root, snapshot_sha, snapshot_repo_path))
        try:
            accepted_context = load_snapshot_context(
                accepted_snapshot,
                accepted_config,
                gamever,
                bindir,
                artifactdir=artifactdir,
            )
        except SnapshotMismatchError as exc:
            if exc.reason == ANALYSIS_OUTPUT_CONTRACT_MISMATCH_REASON:
                print("Analysis output contract changed; discarding the accepted snapshot baseline")
                return _invalidate_yaml_baseline(artifactdir, gamever)
            raise
        accepted_contract = accepted_context.contract
        if (
            manifest.get("analysis_config_path")
            and manifest["analysis_config_path"] != accepted_history.repository_path
        ):
            raise ReleaseWorkflowError("accepted manifest analysis config path does not match SOURCE_SHA")
        if manifest.get("analysis_config_sha256") and manifest["analysis_config_sha256"] != accepted_history.sha256:
            raise ReleaseWorkflowError("accepted manifest analysis config hash does not match SOURCE_SHA")
        if (
            manifest.get("analysis_config_contract_sha256")
            and manifest["analysis_config_contract_sha256"] != accepted_contract.config_sha256
        ):
            raise ReleaseWorkflowError("accepted manifest analysis config contract does not match snapshot")
        manifest_digest_version = manifest_config_digest_version(manifest, accepted_context.document)
        if manifest_digest_version != accepted_contract.config_digest_version:
            raise ReleaseWorkflowError("accepted manifest analysis config digest version does not match snapshot")
        try:
            snapshot_context = load_snapshot_context(
                snapshot,
                snapshot_config,
                gamever,
                bindir,
                artifactdir=artifactdir,
            )
        except SnapshotMismatchError as exc:
            if exc.reason == ANALYSIS_OUTPUT_CONTRACT_MISMATCH_REASON:
                print("Analysis output contract changed; discarding the tracked snapshot baseline")
                return _invalidate_yaml_baseline(artifactdir, gamever)
            raise
        head_contract = load_contract(head_config, gamever, bindir, artifactdir=artifactdir)
        restore_snapshot(
            gamever,
            bindir,
            snapshot_config,
            snapshot,
            replace=True,
            artifactdir=artifactdir,
        )
        plan = build_invalidation_plan(
            snapshot_context.contract,
            head_contract,
            snapshot_context.document,
            snapshot_context.document,
            _changed_files(repo_root, snapshot_sha, source_sha),
            repo_root,
        )
    return _delete_planned_outputs(plan, head_contract.artifact_game_root)


def invalidate_republish(
    *,
    repo_root: Path,
    gamever: str,
    source_sha: str,
    bindir: Path,
    artifactdir: Path = Path("bin_artifacts"),
) -> int:
    repo_root = Path(repo_root).resolve()
    gamever = require_gamever(gamever)
    source_sha = require_sha(source_sha, "SOURCE_SHA")
    bindir = Path(bindir)
    if not bindir.is_absolute():
        bindir = repo_root / bindir
    artifactdir = Path(artifactdir)
    if not artifactdir.is_absolute():
        artifactdir = repo_root / artifactdir
    manifest_path = repo_root / "release-manifests" / f"{gamever}.json"
    if manifest_path.is_file():
        return _invalidate_from_accepted_manifest(
            repo_root,
            gamever,
            source_sha,
            bindir,
            artifactdir,
            manifest_path,
        )
    return _invalidate_yaml_baseline(artifactdir, gamever)

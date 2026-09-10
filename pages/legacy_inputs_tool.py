#!/usr/bin/env python3
"""Maintainer-only offline tool for the pinned pages-snapshots historical archive.

This tool is never invoked by the Pages deployment workflow. It reproduces the
pre-switch game-symbol index, imports historical gamedata from immutable Release
assets, assembles a candidate archive commit, and writes the pinned manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    file_inventory,
    inventory_sha256,
    sha256_bytes,
    sha256_file,
    write_canonical_json,
)
from release_workflow_lib.sevenzip import listed_archive_files

import pages_legacy_input as legacy_input

ALLOWED_REPOSITORY = legacy_input.ALLOWED_REPOSITORY
GAMEDATA_PREFIX = "gamedata/"
GAMESYMBOLS_PREFIX = "gamesymbols/"
MAX_ARCHIVE_ENTRIES = 50000
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
DEFAULT_SOURCES = REPO_ROOT / "pages" / "legacy-gamedata-sources.json"
CANDIDATE_REF = "refs/heads/pages-snapshots-legacy-candidate"
COMMIT_MESSAGE = "chore(pages): import historical gamedata into pinned snapshot archive"
ARCHIVE_GITATTRIBUTES = (
    "# Recovery archive: keep both data subtrees byte-stable across platforms.\n"
    "/gamesymbols/** text eol=lf\n"
    "/gamedata/** text eol=lf\n"
)


class LegacyInputToolError(Exception):
    """Raised when the offline import cannot produce a trustworthy archive commit."""


def _run(argv: list[str], cwd: Path | None = None, *, text: bool = True) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(argv, cwd=str(cwd) if cwd else None, capture_output=True, text=text, check=False)
    except OSError as exc:
        raise LegacyInputToolError(f"unable to run {argv[0]}: {exc}") from exc
    if result.returncode:
        detail = result.stderr or result.stdout
        if isinstance(detail, bytes):
            detail = detail.decode(errors="replace")
        raise LegacyInputToolError((detail or f"{argv[0]} failed").strip())
    return result


def _git(arguments: list[str], cwd: Path | None = None) -> str:
    return _run(["git", *arguments], cwd=cwd).stdout.strip()


def _exit_code(argv: list[str], cwd: Path | None = None) -> int:
    try:
        return subprocess.run(argv, cwd=str(cwd) if cwd else None, capture_output=True, check=False).returncode
    except OSError as exc:
        raise LegacyInputToolError(f"unable to run {argv[0]}: {exc}") from exc


def _npm() -> list[str]:
    return ["cmd", "/c", "npm"] if os.name == "nt" else ["npm"]


def _gh_api(path: str) -> dict:
    return json.loads(_run(["gh", "api", path]).stdout)


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LegacyInputToolError(f"unable to read JSON {path}: {exc}") from exc


def _load_sources(path: Path) -> dict:
    document = _load_json(path)
    releases = document.get("releases")
    excluded = document.get("excluded")
    if document.get("schemaVersion") != 1 or not isinstance(releases, list) or not releases:
        raise LegacyInputToolError(f"{path}: invalid gamedata sources document")
    if not isinstance(excluded, list):
        raise LegacyInputToolError(f"{path}: excluded must be a list")
    tags = [item.get("tag") for item in releases]
    if tags != sorted(tags, key=legacy_input._version_key) or len(set(tags)) != len(tags):
        raise LegacyInputToolError(f"{path}: release tags must be sorted and unique")
    return document


def _verify_release_identity(release: dict) -> None:
    remote = _gh_api(f"repos/{ALLOWED_REPOSITORY}/releases/{release['releaseId']}")
    if (
        remote.get("tag_name") != release["tag"]
        or remote.get("draft") is not False
        or remote.get("prerelease") is not False
    ):
        raise LegacyInputToolError(f"Release {release['releaseId']} identity mismatch")
    assets = {asset["name"]: asset for asset in remote.get("assets", [])}
    remote_asset = assets.get(release["assetName"])
    if (
        remote_asset is None
        or remote_asset.get("id") != release["assetId"]
        or remote_asset.get("size") != release["assetSize"]
    ):
        raise LegacyInputToolError(f"Release asset {release['assetName']} identity mismatch")
    remote_digest = remote_asset.get("digest")
    if remote_digest != release.get("apiDigest"):
        raise LegacyInputToolError(f"Release asset {release['assetName']} API digest changed")


def _download_asset(release: dict, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    arguments = [
        "gh",
        "api",
        "-H",
        "Accept: application/octet-stream",
        f"repos/{ALLOWED_REPOSITORY}/releases/assets/{release['assetId']}",
    ]
    try:
        with destination.open("xb") as handle:
            result = subprocess.run(arguments, stdout=handle, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        raise LegacyInputToolError(f"unable to download {release['assetName']}: {exc}") from exc
    if result.returncode:
        destination.unlink(missing_ok=True)
        raise LegacyInputToolError(
            f"unable to download {release['assetName']}: {result.stderr.decode(errors='replace').strip()}"
        )


def _directory_paths(output: str) -> set[str]:
    directories = set()
    for block in re.split(r"\n\s*\n", output.replace("\r\n", "\n")):
        fields = {}
        for line in block.splitlines():
            key, separator, value = line.partition(" = ")
            if separator and key not in fields:
                fields[key] = value
        raw_path = fields.get("Path")
        if not raw_path:
            continue
        attributes = fields.get("Attributes", "").split()
        if fields.get("Folder") == "+" or any(token.upper().startswith("D") for token in attributes):
            directories.add(raw_path.replace("\\", "/"))
    return directories


def _list_archive(archive: Path) -> list[dict]:
    output = _run(["7z", "l", "-slt", "-ba", str(archive)]).stdout
    directories = _directory_paths(output)
    files = listed_archive_files(output)
    return [item for item in files if item["path"] not in directories]


def _enforce_limits(listing: list[dict]) -> None:
    if len(listing) > MAX_ARCHIVE_ENTRIES:
        raise LegacyInputToolError(f"7z archive lists {len(listing)} entries, above the {MAX_ARCHIVE_ENTRIES} limit")
    total = sum(item["size"] for item in listing)
    if total > MAX_EXTRACTED_BYTES:
        raise LegacyInputToolError(f"7z archive lists {total} bytes, above the {MAX_EXTRACTED_BYTES} limit")


def _extract_version(archive: Path, destination: Path, game_version: str) -> None:
    prefix = f"{GAMEDATA_PREFIX}{game_version}/"
    listing = _list_archive(archive)
    if len(listing) > MAX_ARCHIVE_ENTRIES:
        raise LegacyInputToolError(f"{archive}: lists {len(listing)} entries, above the {MAX_ARCHIVE_ENTRIES} limit")
    expected = [
        {"path": item["path"][len(prefix) :], "size": item["size"]}
        for item in listing
        if item["path"].startswith(prefix)
    ]
    if not expected:
        raise LegacyInputToolError(f"{archive}: no {prefix} entries found")
    _enforce_limits(expected)
    destination.mkdir(parents=True)
    _run(["7z", "x", "-y", "-bd", "-bso0", "-bsp0", f"-o{destination}", str(archive), f"{prefix}*"])
    extracted_root = destination / "gamedata" / game_version
    if not extracted_root.is_dir():
        raise LegacyInputToolError(f"{archive}: extraction did not produce {prefix}")
    actual = [{"path": item["path"], "size": item["size"]} for item in file_inventory(extracted_root)]
    if actual != sorted(expected, key=lambda item: item["path"]):
        raise LegacyInputToolError(f"{archive}: extracted inventory differs from the 7z listing")


def _cross_check(release_root: Path, tracked_root: Path, game_version: str) -> list[dict]:
    release = {item["path"]: item for item in file_inventory(release_root)}
    tracked_dir = tracked_root / game_version
    tracked = {item["path"]: item for item in file_inventory(tracked_dir)} if tracked_dir.is_dir() else {}
    differences = []
    for path in sorted(set(release) | set(tracked)):
        left = release.get(path)
        right = tracked.get(path)
        if (
            left is not None
            and right is not None
            and left["sha256"] == right["sha256"]
            and left["size"] == right["size"]
        ):
            continue
        differences.append(
            {
                "path": f"{GAMEDATA_PREFIX}{game_version}/{path}",
                "releaseSha256": left["sha256"] if left else None,
                "trackedSha256": right["sha256"] if right else None,
            }
        )
    return differences


def _verify_content_source(worktree: Path, commit: str) -> None:
    if _git(["rev-parse", "HEAD"], cwd=worktree) != commit:
        raise LegacyInputToolError(f"{worktree}: HEAD does not match the declared content source commit {commit}")
    dirty = _git(["status", "--porcelain", "--untracked-files=all", "--", "gamedata"], cwd=worktree)
    if dirty:
        raise LegacyInputToolError(f"{worktree}: content source has uncommitted gamedata changes:\n{dirty}")


def _verify_archive_checkout(worktree: Path, commit: str) -> None:
    if _git(["rev-parse", "HEAD"], cwd=worktree) != commit:
        raise LegacyInputToolError(f"{worktree}: HEAD does not match the declared archive commit {commit}")
    dirty = _git(["status", "--porcelain", "--untracked-files=all", "--", "gamesymbols", "gamedata"], cwd=worktree)
    if dirty:
        raise LegacyInputToolError(f"{worktree}: archive worktree has uncommitted changes:\n{dirty}")


def _prepare_worktree(destination: Path, source_commit: str) -> str:
    _git(
        ["fetch", "--no-tags", "origin", "refs/heads/pages-snapshots:refs/remotes/origin/pages-snapshots"],
        cwd=REPO_ROOT,
    )
    tip = _git(["rev-parse", "refs/remotes/origin/pages-snapshots"], cwd=REPO_ROOT)
    if _exit_code(["git", "merge-base", "--is-ancestor", source_commit, tip], cwd=REPO_ROOT):
        raise LegacyInputToolError(f"{source_commit} is not an ancestor of the pages-snapshots tip {tip}")
    if destination.exists():
        raise LegacyInputToolError(f"worktree path already exists: {destination}")
    _git(["worktree", "add", "--detach", str(destination), tip], cwd=REPO_ROOT)
    return tip


def _tree_of(ref: str, cwd: Path) -> str:
    return _git(["rev-parse", f"{ref}^{{tree}}"], cwd=cwd)


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _blob_tree(worktree: Path, treeish: str, prefix: str) -> dict[str, str]:
    listing = _git(["ls-tree", "-r", "--format=%(objectname) %(path)", treeish, "--", prefix], cwd=worktree)
    result = {}
    for line in listing.splitlines():
        if not line.strip():
            continue
        objectname, path = line.split(" ", 1)
        result[path] = objectname
    return result


def _imported_tree(prefix: str, root: Path) -> dict[str, str]:
    result = {}
    for path in root.rglob("*"):
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            result[f"{prefix}{relative}"] = _git_blob_sha1(path.read_bytes())
    return result


def _materialize_worktree(worktree: Path) -> None:
    head = _git(["rev-parse", "HEAD"], cwd=worktree)
    _git(["checkout", "--force", "--detach", head], cwd=worktree)
    for subtree in ("gamesymbols", "gamedata"):
        shutil.rmtree(worktree / subtree, ignore_errors=True)
    _git(["checkout", "--", "."], cwd=worktree)


def _assemble_archive_commit(*, worktree: Path, imported: dict[str, Path], candidate_ref: str) -> str:
    gamedata_root = worktree / "gamedata"
    for game_version, extracted_root in sorted(imported.items(), key=lambda item: legacy_input._version_key(item[0])):
        prefix = f"{GAMEDATA_PREFIX}{game_version}/"
        existing = _blob_tree(worktree, "HEAD", f"{GAMEDATA_PREFIX}{game_version}")
        if existing:
            if existing != _imported_tree(prefix, extracted_root):
                raise LegacyInputToolError(
                    f"{gamedata_root / game_version}: existing gamedata version conflicts with the imported bytes"
                )
            continue
        shutil.copytree(extracted_root, gamedata_root / game_version)
    if _git(["diff", "--cached", "--name-only", "--", "gamesymbols"], cwd=worktree):
        raise LegacyInputToolError("baseline gamesymbols subtree was modified during import")

    (worktree / ".gitattributes").write_text(ARCHIVE_GITATTRIBUTES, encoding="utf-8", newline="\n")
    _git(["add", "--all", "--", "gamedata", ".gitattributes"], cwd=worktree)
    tree = _git(["write-tree"], cwd=worktree)
    try:
        candidate = _git(["rev-parse", candidate_ref], cwd=worktree)
    except LegacyInputToolError:
        candidate = None
    if candidate and _tree_of(candidate, worktree) == tree:
        _git(["checkout", "--force", "--detach", candidate], cwd=worktree)
        _materialize_worktree(worktree)
        return candidate
    if _git(["diff", "--cached", "--name-only"], cwd=worktree) == "":
        _materialize_worktree(worktree)
        return _git(["rev-parse", "HEAD"], cwd=worktree)
    _git(
        [
            "-c",
            "user.name=pagessnapshots-bot",
            "-c",
            "user.email=pagessnapshots-bot@users.noreply.github.com",
            "commit",
            "--no-verify",
            "-m",
            COMMIT_MESSAGE,
        ],
        cwd=worktree,
    )
    commit = _git(["rev-parse", "HEAD"], cwd=worktree)
    _git(["update-ref", candidate_ref, commit], cwd=worktree)
    _materialize_worktree(worktree)
    return commit


def reproduce_index(args: argparse.Namespace) -> int:
    worktree = Path(args.worktree).resolve()
    output = Path(args.out).resolve()
    source_commit = _git(["rev-parse", args.source_commit], cwd=REPO_ROOT)
    _git(["worktree", "add", "--detach", str(worktree), source_commit], cwd=REPO_ROOT)
    try:
        _run([*_npm(), "ci"], cwd=worktree / "pages")
        _run([*_npm(), "run", "build"], cwd=worktree / "pages")
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(worktree / "pages" / "dist" / "gamesymbols" / "index.json", output)
    finally:
        try:
            _git(["worktree", "remove", "--force", str(worktree)], cwd=REPO_ROOT)
        except LegacyInputToolError:
            pass
    print(f"Reproduced pre-switch index from {source_commit} into {output}")
    return 0


def archive_gamedata(args: argparse.Namespace) -> int:
    sources = _load_sources(Path(args.sources))
    work_root = Path(tempfile.mkdtemp(prefix="legacy-gamedata-"))
    release_extract: dict[str, Path] = {}
    provenance = []
    try:
        for release in sources["releases"]:
            _verify_release_identity(release)
            archive = work_root / "downloads" / release["assetName"]
            _download_asset(release, archive)
            digest = sha256_file(archive)
            if archive.stat().st_size != release["assetSize"] or digest != release["sha256"]:
                raise LegacyInputToolError(f"{release['assetName']}: downloaded bytes do not match the pinned identity")
            _extract_version(archive, work_root / "extract" / release["tag"], release["tag"])
            release_extract[release["tag"]] = work_root / "extract" / release["tag"] / "gamedata" / release["tag"]
            provenance.append(
                {
                    "tag": release["tag"],
                    "releaseId": release["releaseId"],
                    "assetId": release["assetId"],
                    "assetName": release["assetName"],
                    "assetSize": release["assetSize"],
                    "sha256": digest,
                    "apiDigest": release["apiDigest"],
                }
            )

        differences: list[dict] = []
        if args.content_source_worktree:
            if not args.content_source_commit or not args.selection_reason:
                raise LegacyInputToolError(
                    "--content-source-worktree requires --content-source-commit and --selection-reason"
                )
            source_worktree = Path(args.content_source_worktree).resolve()
            _verify_content_source(source_worktree, args.content_source_commit)
            tracked_root = source_worktree / "gamedata"
            if not tracked_root.is_dir():
                raise LegacyInputToolError(f"content source gamedata subtree is missing: {tracked_root}")
            imported: dict[str, Path] = {}
            for game_version in sorted(release_extract, key=legacy_input._version_key):
                differences.extend(_cross_check(release_extract[game_version], tracked_root, game_version))
                source = tracked_root / game_version
                if not source.is_dir():
                    raise LegacyInputToolError(f"content source is missing {game_version}: {source}")
                imported[game_version] = source
            content_source = {
                "kind": "switch-pre-tracked",
                "commit": args.content_source_commit,
                "subtree": "gamedata",
                "selectionReason": args.selection_reason,
            }
        else:
            if args.content_source_commit or args.selection_reason:
                raise LegacyInputToolError(
                    "--content-source-commit/--selection-reason require --content-source-worktree"
                )
            imported = release_extract
            content_source = {
                "kind": "release-assets",
                "commit": None,
                "subtree": "gamedata",
                "selectionReason": "release assets are the sole import source",
            }

        worktree = Path(args.worktree).resolve()
        import_base = _prepare_worktree(worktree, args.source_archive_commit)
        archive_commit = _assemble_archive_commit(
            worktree=worktree,
            imported=imported,
            candidate_ref=args.candidate_ref,
        )
        diff = _git(["show", "--stat", "--oneline", archive_commit], cwd=worktree)
        gamedata_inventory = file_inventory(worktree / "gamedata")
        content_source["inventorySha256"] = inventory_sha256(gamedata_inventory)
        content_source["differences"] = sorted(differences, key=lambda item: item["path"])
        report = {
            "schemaVersion": 1,
            "archiveCommit": archive_commit,
            "importBaseCommit": import_base,
            "sourceArchiveCommit": args.source_archive_commit,
            "contentSource": content_source,
            "releases": provenance,
            "gamedataFileCount": len(gamedata_inventory),
            "gamedataTotalBytes": sum(item["size"] for item in gamedata_inventory),
            "gamedataInventorySha256": inventory_sha256(gamedata_inventory),
            "candidateRef": args.candidate_ref,
        }
        write_canonical_json(Path(args.report), report)
        print(diff)
        print(
            f"archiveCommit={archive_commit} importBase={import_base} contentSource={content_source['kind']} "
            f"gamedataFiles={len(gamedata_inventory)} bytes={report['gamedataTotalBytes']} "
            f"differences={len(differences)}"
        )
    finally:
        shutil.rmtree(work_root, ignore_errors=True)
    return 0


def _node_validate_archive(manifest_path: Path, archive_directory: Path) -> None:
    script = REPO_ROOT / "pages" / "mergeLegacyGameSymbols.mjs"
    _run(
        [
            "node",
            str(script),
            "--validate-archive",
            "--manifest",
            str(manifest_path),
            "--archive",
            str(archive_directory),
        ]
    )


def select(args: argparse.Namespace) -> int:
    sources = _load_sources(Path(args.sources))
    worktree = Path(args.archive_root).resolve()
    _verify_archive_checkout(worktree, args.archive_commit)
    archive_report = _load_json(Path(args.archive_report))
    if archive_report.get("archiveCommit") != args.archive_commit:
        raise LegacyInputToolError(f"{args.archive_report}: archiveCommit does not match {args.archive_commit}")
    content_source = archive_report.get("contentSource")
    if not isinstance(content_source, dict):
        raise LegacyInputToolError(f"{args.archive_report}: contentSource is missing")

    index_raw = Path(args.reproduced_index).read_bytes()
    index = json.loads(index_raw.decode("utf-8"))
    if index.get("schemaVersion") != 4 or not isinstance(index.get("versions"), list):
        raise LegacyInputToolError("reproduced index must be a gamesymbol index schema v4")

    gamesymbol_inventory = file_inventory(worktree / "gamesymbols")
    file_by_path = {f"{GAMESYMBOLS_PREFIX}{item['path']}": item for item in gamesymbol_inventory}
    selected = []
    for entry in index["versions"]:
        url = entry.get("url")
        record = file_by_path.get(f"{GAMESYMBOLS_PREFIX}{url}")
        if record is None or record["sha256"] != entry.get("sha256") or record["size"] != entry.get("size"):
            raise LegacyInputToolError(f"selected snapshot {url} is absent from the archive or differs in bytes")
        selected.append(
            {
                "gameVersion": entry["gameVersion"],
                "url": url,
                "sha256": entry["sha256"],
                "size": entry["size"],
                "fileCount": entry["fileCount"],
                "snapshotSchemaVersion": entry["snapshotSchemaVersion"],
                "lastPublishTime": entry["lastPublishTime"],
            }
        )
    selected.sort(key=lambda item: legacy_input._version_key(item["gameVersion"]))

    gamedata_inventory = file_inventory(worktree / "gamedata")
    groups: dict[str, list] = {}
    for item in gamedata_inventory:
        game_version = item["path"].split("/", 1)[0]
        groups.setdefault(game_version, []).append(
            {"path": f"{GAMEDATA_PREFIX}{item['path']}", "size": item["size"], "sha256": item["sha256"]}
        )
    versions = [
        {"gameVersion": game_version, "files": sorted(groups[game_version], key=lambda item: item["path"])}
        for game_version in sorted(groups, key=legacy_input._version_key)
    ]

    manifest = {
        "schemaVersion": 1,
        "repository": ALLOWED_REPOSITORY,
        "archiveCommit": args.archive_commit,
        "gamesymbols": {
            "files": [
                {"path": f"{GAMESYMBOLS_PREFIX}{item['path']}", "size": item["size"], "sha256": item["sha256"]}
                for item in gamesymbol_inventory
            ],
            "selected": selected,
        },
        "gamedata": {"versions": versions},
        "excluded": sorted(
            (
                {"kind": "gamedata", "gameVersion": item["gameVersion"], "reason": item["reason"]}
                for item in sources["excluded"]
            ),
            key=lambda item: (item["kind"], legacy_input._version_key(item["gameVersion"])),
        ),
        "importProvenance": {
            "sourceArchiveCommit": args.source_archive_commit,
            "importBaseCommit": args.import_base_commit,
            "selectedBasis": {
                "kind": "pre-switch-source-reproduction",
                "sourceCommit": args.source_commit,
                "indexSha256": sha256_bytes(index_raw),
                "indexSize": len(index_raw),
            },
            "gamedataSource": content_source,
            "releases": sorted(
                (
                    {
                        "tag": release["tag"],
                        "releaseId": release["releaseId"],
                        "assetId": release["assetId"],
                        "assetName": release["assetName"],
                        "assetSize": release["assetSize"],
                        "sha256": release["sha256"],
                        "apiDigest": release["apiDigest"],
                    }
                    for release in sources["releases"]
                ),
                key=lambda item: legacy_input._version_key(item["tag"]),
            ),
        },
    }
    manifest_path = Path(args.manifest_out).resolve()
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    write_canonical_json(manifest_path, manifest)
    legacy_input.parse_legacy_inputs(manifest_path.read_bytes(), str(manifest_path))
    try:
        _node_validate_archive(manifest_path, worktree / "gamesymbols")
    except BaseException:
        manifest_path.unlink(missing_ok=True)
        raise
    report = {
        "schemaVersion": 1,
        "archiveCommit": args.archive_commit,
        "gamesymbolFiles": len(manifest["gamesymbols"]["files"]),
        "selectedVersions": [item["gameVersion"] for item in selected],
        "gamedataVersions": [item["gameVersion"] for item in versions],
        "excluded": manifest["excluded"],
        "gamedataTotalBytes": sum(item["size"] for item in gamedata_inventory),
    }
    write_canonical_json(Path(args.report), report)
    print(f"Wrote {manifest_path} with {len(selected)} selected and {len(versions)} gamedata versions")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    reproduce = sub.add_parser("reproduce-index", help="build the pre-switch gamesymbol index")
    reproduce.add_argument("--source-commit", required=True)
    reproduce.add_argument("--out", required=True)
    reproduce.add_argument("--worktree", required=True)
    reproduce.set_defaults(func=reproduce_index)

    archive = sub.add_parser("archive-gamedata", help="download, verify and commit historical gamedata")
    archive.add_argument("--sources", default=str(DEFAULT_SOURCES))
    archive.add_argument("--worktree", required=True)
    archive.add_argument("--source-archive-commit", required=True)
    archive.add_argument("--candidate-ref", default=CANDIDATE_REF)
    archive.add_argument(
        "--content-source-worktree",
        help="git worktree pinned at the switch-pre source commit whose gamedata is the adjudicated content source",
    )
    archive.add_argument("--content-source-commit", help="full source SHA that --content-source-worktree must be at")
    archive.add_argument("--selection-reason", help="reviewer-supplied reason for choosing the content source")
    archive.add_argument("--report", required=True)
    archive.set_defaults(func=archive_gamedata)

    select_cmd = sub.add_parser("select", help="assemble the pinned manifest from a reproduced index")
    select_cmd.add_argument("--sources", default=str(DEFAULT_SOURCES))
    select_cmd.add_argument("--reproduced-index", required=True)
    select_cmd.add_argument("--archive-root", required=True)
    select_cmd.add_argument("--archive-report", required=True)
    select_cmd.add_argument("--archive-commit", required=True)
    select_cmd.add_argument("--source-archive-commit", required=True)
    select_cmd.add_argument("--import-base-commit", required=True)
    select_cmd.add_argument("--source-commit", required=True)
    select_cmd.add_argument("--manifest-out", required=True)
    select_cmd.add_argument("--report", required=True)
    select_cmd.set_defaults(func=select)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, LegacyInputToolError, ReleaseWorkflowError, legacy_input.LegacyInputError) as exc:
        print(f"Legacy inputs tool error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

import re
from pathlib import Path

from gamedata_contract import discover_generator_modules, expected_inventory_paths, generator_contract_sha256
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    HEX_SHA256_LENGTH,
    canonical_json_bytes,
    inventory_sha256,
    load_json_object,
    sha256_file,
    tracked_output_inventory,
    write_canonical_json,
)

GAMEVER_RE = re.compile(r"^[0-9]{4,10}[a-z]?$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
BUILD_ID_RE = re.compile(r"^[0-9]+-[0-9]+$")
BRANCH_RE = re.compile(r"^gamesymbols/build/(?P<gamever>[0-9]{4,10}[a-z]?)/(?P<build_id>[0-9]+-[0-9]+)$")
LEGACY_BRANCH_RE = re.compile(r"^gamesymbols/(?P<gamever>[0-9]{4,10}[a-z]?)/build-(?P<build_id>[0-9]+-[0-9]+)$")
ALLOWED_REPOSITORIES = {"HLND2T/CS2_VibeSignatures", "hzqst/CS2_VibeSignatures"}
LEGACY_ACTIONS_BOT_LOGIN = "github-actions[bot]"
TRUSTED_PR_AUTHOR_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
SCHEMA_VERSION = 5
PRE_METADATA_SCHEMA_VERSION = 4
PRE_GAMEDATA_SCHEMA_VERSION = 3
CONTRACT_SCHEMA_VERSION = 2
LEGACY_SCHEMA_VERSION = 1
TRACKED_FIELDS = {
    "schema_version",
    "gamever",
    "release_tag",
    "mode",
    "build_id",
    "source_sha",
    "candidate_sha256",
    "bin_manifest_sha256",
    "tracked_output_manifest_sha256",
    "workflow_run_url",
    "analysis_config_path",
    "analysis_config_sha256",
    "analysis_config_contract_digest_version",
    "analysis_config_contract_sha256",
    "gamedata_path",
    "gamedata_manifest_sha256",
    "generator_contract_sha256",
}
PRE_GAMEDATA_TRACKED_FIELDS = TRACKED_FIELDS - {
    "gamedata_path",
    "gamedata_manifest_sha256",
    "generator_contract_sha256",
}
CONTRACT_TRACKED_FIELDS = PRE_GAMEDATA_TRACKED_FIELDS - {"analysis_config_contract_digest_version"}
LEGACY_TRACKED_FIELDS = CONTRACT_TRACKED_FIELDS - {
    "analysis_config_path",
    "analysis_config_sha256",
    "analysis_config_contract_sha256",
}


def require_gamever(value: str) -> str:
    if not GAMEVER_RE.fullmatch(str(value)):
        raise ReleaseWorkflowError(f"invalid GAMEVER: {value!r}")
    return str(value)


def require_sha(value: str, label: str = "SHA") -> str:
    if not SHA_RE.fullmatch(str(value)):
        raise ReleaseWorkflowError(f"{label} must be a full 40-hex commit SHA")
    return str(value).lower()


def require_mode(value: str) -> str:
    if value not in {"new", "republish"}:
        raise ReleaseWorkflowError(f"invalid release mode: {value!r}")
    return value


def require_build_id(value: str) -> str:
    value = str(value)
    if not BUILD_ID_RE.fullmatch(value):
        raise ReleaseWorkflowError(f"invalid BUILD_ID: {value!r}")
    return value


def format_output_branch(gamever: str, build_id: str) -> str:
    gamever = require_gamever(gamever)
    build_id = require_build_id(build_id)
    return f"gamesymbols/build/{gamever}/{build_id}"


def parse_output_branch(branch: str) -> tuple[str, str]:
    match = BRANCH_RE.fullmatch(branch)
    if not match:
        raise ReleaseWorkflowError(f"invalid generated-output branch: {branch!r}")
    return match.group("gamever"), match.group("build_id")


def parse_abandon_output_branch(branch: str) -> tuple[str, str]:
    for pattern in (BRANCH_RE, LEGACY_BRANCH_RE):
        if match := pattern.fullmatch(branch):
            return match.group("gamever"), match.group("build_id")
    raise ReleaseWorkflowError(f"invalid generated-output abandonment branch: {branch!r}")


def build_tracked_manifest(
    *,
    gamever: str,
    mode: str,
    build_id: str,
    source_sha: str,
    candidate_sha256: str,
    bin_manifest_sha256: str,
    tracked_output_manifest_sha256: str,
    workflow_run_url: str,
    analysis_config_path: str | None = None,
    analysis_config_sha256: str | None = None,
    analysis_config_contract_digest_version: int | None = None,
    analysis_config_contract_sha256: str | None = None,
    gamedata_path: str | None = None,
    gamedata_manifest_sha256: str | None = None,
    generator_contract_sha256: str | None = None,
    target_schema_version: int | None = None,
) -> dict:
    require_gamever(gamever)
    require_mode(mode)
    require_sha(source_sha, "SOURCE_SHA")
    build_id = require_build_id(build_id)
    for label, value in (
        ("candidate_sha256", candidate_sha256),
        ("bin_manifest_sha256", bin_manifest_sha256),
        ("tracked_output_manifest_sha256", tracked_output_manifest_sha256),
    ):
        if len(value) != HEX_SHA256_LENGTH or any(char not in "0123456789abcdef" for char in value):
            raise ReleaseWorkflowError(f"invalid {label}")
    gamedata_values = (gamedata_path, gamedata_manifest_sha256, generator_contract_sha256)
    has_gamedata = all(value is not None for value in gamedata_values)
    if any(value is not None for value in gamedata_values) and not has_gamedata:
        raise ReleaseWorkflowError("gamedata provenance fields must be provided together")
    if has_gamedata:
        if gamedata_path != f"gamedata/{gamever}":
            raise ReleaseWorkflowError("gamedata_path must be the canonical versioned path")
        for label, value in (
            ("gamedata_manifest_sha256", gamedata_manifest_sha256),
            ("generator_contract_sha256", generator_contract_sha256),
        ):
            if len(str(value)) != HEX_SHA256_LENGTH or any(char not in "0123456789abcdef" for char in str(value)):
                raise ReleaseWorkflowError(f"invalid {label}")
    if not workflow_run_url.startswith("https://github.com/"):
        raise ReleaseWorkflowError("workflow_run_url must be a GitHub Actions URL")
    provenance_values = (
        analysis_config_path,
        analysis_config_sha256,
        analysis_config_contract_sha256,
    )
    legacy = all(value is None for value in provenance_values)
    if any(value is None for value in provenance_values) and not legacy:
        raise ReleaseWorkflowError("analysis config provenance fields must be provided together")
    if legacy and analysis_config_contract_digest_version is not None:
        raise ReleaseWorkflowError("legacy manifest cannot record a config digest version")
    if not legacy:
        if analysis_config_path != f"configs/{gamever}.yaml":
            raise ReleaseWorkflowError("analysis_config_path must be the canonical versioned path")
        if (
            not analysis_config_sha256
            or len(analysis_config_sha256) != HEX_SHA256_LENGTH
            or any(char not in "0123456789abcdef" for char in analysis_config_sha256)
        ):
            raise ReleaseWorkflowError("invalid analysis_config_sha256")
        contract_hex = str(analysis_config_contract_sha256 or "").removeprefix("sha256:")
        if len(contract_hex) != HEX_SHA256_LENGTH or any(char not in "0123456789abcdef" for char in contract_hex):
            raise ReleaseWorkflowError("invalid analysis_config_contract_sha256")
        if analysis_config_contract_digest_version not in {None, 1, 2}:
            raise ReleaseWorkflowError("invalid analysis_config_contract_digest_version")
    if has_gamedata and legacy:
        raise ReleaseWorkflowError("versioned gamedata requires analysis config provenance")
    schema_version = LEGACY_SCHEMA_VERSION
    if not legacy:
        schema_version = (
            PRE_GAMEDATA_SCHEMA_VERSION
            if analysis_config_contract_digest_version is not None
            else CONTRACT_SCHEMA_VERSION
        )
    if has_gamedata:
        if analysis_config_contract_digest_version is None:
            raise ReleaseWorkflowError("versioned gamedata requires an analysis config digest version")
        if target_schema_version not in {None, PRE_METADATA_SCHEMA_VERSION, SCHEMA_VERSION}:
            raise ReleaseWorkflowError("invalid versioned gamedata release schema")
        schema_version = target_schema_version or SCHEMA_VERSION
    elif target_schema_version is not None and target_schema_version != schema_version:
        raise ReleaseWorkflowError("explicit release schema does not match manifest fields")
    manifest = {
        "schema_version": schema_version,
        "gamever": gamever,
        "release_tag": gamever,
        "mode": mode,
        "build_id": build_id,
        "source_sha": source_sha.lower(),
        "candidate_sha256": candidate_sha256,
        "bin_manifest_sha256": bin_manifest_sha256,
        "tracked_output_manifest_sha256": tracked_output_manifest_sha256,
        "workflow_run_url": workflow_run_url,
    }
    if not legacy:
        manifest.update(
            {
                "analysis_config_path": analysis_config_path,
                "analysis_config_sha256": analysis_config_sha256,
                "analysis_config_contract_sha256": analysis_config_contract_sha256,
            }
        )
        if analysis_config_contract_digest_version is not None:
            manifest["analysis_config_contract_digest_version"] = analysis_config_contract_digest_version
    if has_gamedata:
        manifest.update(
            {
                "gamedata_path": gamedata_path,
                "gamedata_manifest_sha256": gamedata_manifest_sha256,
                "generator_contract_sha256": generator_contract_sha256,
            }
        )
    return manifest


def tracked_fields_for_schema(schema_version: object) -> set[str]:
    if not isinstance(schema_version, int):
        raise ReleaseWorkflowError(f"unsupported tracked release manifest schema: {schema_version!r}")
    fields_by_schema = {
        LEGACY_SCHEMA_VERSION: LEGACY_TRACKED_FIELDS,
        CONTRACT_SCHEMA_VERSION: CONTRACT_TRACKED_FIELDS,
        PRE_GAMEDATA_SCHEMA_VERSION: PRE_GAMEDATA_TRACKED_FIELDS,
        PRE_METADATA_SCHEMA_VERSION: TRACKED_FIELDS,
        SCHEMA_VERSION: TRACKED_FIELDS,
    }
    fields = fields_by_schema.get(schema_version)
    if fields is None:
        raise ReleaseWorkflowError(f"unsupported tracked release manifest schema: {schema_version!r}")
    return fields


def validate_tracked_manifest(manifest: dict) -> dict:
    fields = tracked_fields_for_schema(manifest.get("schema_version"))
    if set(manifest) != fields:
        raise ReleaseWorkflowError("tracked release manifest has unexpected or missing fields")
    expected = build_tracked_manifest(
        gamever=manifest["gamever"],
        mode=manifest["mode"],
        build_id=manifest["build_id"],
        source_sha=manifest["source_sha"],
        candidate_sha256=manifest["candidate_sha256"],
        bin_manifest_sha256=manifest["bin_manifest_sha256"],
        tracked_output_manifest_sha256=manifest["tracked_output_manifest_sha256"],
        workflow_run_url=manifest["workflow_run_url"],
        analysis_config_path=manifest.get("analysis_config_path"),
        analysis_config_sha256=manifest.get("analysis_config_sha256"),
        analysis_config_contract_digest_version=manifest.get("analysis_config_contract_digest_version"),
        analysis_config_contract_sha256=manifest.get("analysis_config_contract_sha256"),
        gamedata_path=manifest.get("gamedata_path"),
        gamedata_manifest_sha256=manifest.get("gamedata_manifest_sha256"),
        generator_contract_sha256=manifest.get("generator_contract_sha256"),
        target_schema_version=manifest["schema_version"],
    )
    if manifest != expected:
        raise ReleaseWorkflowError("tracked release manifest is not canonical")
    return manifest


def manifest_config_digest_version(manifest: dict, snapshot_document: dict) -> int:
    from gamesymbol_snapshot_lib.codec import snapshot_config_digest_version

    snapshot_version = snapshot_config_digest_version(snapshot_document)
    manifest_version = manifest.get("analysis_config_contract_digest_version")
    if manifest_version is None:
        if snapshot_version != 1:
            raise ReleaseWorkflowError("release manifest lacks digest version for a non-legacy snapshot")
        return 1
    if manifest_version != snapshot_version:
        raise ReleaseWorkflowError("release manifest config digest version does not match snapshot")
    return manifest_version


def load_tracked_manifest(path: Path) -> dict:
    manifest = validate_tracked_manifest(load_json_object(path))
    if Path(path).read_bytes() != canonical_json_bytes(manifest):
        raise ReleaseWorkflowError(f"tracked release manifest is not canonically encoded: {path}")
    return manifest


def verify_tracked_outputs(repo_root: Path, manifest: dict) -> list[dict]:
    inventory = tracked_output_inventory(repo_root, manifest["gamever"])
    if inventory_sha256(inventory) != manifest["tracked_output_manifest_sha256"]:
        raise ReleaseWorkflowError("tracked output manifest hash mismatch")
    snapshot_path = f"gamesymbols/{manifest['gamever']}.yaml"
    snapshot = next(item for item in inventory if item["path"] == snapshot_path)
    if snapshot["sha256"] != manifest["candidate_sha256"]:
        raise ReleaseWorkflowError("published snapshot does not match candidate hash")
    if manifest["schema_version"] in {PRE_METADATA_SCHEMA_VERSION, SCHEMA_VERSION}:
        gamever = manifest["gamever"]
        gamedata_prefix = f"gamedata/{gamever}/"
        gamedata_inventory = [item for item in inventory if item["path"].startswith(gamedata_prefix)]
        if inventory_sha256(gamedata_inventory) != manifest["gamedata_manifest_sha256"]:
            raise ReleaseWorkflowError("versioned gamedata manifest hash mismatch")
        try:
            modules = discover_generator_modules(Path(repo_root) / "gamedata-generators")
        except ValueError as exc:
            raise ReleaseWorkflowError(f"trusted generator contract is invalid: {exc}") from exc
        if generator_contract_sha256(modules) != manifest["generator_contract_sha256"]:
            raise ReleaseWorkflowError("generator contract hash mismatch")
        expected_paths = expected_inventory_paths(
            modules,
            gamever,
            include_metadata=manifest["schema_version"] == SCHEMA_VERSION,
        )
        if [item["path"] for item in gamedata_inventory] != expected_paths:
            raise ReleaseWorkflowError("tracked versioned gamedata paths do not match generator OUTPUT_PATHS")
    return inventory


def write_release_metadata(
    *,
    output_dir: Path,
    manifest: dict,
    output_merge_sha: str,
    tag_sha: str,
    repository: str,
    assets: list[Path],
) -> tuple[Path, Path, Path]:
    output_merge_sha = require_sha(output_merge_sha, "OUTPUT_MERGE_SHA")
    tag_sha = require_sha(tag_sha, "tag SHA")
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    asset_records = [
        {"name": path.name, "size": path.stat().st_size, "sha256": sha256_file(path)} for path in sorted(assets)
    ]
    provenance = {
        "schema_version": SCHEMA_VERSION,
        "gamever": manifest["gamever"],
        "release_tag": manifest["release_tag"],
        "mode": manifest["mode"],
        "build_id": manifest["build_id"],
        "tag_sha": tag_sha,
        "source_sha": manifest["source_sha"],
        "output_merge_sha": output_merge_sha,
        "candidate_sha256": manifest["candidate_sha256"],
        "bin_manifest_sha256": manifest["bin_manifest_sha256"],
        "tracked_output_manifest_sha256": manifest["tracked_output_manifest_sha256"],
        "assets": asset_records,
    }
    for field in (
        "analysis_config_path",
        "analysis_config_sha256",
        "analysis_config_contract_digest_version",
        "analysis_config_contract_sha256",
        "gamedata_path",
        "gamedata_manifest_sha256",
        "generator_contract_sha256",
    ):
        if field in manifest:
            provenance[field] = manifest[field]
    output_dir = Path(output_dir)
    provenance_path = output_dir / f"release-provenance-{manifest['gamever']}.json"
    write_canonical_json(provenance_path, provenance)
    checksum_path = output_dir / f"SHA256SUMS-{manifest['gamever']}.txt"
    checksum_assets = [*assets, provenance_path]
    checksum_path.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in sorted(checksum_assets)),
        encoding="utf-8",
    )
    release_url = f"https://github.com/{repository}/releases/download/{manifest['release_tag']}"
    commit_url = f"https://github.com/{repository}/commit"
    notes_lines = [
        f"## CS2 gamedata {manifest['gamever']}",
        "",
        "Validated release artifacts generated from the accepted repository output.",
        "",
        f"- Build mode: `{manifest['mode']}`",
        f"- Build ID: `{manifest['build_id']}`",
        f"- Source commit: [`{manifest['source_sha'][:7]}`]({commit_url}/{manifest['source_sha']})",
        f"- Output merge: [`{output_merge_sha[:7]}`]({commit_url}/{output_merge_sha})",
        f"- Tag target: [`{tag_sha[:7]}`]({commit_url}/{tag_sha})",
        "",
        "### Downloads",
        "",
    ]
    descriptions = {
        f"gamedata-{manifest['gamever']}.7z": "generated signatures and gamedata",
        f"gamebin-{manifest['gamever']}.7z": "analyzed game binaries",
    }
    for asset in asset_records:
        name = asset["name"]
        description = descriptions.get(name, "release artifact")
        notes_lines.append(f"- [`{name}`]({release_url}/{name}) — {description}")
    notes_lines.extend(
        [
            f"- [`{checksum_path.name}`]({release_url}/{checksum_path.name}) — SHA-256 checksums",
            f"- [`{provenance_path.name}`]({release_url}/{provenance_path.name}) — machine-readable build provenance",
            "",
        ]
    )
    notes_path = output_dir / f"release-notes-{manifest['gamever']}.md"
    notes_path.write_text("\n".join(notes_lines), encoding="utf-8")
    return provenance_path, checksum_path, notes_path

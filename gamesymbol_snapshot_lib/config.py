import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath

import yaml

import analysis_output_contract
import ida_analyze_bin
from gamesymbol_snapshot_lib.errors import SnapshotConfigError
from gamesymbol_snapshot_lib.model import BinaryTarget, ProducerGroup, SkillNode, SnapshotContract
from gamesymbol_snapshot_lib.paths import canonical_key
from trusted_yaml import load_yaml_file

PLATFORMS = ("windows", "linux")
LATEST_CONFIG_DIGEST_VERSION = 2
SUPPORTED_CONFIG_DIGEST_VERSIONS = (1, 2)
V1_LEGACY_SKILL_FIELDS = (
    "name",
    "platform",
    "expected_output",
    "expected_output_windows",
    "expected_output_linux",
    "optional_output",
    "expected_input",
    "expected_input_windows",
    "expected_input_linux",
    "prerequisite",
    "skip_if_exists",
)
V1_ADDITIVE_FIELDS = (
    "optional_input",
    "optional_input_windows",
    "optional_input_linux",
)
V1_SKILL_FIELDS = (*V1_LEGACY_SKILL_FIELDS, *V1_ADDITIVE_FIELDS)
V2_SKILL_FIELDS = (
    "name",
    "platform",
    "expected_output",
    "expected_output_windows",
    "expected_output_linux",
    "optional_output",
    "expected_input",
    "expected_input_windows",
    "expected_input_linux",
    "optional_input",
    "optional_input_windows",
    "optional_input_linux",
    "prerequisite",
    "skip_if_exists",
)
V2_DOMAIN_SEPARATOR = b"gamesymbol-config-contract:v2\n"


def _load_raw_config(config_path: Path) -> dict:
    try:
        raw = load_yaml_file(config_path, cache=True) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise SnapshotConfigError(f"unable to read config {config_path}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("modules", []), list):
        raise SnapshotConfigError("analysis config must contain a modules list")
    return raw


def _string_list(value, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise SnapshotConfigError(f"{field} must be a list of non-empty strings")
    return list(value)


def _normalized_skill_v1(skill: object, context: str) -> dict:
    if not isinstance(skill, dict):
        raise SnapshotConfigError(f"{context} skill must be a mapping")
    normalized = {}
    for field in V1_SKILL_FIELDS:
        value = skill.get(field)
        if field in {"name", "platform"}:
            if value is not None and not isinstance(value, str):
                raise SnapshotConfigError(f"{context}.{field} must be a string")
            normalized[field] = value
        else:
            values = _string_list(value, f"{context}.{field}")
            if field in V1_ADDITIVE_FIELDS and not values:
                continue
            normalized[field] = values
    return normalized


def _normalized_skill_v2(skill: object, context: str) -> dict:
    if not isinstance(skill, dict):
        raise SnapshotConfigError(f"{context} skill must be a mapping")
    normalized = {}
    for field in V2_SKILL_FIELDS:
        value = skill.get(field)
        if field in {"name", "platform"}:
            if value is not None and not isinstance(value, str):
                raise SnapshotConfigError(f"{context}.{field} must be a string")
            normalized[field] = value
        else:
            normalized[field] = _string_list(value, f"{context}.{field}")
    return normalized


def _normalized_contract(raw: dict, config_digest_version: int) -> list[dict]:
    if config_digest_version not in SUPPORTED_CONFIG_DIGEST_VERSIONS:
        raise SnapshotConfigError(f"unsupported config digest version: {config_digest_version!r}")
    normalize_skill = _normalized_skill_v1 if config_digest_version == 1 else _normalized_skill_v2
    modules = []
    for stage_index, module in enumerate(raw.get("modules", [])):
        if not isinstance(module, dict):
            raise SnapshotConfigError(f"modules[{stage_index}] must be a mapping")
        name = module.get("name")
        if not isinstance(name, str) or not name:
            raise SnapshotConfigError(f"modules[{stage_index}].name must be a non-empty string")
        entry = {"stage_index": stage_index, "name": name}
        for platform in PLATFORMS:
            field = f"path_{platform}"
            value = module.get(field)
            if value is not None and not isinstance(value, str):
                raise SnapshotConfigError(f"modules[{stage_index}].{field} must be a string")
            entry[field] = {"present": field in module, "value": value}
        skills = module.get("skills", []) or []
        if not isinstance(skills, list):
            raise SnapshotConfigError(f"modules[{stage_index}].skills must be a list")
        entry["skills"] = [
            normalize_skill(skill, f"modules[{stage_index}].skills[{index}]") for index, skill in enumerate(skills)
        ]
        modules.append(entry)
    return modules


def _digest(normalized: list[dict], config_digest_version: int) -> str:
    encoded = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if config_digest_version == 2:
        encoded = V2_DOMAIN_SEPARATOR + encoded
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _unversioned_digest(normalized: list[dict]) -> str:
    encoded = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _resolved_keys(binary_dir: Path, paths: list[str], platform: str, game_root: Path) -> frozenset[str]:
    resolved = []
    for path in paths:
        artifact = ida_analyze_bin.resolve_artifact_path(str(binary_dir), path, platform)
        key = canonical_key(game_root, artifact)
        if key.endswith(".yaml"):
            resolved.append(key)
    return frozenset(resolved)


def _make_node(module: dict, skill: dict, skill_index: int, platform: str, game_root: Path) -> SkillNode:
    binary_dir = game_root / module["name"]
    required, optional, _combined = ida_analyze_bin.expand_skill_output_paths(str(binary_dir), skill, platform)
    required_keys = frozenset(canonical_key(game_root, path) for path in required if path.endswith(".yaml"))
    optional_keys = frozenset(canonical_key(game_root, path) for path in optional if path.endswith(".yaml"))
    required_input_paths = list(skill.get("expected_input", []) or [])
    required_input_paths += list(skill.get(f"expected_input_{platform}", []) or [])
    optional_input_paths = list(skill.get("optional_input", []) or [])
    optional_input_paths += list(skill.get(f"optional_input_{platform}", []) or [])
    required_inputs = _resolved_keys(binary_dir, required_input_paths, platform, game_root)
    optional_inputs = _resolved_keys(binary_dir, optional_input_paths, platform, game_root)
    alternative_output_paths = _string_list(
        skill.get("alternative_output"),
        f"modules[{module['stage_index']}].skills[{skill_index}].alternative_output",
    )
    alternative_output_paths += _string_list(
        skill.get(f"alternative_output_{platform}"),
        f"modules[{module['stage_index']}].skills[{skill_index}].alternative_output_{platform}",
    )
    alternative_outputs = _resolved_keys(binary_dir, alternative_output_paths, platform, game_root)
    undeclared_alternatives = alternative_outputs - (required_keys | optional_keys)
    if undeclared_alternatives:
        raise SnapshotConfigError(
            f"alternative outputs must also be declared outputs: {', '.join(sorted(undeclared_alternatives))}"
        )
    node_id = f"{module['stage_index']}:{skill_index}:{module['name']}:{platform}:{skill['name']}"
    fingerprint_data = {
        "stage_index": module["stage_index"],
        "module_name": module["name"],
        "binary_path": module.get(f"path_{platform}"),
        "skill_name": skill["name"],
        "platform": platform,
        "required_outputs": sorted(required_keys),
        "optional_outputs": sorted(optional_keys),
        "required_inputs": sorted(required_inputs),
        "optional_inputs": sorted(optional_inputs),
        "alternative_outputs": sorted(alternative_outputs),
        "prerequisites": list(skill.get("prerequisite", []) or []),
        "skip_if_exists": list(skill.get("skip_if_exists", []) or []),
    }
    fingerprint = hashlib.sha256(
        json.dumps(fingerprint_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return SkillNode(
        node_id,
        (module["name"], skill["name"], platform),
        module["stage_index"],
        module["name"],
        skill["name"],
        platform,
        required_keys,
        optional_keys,
        required_inputs,
        optional_inputs,
        alternative_outputs,
        tuple(skill.get("prerequisite", []) or []),
        fingerprint,
    )


def _collect_nodes(modules: list[dict], game_root: Path) -> dict[str, SkillNode]:
    nodes = {}
    for module in modules:
        for platform in PLATFORMS:
            if not module.get(f"path_{platform}"):
                continue
            for skill_index, skill in enumerate(module.get("skills", []) or []):
                if not ida_analyze_bin._skill_runs_on_platform(skill, platform):
                    continue
                node = _make_node(module, skill, skill_index, platform, game_root)
                nodes[node.node_id] = node
    return nodes


def _group_fingerprint(
    *, artifact_path: str, required: bool, alternative_node_ids: tuple[str, ...], nodes: dict[str, SkillNode]
) -> str:
    payload = {
        "artifact_path": artifact_path,
        "required": required,
        "alternatives": [
            {"node_id": node_id, "fingerprint": nodes[node_id].fingerprint} for node_id in alternative_node_ids
        ],
    }
    encoded = b"source2-producer-group:v1\n" + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _collect_paths(nodes: dict[str, SkillNode], *, require_explicit_producer_groups: bool):
    required = set()
    optional = set()
    ordered_owners: dict[str, list[str]] = {}
    case_spellings = {}
    for node in nodes.values():
        for path in node.outputs:
            prior = case_spellings.setdefault(path.casefold(), path)
            if prior != path:
                raise SnapshotConfigError(f"case-insensitive artifact collision: {prior} and {path}")
            ordered_owners.setdefault(path, []).append(node.node_id)
        required.update(node.required_outputs)
        optional.update(node.optional_outputs)
    optional.difference_update(required)
    formal_paths = required | optional
    for node in nodes.values():
        undeclared_inputs = node.inputs - formal_paths
        if undeclared_inputs:
            raise SnapshotConfigError(
                f"artifact inputs must resolve to a formal output: {', '.join(sorted(undeclared_inputs))}"
            )

    groups = {}
    group_ids_by_path = {}
    for path in sorted(formal_paths):
        alternatives = tuple(ordered_owners[path])
        marked = tuple(node_id for node_id in alternatives if path in nodes[node_id].alternative_outputs)
        if len(alternatives) == 1 and marked:
            raise SnapshotConfigError(f"alternative output has only one producer: {path}")
        if len(alternatives) > 1 and marked and marked != alternatives:
            raise SnapshotConfigError(f"all producers must mark the shared alternative output: {path}")
        if len(alternatives) > 1 and require_explicit_producer_groups and not marked:
            raise SnapshotConfigError(f"duplicate producers require an explicit alternative output group: {path}")
        group_id = f"producer-group:{path}"
        group_ids_by_path[path] = group_id
        input_paths = frozenset().union(*(nodes[node_id].inputs for node_id in alternatives))
        groups[group_id] = ProducerGroup(
            group_id=group_id,
            artifact_path=path,
            required=path in required,
            alternative_node_ids=alternatives,
            input_paths=input_paths,
            upstream_group_ids=(),
            fingerprint=_group_fingerprint(
                artifact_path=path,
                required=path in required,
                alternative_node_ids=alternatives,
                nodes=nodes,
            ),
        )

    for group_id, group in tuple(groups.items()):
        groups[group_id] = ProducerGroup(
            group_id=group.group_id,
            artifact_path=group.artifact_path,
            required=group.required,
            alternative_node_ids=group.alternative_node_ids,
            input_paths=group.input_paths,
            upstream_group_ids=tuple(sorted({group_ids_by_path[path] for path in group.input_paths})),
            fingerprint=group.fingerprint,
        )
    frozen_owners = {path: frozenset(node_ids) for path, node_ids in ordered_owners.items()}
    return frozenset(required), frozenset(optional), frozen_owners, groups, group_ids_by_path


def _validate_binary_source_path(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise SnapshotConfigError(f"{context} must be a non-empty string")
    if "\\" in value or PureWindowsPath(value).is_absolute():
        raise SnapshotConfigError(f"{context} must be a relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or "//" in value or any(part in {"", ".", ".."} for part in path.parts):
        raise SnapshotConfigError(f"{context} is unsafe: {value!r}")
    return path.as_posix()


def _collect_binary_targets(modules: list[dict]) -> dict[tuple[str, str], BinaryTarget]:
    targets = {}
    case_spellings = {}
    for module in modules:
        module_name = module["name"]
        if module_name in {".", ".."} or "/" in module_name or "\\" in module_name:
            raise SnapshotConfigError(f"invalid binary module name: {module_name!r}")
        prior_module = case_spellings.setdefault(module_name.casefold(), module_name)
        if prior_module != module_name:
            raise SnapshotConfigError(f"case-insensitive binary module collision: {prior_module!r} and {module_name!r}")
        for platform in PLATFORMS:
            raw_path = module.get(f"path_{platform}")
            if raw_path is None:
                continue
            source_path = _validate_binary_source_path(
                raw_path,
                f"modules[{module['stage_index']}].path_{platform}",
            )
            key = (module_name, platform)
            previous = targets.get(key)
            if previous is not None and previous.source_path != source_path:
                raise SnapshotConfigError(
                    f"conflicting binary path for {module_name}/{platform}: "
                    f"{previous.source_path!r} and {source_path!r}"
                )
            targets[key] = BinaryTarget(module_name, platform, source_path)
    return targets


def _build_contract(
    config_document,
    game_version,
    bindir,
    artifactdir,
    config_digest_version: int,
    config_sha256: str,
    *,
    require_explicit_producer_groups: bool,
) -> SnapshotContract:
    bindir = Path(bindir)
    artifactdir = Path(artifactdir)
    game_version = str(game_version)
    try:
        modules = ida_analyze_bin.parse_config_document(config_document)
        ida_analyze_bin.validate_module_skill_dependencies(modules)
        nodes = _collect_nodes(modules, artifactdir / game_version)
        binary_targets = _collect_binary_targets(modules)
    except (OSError, ValueError, TypeError) as exc:
        raise SnapshotConfigError(f"invalid analysis contract: {exc}") from exc
    required, optional, owners, producer_groups, group_ids_by_path = _collect_paths(
        nodes,
        require_explicit_producer_groups=require_explicit_producer_groups,
    )
    return SnapshotContract(
        game_version,
        bindir / game_version,
        artifactdir / game_version,
        config_digest_version,
        config_sha256,
        analysis_output_contract.ANALYSIS_OUTPUT_CONTRACT_VERSION,
        required,
        optional,
        owners,
        nodes,
        binary_targets,
        producer_groups,
        group_ids_by_path,
    )


def load_contract(
    config_path,
    game_version,
    bindir,
    config_digest_version: int = LATEST_CONFIG_DIGEST_VERSION,
    *,
    artifactdir=None,
    require_explicit_producer_groups: bool = False,
) -> SnapshotContract:
    config_path = Path(config_path)
    raw = _load_raw_config(config_path)
    normalized = _normalized_contract(raw, config_digest_version)
    return _build_contract(
        raw,
        game_version,
        bindir,
        Path(bindir).parent / "bin_artifacts" if artifactdir is None else artifactdir,
        config_digest_version,
        _digest(normalized, config_digest_version),
        require_explicit_producer_groups=require_explicit_producer_groups,
    )


def load_unversioned_schema1_contract(
    config_path,
    game_version,
    bindir,
    *,
    artifactdir=None,
) -> SnapshotContract:
    """Load the short-lived schema-1 digest representation used before digest versioning."""
    config_path = Path(config_path)
    raw = _load_raw_config(config_path)
    normalized = _normalized_contract(raw, 2)
    return _build_contract(
        raw,
        game_version,
        bindir,
        Path(bindir).parent / "bin_artifacts" if artifactdir is None else artifactdir,
        1,
        _unversioned_digest(normalized),
        require_explicit_producer_groups=False,
    )

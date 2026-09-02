from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ChangedPath:
    status: str
    old_path: str | None
    new_path: str | None

    def __post_init__(self) -> None:
        status = self.status.upper()
        if status not in {"A", "M", "D", "R", "C"}:
            raise ValueError(f"unsupported Git change status: {self.status!r}")
        old_path = self._normalize_path(self.old_path)
        new_path = self._normalize_path(self.new_path)
        if status == "A" and (old_path is not None or new_path is None):
            raise ValueError("added path requires only new_path")
        if status == "D" and (old_path is None or new_path is not None):
            raise ValueError("deleted path requires only old_path")
        if status in {"M", "R", "C"} and (old_path is None or new_path is None):
            raise ValueError(f"{status} path requires old_path and new_path")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "old_path", old_path)
        object.__setattr__(self, "new_path", new_path)

    @staticmethod
    def _normalize_path(path: str | None) -> str | None:
        if path is None:
            return None
        normalized = path.replace("\\", "/").removeprefix("./")
        if not normalized:
            raise ValueError("changed path must not be empty")
        return normalized


@dataclass(frozen=True)
class SkillNode:
    node_id: str
    logical_key: tuple[str, str, str]
    stage_index: int
    module_name: str
    skill_name: str
    platform: str
    required_outputs: frozenset[str]
    optional_outputs: frozenset[str]
    required_inputs: frozenset[str]
    optional_inputs: frozenset[str]
    alternative_outputs: frozenset[str]
    prerequisites: tuple[str, ...]
    fingerprint: str

    @property
    def outputs(self) -> frozenset[str]:
        return self.required_outputs | self.optional_outputs

    @property
    def inputs(self) -> frozenset[str]:
        return self.required_inputs | self.optional_inputs


@dataclass(frozen=True)
class ProducerGroup:
    group_id: str
    artifact_path: str
    required: bool
    alternative_node_ids: tuple[str, ...]
    input_paths: frozenset[str]
    upstream_group_ids: tuple[str, ...]
    fingerprint: str


@dataclass(frozen=True)
class BinaryTarget:
    module_name: str
    platform: str
    source_path: str


@dataclass(frozen=True)
class SnapshotContract:
    game_version: str
    binary_game_root: Path
    artifact_game_root: Path
    config_digest_version: int
    config_sha256: str
    analysis_output_contract_version: int
    required_paths: frozenset[str]
    optional_paths: frozenset[str]
    owners_by_path: dict[str, frozenset[str]]
    nodes: dict[str, SkillNode]
    binary_targets: dict[tuple[str, str], BinaryTarget]
    producer_groups: dict[str, ProducerGroup]
    producer_group_ids_by_path: dict[str, str]

    @property
    def game_root(self) -> Path:
        """Compatibility alias for artifact readers during the dual-root migration."""
        return self.artifact_game_root

    @property
    def formal_paths(self) -> frozenset[str]:
        return self.required_paths | self.optional_paths

    def producer_group_for_path(self, artifact_path: str) -> ProducerGroup:
        group_id = self.producer_group_ids_by_path[artifact_path]
        return self.producer_groups[group_id]

    def downstream_group_ids(self, seed_group_ids: set[str] | frozenset[str]) -> frozenset[str]:
        selected = set(seed_group_ids)
        unknown = selected - set(self.producer_groups)
        if unknown:
            raise KeyError(f"unknown producer groups: {', '.join(sorted(unknown))}")
        changed = True
        while changed:
            changed = False
            for group_id, group in self.producer_groups.items():
                if group_id not in selected and selected.intersection(group.upstream_group_ids):
                    selected.add(group_id)
                    changed = True
        return frozenset(selected)


@dataclass(frozen=True)
class SnapshotContext:
    document: dict
    raw_bytes: bytes
    contract: SnapshotContract


@dataclass(frozen=True)
class InvalidationPlan:
    paths: frozenset[str]
    node_ids: frozenset[str]
    reasons: tuple[str, ...]

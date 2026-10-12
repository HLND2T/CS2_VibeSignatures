from pathlib import Path

import yaml

import binary_lock
from gamesymbol_snapshot_lib.config import load_contract


# One canonical `gv` artifact for gates that need a category with an anchor group:
# its locator fields may drift while gv_va/gv_rva stay pinned.
GLOBAL_ARTIFACT_PAYLOAD = {
    "gv_name": "G",
    "gv_va": "0x182226f08",
    "gv_rva": "0x2226f08",
    "gv_sig": "48 89 15 ?? ?? ?? ?? 48 89 42 ??",
    "gv_sig_va": "0x180b7f32c",
    "gv_inst_offset": 0,
    "gv_inst_length": 7,
    "gv_inst_disp": 3,
}


def write_yaml(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def write_binary(path: Path, data: bytes | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if data is not None else f"binary:{path.name}".encode("utf-8"))


def write_config(path: Path, modules) -> None:
    write_yaml(path, {"modules": modules})


def write_source_binary_lock(root: Path, game_version: str) -> dict:
    contract = load_contract(
        root / "configs" / f"{game_version}.yaml",
        game_version,
        root / "bin",
        artifactdir=root / "bin_artifacts",
    )
    document = binary_lock.build_binary_lock_from_root(
        game_version=game_version,
        download_payload=(root / "download.yaml").read_bytes(),
        binary_targets=contract.binary_targets,
        binary_root=contract.binary_game_root,
    )
    binary_lock.write_binary_lock(root / "binary_locks" / f"{game_version}.json", document)
    return document


def module(name: str, skills, *, windows: bool = True, linux: bool = True):
    value = {"name": name, "skills": skills}
    if windows:
        value["path_windows"] = f"game/bin/win64/{name}.dll"
    if linux:
        value["path_linux"] = f"game/bin/linuxsteamrt64/{name}.so"
    return value


def skill(name: str, outputs, **extra):
    return {"name": name, "expected_output": outputs, **extra}

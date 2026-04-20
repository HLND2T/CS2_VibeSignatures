#!/usr/bin/env python3
"""Preprocess script for find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate skill."""

import os
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
]

FUNC_VTABLE_RELATIONS = [
    (
        "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
        "CSpawnGroupMgrGameSystem_vtable2",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            #"func_sig", # does't really make any sense for a function with sfunc_sizeize = 0xe
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
            #"func_sig_allow_across_function_boundary:true",
        ],
    ),
]

# Signature templates — last byte is IGameSystemFactory_DoesGameSystemReallocate vfunc_offset
# Windows: mov rcx, cs:[rip+??]; mov rax, [rcx]; jmp [rax+OFFSET]
_SIG_WINDOWS_TEMPLATE = "48 8B 0D ?? ?? ?? ?? 48 8B 01 48 FF 60 {:02X}"
# Linux: mov rdi, cs:[rip+??]; mov rax, [rdi]; jmp [rax+OFFSET]
_SIG_LINUX_TEMPLATE = "48 8B 3D ?? ?? ?? ?? 48 8B 07 FF 60 {:02X}"
_FACTORY_STEM = "IGameSystemFactory_DoesGameSystemReallocate"


def _build_factory_yaml_paths(new_binary_dir, platform):
    """Return candidate paths for the factory vfunc YAML."""
    filename = f"{_FACTORY_STEM}.{platform}.yaml"
    module_dir = Path(new_binary_dir)
    candidates = [module_dir / filename]
    sibling_client_path = module_dir.parent / "client" / filename
    if sibling_client_path.resolve() != candidates[0].resolve():
        candidates.append(sibling_client_path)
    return [os.fspath(path) for path in candidates]


def _read_vfunc_offset(yaml_path):
    """Read vfunc_offset from a YAML file, returning integer or None."""
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            val = data.get("vfunc_offset")
            if val is not None:
                return int(str(val).strip(), 0)
    except Exception:
        pass
    return None


def _read_factory_vfunc_offset(new_binary_dir, platform):
    """Read the factory vfunc offset from local or sibling-client YAML."""
    for yaml_path in _build_factory_yaml_paths(new_binary_dir, platform):
        vfunc_offset = _read_vfunc_offset(yaml_path)
        if vfunc_offset is not None:
            return vfunc_offset, yaml_path
    return None, None


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Locate CSpawnGroupMgrGameSystem_DoesGameSystemReallocate via factory vfunc thunk signature."""
    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required")
        return False

    # Load vfunc_offset from IGameSystemFactory_DoesGameSystemReallocate YAML
    vfunc_offset, factory_yaml_path = _read_factory_vfunc_offset(
        new_binary_dir,
        platform,
    )
    if vfunc_offset is None:
        if debug:
            print(
                "    Preprocess: failed to read vfunc_offset from "
                "IGameSystemFactory_DoesGameSystemReallocate YAML"
            )
        return False

    if vfunc_offset > 0x7F:
        if debug:
            print(
                f"    Preprocess: vfunc_offset 0x{vfunc_offset:X} exceeds disp8 range, "
                "signature template needs update"
            )
        return False

    # Build platform-specific signature
    if platform == "windows":
        sig = _SIG_WINDOWS_TEMPLATE.format(vfunc_offset)
    elif platform == "linux":
        sig = _SIG_LINUX_TEMPLATE.format(vfunc_offset)
    else:
        return False

    if debug:
        print(
            "    Preprocess: using xref signature from "
            f"{os.path.basename(factory_yaml_path)}: {sig}"
        )

    func_xrefs = [
        {
            "func_name": "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
            "xref_strings": [],
            "xref_gvs": [],
            "xref_signatures": [sig],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": [],
        },
    ]

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )

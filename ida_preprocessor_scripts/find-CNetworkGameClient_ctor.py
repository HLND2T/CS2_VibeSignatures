import os

import yaml

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CNetworkGameClient_ctor"]

GENERATE_YAML_DESIRED_FIELDS = [
    ("CNetworkGameClient_ctor", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]


def _read_vtable_va(yaml_path):
    try:
        with open(yaml_path, "r", encoding="utf-8") as file_handle:
            data = yaml.safe_load(file_handle)
        if isinstance(data, dict) and data.get("vtable_va"):
            return str(data["vtable_va"])
    except Exception:
        pass
    return None


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    vtable_path = os.path.join(new_binary_dir, f"CNetworkGameClient_vtable.{platform}.yaml")
    vtable_va = _read_vtable_va(vtable_path)
    if not vtable_va:
        if debug:
            print("    Preprocess: CNetworkGameClient_vtable vtable_va not found")
        return False
    func_xrefs = [{
        "func_name": "CNetworkGameClient_ctor",
        "xref_strings": [],
        "xref_gvs": [vtable_va],
        "xref_signatures": [],
        "xref_funcs": ["CNetworkGameClientBase_ctor"],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }]
    return await preprocess_common_skill(
        session=session, expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map, new_binary_dir=new_binary_dir, platform=platform,
        image_base=image_base, func_names=TARGET_FUNCTION_NAMES, func_xrefs=func_xrefs,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS, debug=debug,
    )

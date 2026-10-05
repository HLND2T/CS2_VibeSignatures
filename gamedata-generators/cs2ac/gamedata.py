#!/usr/bin/env python3
"""Update CS2AC VDF gamedata from snapshot signatures and offsets."""

import os
import sys
from pathlib import Path

import vdf

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from gamedata_utils import convert_sig_to_cs2fixes, normalize_func_name_colons_to_underscore


MODULE_NAME = "CS2AC"
MODULE_ENABLED = True
GAMEDATA_PATH = "gamedata/cs2ac.games.txt"
OUTPUT_PATHS = (GAMEDATA_PATH,)
DOWNLOAD_SOURCES = ()
STATIC_SOURCES = (("templates/cs2ac.games.txt", GAMEDATA_PATH),)

# Ordered fields preserve virtual-function offset precedence.
SECTION_FIELDS = {
    "Signatures": (("func_sig", "signature"), ("gv_sig", "signature")),
    "Offsets": (("vfunc_index", "offset"), ("struct_member_offset", "struct_offset")),
}


def update(yaml_data, func_lib_map, platforms, output_dir, alias_to_name_map, debug=False):
    """Replace available values; count missing values once per requested platform."""
    gamedata_path = Path(output_dir) / GAMEDATA_PATH
    gamedata = vdf.loads(gamedata_path.read_text(encoding="utf-8-sig"))
    csgo = gamedata["Games"]["csgo"]
    requested_platforms = tuple(dict.fromkeys(platforms))
    updated_count = 0
    skipped_count = 0
    updated_symbols = []
    skipped_symbols = []

    for section, fields in SECTION_FIELDS.items():
        for name, entry in csgo.get(section, {}).items():
            symbol_name = normalize_func_name_colons_to_underscore(name, alias_to_name_map)
            symbol = yaml_data.get(symbol_name)
            reason = None
            if section == "Signatures":
                library = entry.get("library") or func_lib_map.get(symbol_name)
                if not library:
                    reason = "unknown library"
                elif symbol and symbol.get("library") != library:
                    reason = "library mismatch"
            if reason is None and not symbol:
                reason = "no matching YAML data"

            for platform in requested_platforms:
                platform_reason = reason
                platform_data = symbol.get(platform) if symbol else None
                field = None
                if platform_reason is None:
                    if not platform_data:
                        platform_reason = "missing platform data"
                    else:
                        field = next(((key, kind) for key, kind in fields if platform_data.get(key) is not None), None)
                        if field is None:
                            platform_reason = "missing " + " or ".join(key for key, _ in fields)

                if platform_reason is not None:
                    skipped_count += 1
                    if debug:
                        skipped_symbols.append({"name": name, "platform": platform, "reason": platform_reason})
                    continue

                key, kind = field
                value = platform_data[key]
                entry[platform] = convert_sig_to_cs2fixes(value) if section == "Signatures" else str(value)
                updated_count += 1
                if debug:
                    updated_symbols.append({"name": name, "type": kind, "platform": platform})

    # Match the existing VDF generator's single-backslash signature encoding.
    content = vdf.dumps(gamedata, pretty=True).replace("\\\\x", "\\x")
    gamedata_path.write_text(content, encoding="utf-8-sig")
    return updated_count, skipped_count, updated_symbols, skipped_symbols

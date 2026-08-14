#!/usr/bin/env python3
"""Push accumulated IDA symbols to every configured binary's BinSync remote.

Each configured Windows/Linux binary is resolved from the analysis config and
force-pushed from the IDA artifacts already persisted in that binary's ``.i64``
database. Pushes are mandatory: a missing interpreter/headless script/capability
or any individual push failure makes this script exit non-zero, so callers
(e.g. the release workflow) can enforce that the BinSync flow must succeed.
"""

import argparse
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from init_gamebin import (  # noqa: E402
    iter_configured_binaries,
    load_yaml_document,
    resolve_analysis_config,
)

# Symbol categories that map to a BinSync function vs. global-variable artifact.
FUNCTION_CATEGORIES = frozenset({"func", "vfunc"})
GLOBAL_CATEGORIES = frozenset({"gv"})

# Mirror the exact imports headless_force_push.py performs, so a passing probe
# guarantees the push script can actually start in the same interpreter.
CAPABILITY_PROBE = "import idapro, binsync.controller, declib.decompilers.ida.interface"


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gamever", help="Exact GAMEVER from download.yaml")
    parser.add_argument("--python", required=True, help="Interpreter with idalib + binsync + declib")
    parser.add_argument(
        "--headless-script",
        default=str(REPOSITORY_ROOT / "headless_force_push.py"),
        help="Path to headless_force_push.py (defaults to the repo copy)",
    )
    return parser.parse_args(argv)


def probe_capability(python_exe: str) -> tuple[bool, str]:
    """Return whether ``python_exe`` can import the push script's runtime deps."""
    result = subprocess.run([python_exe, "-c", CAPABILITY_PROBE], capture_output=True, text=True, check=False)
    if result.returncode == 0:
        return True, ""
    return False, (result.stderr or result.stdout).strip()


def push_binary(python_exe: str, headless_script: str, binary_path: Path, manifest_path: Path) -> int:
    """Run headless_force_push.py for one binary in its own idalib process."""
    cmd = [python_exe, headless_script, str(binary_path), "--push"]
    if manifest_path is not None:
        cmd += ["--artifacts-file", str(manifest_path)]
    return subprocess.run(cmd, check=False).returncode


def _pe_first_section_rva(data: bytes) -> int:
    """Return the RVA (offset from the image base) of the first PE section.

    declib's ``binary_base_addr`` is ``get_first_segment_base()`` -- the VA of
    IDA's first segment, which for a PE is the first (lowest-address) section,
    i.e. ``image_base + <section RVA>`` (0x1000 for ``.text`` in these game
    binaries). This is the address-space offset declib subtracts when lifting.
    """
    if data[:2] != b"MZ":
        raise ValueError("not a PE (missing MZ signature)")
    if len(data) < 0x40:
        raise ValueError("truncated DOS header")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\x00\x00":
        raise ValueError("invalid PE signature")
    num_sections = struct.unpack_from("<H", data, pe + 6)[0]
    size_opt = struct.unpack_from("<H", data, pe + 20)[0]
    sec_tbl = pe + 24 + size_opt
    if num_sections == 0:
        raise ValueError("PE has no sections")
    first_rva = None
    for index in range(num_sections):
        off = sec_tbl + index * 40
        if off + 40 > len(data):
            raise ValueError("truncated PE section table")
        rva = struct.unpack_from("<I", data, off + 12)[0]
        if first_rva is None or rva < first_rva:
            first_rva = rva
    if first_rva is None:
        raise ValueError("PE has no sections")
    return first_rva


def _first_segment_lift_bias(binary_path: Path) -> int:
    """Address delta between a YAML ``*_rva`` and BinSync's lifted key.

    ``{symbol}.{platform}.yaml`` stores ``func_rva = func_va - image_base`` (the
    PE image base, 0x180000000 for these; 0 for ELF). BinSync's declib interface
    keys functions/globals by ``func_va - get_first_segment_base()``, where the
    "first segment" is the *lowest-address* IDA segment -- ``.text`` for a PE,
    which starts at ``image_base + first_section_rva``. The two conventions
    differ by the first section's RVA on Windows and coincide on Linux (these
    ELF shared objects load at vaddr 0, so the first segment base is 0):

        windows:  declib key == func_rva - 0x1000   (.text at RVA 0x1000)
        linux:    declib key == func_rva

    Return the amount to subtract from a YAML ``*_rva`` so the manifest matches
    declib's lifted keys, i.e. BinSync can find the function/global by address.
    """
    data = binary_path.read_bytes()
    if data[:4] == b"\x7fELF":
        # ELF shared objects in this repo load at vaddr 0; YAML rva == func_va
        # == declib's lifted key already.
        return 0
    if data[:2] == b"MZ":
        return _pe_first_section_rva(data)
    raise ValueError(f"unsupported binary format for lift bias: {binary_path}")


def collect_manifest_symbols(root: Path, gamever: str, config_path: Path) -> dict[str, dict[str, list[int]]]:
    """Map ``(module, platform) -> {"functions": [rva, ...], "globals": [rva, ...]}``.

    Only ``func``/``vfunc`` and ``gv`` symbols explicitly declared under each
    module's ``symbols:`` are selected. The target address is read from the
    generated ``{symbol}.{platform}.yaml`` (``func_rva`` for functions, ``gv_rva``
    for globals). The YAML ``*_rva`` is relative to the PE image base on Windows
    and to vaddr 0 on Linux; BinSync's declib key is relative to the first
    (lowest-address) IDA segment, so the ``*_rva`` is adjusted by the first
    section's RVA on Windows (0x1000 here) before the manifest is built.
    Types, segments, and undeclared functions/globals are deliberately excluded.
    """
    document = load_yaml_document(config_path, "analysis config")
    modules = document.get("modules") or []
    manifest: dict[str, dict[str, list[int]]] = {}

    for module_name, platform, binary_path in iter_configured_binaries(root, gamever, config_path):
        module_dir = binary_path.parent
        try:
            lift_bias = _first_segment_lift_bias(binary_path)
        except ValueError as exc:
            print(
                f"BinSync push skipped (unsupported binary): {binary_path.name}: {exc}",
                file=sys.stderr,
            )
            continue
        functions: list[int] = []
        globals: list[int] = []

        for module in modules:
            if module.get("name") != module_name:
                continue
            for symbol in module.get("symbols") or []:
                category = symbol.get("category")
                symbol_name = symbol.get("name")
                if not isinstance(symbol_name, str) or category not in FUNCTION_CATEGORIES | GLOBAL_CATEGORIES:
                    continue
                symbol_platform = symbol.get("platform")
                if symbol_platform and symbol_platform != platform:
                    continue

                yaml_path = module_dir / f"{symbol_name}.{platform}.yaml"
                try:
                    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
                except (OSError, yaml.YAMLError):
                    continue

                key = "func_rva" if category in FUNCTION_CATEGORIES else "gv_rva"
                raw = data.get(key)
                try:
                    addr = int(str(raw), 0)
                except (TypeError, ValueError):
                    continue
                # Convert the YAML rva (relative to image base / vaddr 0) to the
                # declib lifted key (relative to the first IDA segment) so BinSync
                # finds the artifact by address. No-op on Linux (bias 0).
                addr -= lift_bias
                (functions if category in FUNCTION_CATEGORIES else globals).append(addr)

        manifest[f"{module_name}/{platform}"] = {
            "functions": sorted(set(functions)),
            "globals": sorted(set(globals)),
        }

    return manifest


def build_manifest(entries: dict[str, list]) -> Path:
    """Write a temp JSON manifest and return its path."""
    fd, path = tempfile.mkstemp(prefix="binsync_manifest_", suffix=".json")
    with open(fd, "w", encoding="utf-8") as handle:
        json.dump(entries, handle)
    return Path(path)


def main(argv=None) -> int:
    args = parse_args(argv)

    python_exe = shutil.which(args.python)
    if not python_exe:
        print(f"BinSync push failed: python not found: {args.python}", file=sys.stderr)
        return 1

    if not Path(args.headless_script).is_file():
        print(f"BinSync push failed: headless script not found: {args.headless_script}", file=sys.stderr)
        return 1

    supported, detail = probe_capability(python_exe)
    if not supported:
        print(f"BinSync push failed: {python_exe} lacks idalib/binsync/declib", file=sys.stderr)
        if detail:
            print(detail, file=sys.stderr)
        return 1

    config_path = resolve_analysis_config(args.gamever, repo_root=REPOSITORY_ROOT)
    manifests = collect_manifest_symbols(REPOSITORY_ROOT, args.gamever, config_path)

    pushed = 0
    failed = 0
    for module_name, platform, binary_path in iter_configured_binaries(REPOSITORY_ROOT, args.gamever, config_path):
        entries = manifests.get(f"{module_name}/{platform}")
        if entries is None or not (entries["functions"] or entries["globals"]):
            print(f"BinSync push skipped (no declared symbols): {binary_path.name}", file=sys.stderr)
            continue
        manifest_path = build_manifest(entries)
        try:
            code = push_binary(python_exe, args.headless_script, binary_path, manifest_path)
        finally:
            manifest_path.unlink(missing_ok=True)
        if code == 0:
            pushed += 1
        else:
            failed += 1
            print(f"BinSync push FAILED for {binary_path.name} (exit {code})", file=sys.stderr)

    print(f"BinSync push done: {pushed} pushed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

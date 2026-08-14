import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path("push_binsync_symbols.py")
SPEC = importlib.util.spec_from_file_location("push_binsync_symbols", SCRIPT)
push_binsync_symbols = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(push_binsync_symbols)


class TestCollectManifestSymbols(unittest.TestCase):
    def _make_config(self, root: Path, gamever: str = "14174") -> Path:
        module = root / "bin" / gamever / "engine"
        module.mkdir(parents=True)
        (module / "engine2.dll").write_bytes(b"windows")
        (module / "libengine2.so").write_bytes(b"linux")

        (module / "Ctor.windows.yaml").write_text(
            "func_name: Ctor\nfunc_va: '0x1800bab40'\nfunc_rva: '0xbab40'\nfunc_size: '0x1bd'\n",
            encoding="utf-8",
        )
        (module / "Ctor.linux.yaml").write_text(
            "func_name: Ctor\nfunc_va: '0x533b70'\nfunc_rva: '0x533b70'\nfunc_size: '0x21d'\n",
            encoding="utf-8",
        )
        (module / "g_pCvar.windows.yaml").write_text(
            "gv_name: g_pCvar\ngv_rva: '0x688b08'\ngv_va: '0x180688b08'\n",
            encoding="utf-8",
        )
        (module / "g_pCvar.linux.yaml").write_text(
            "gv_name: g_pCvar\ngv_rva: '0xc72230'\ngv_va: '0xc72230'\n",
            encoding="utf-8",
        )

        config = root / "config.yaml"
        config.write_text(
            "modules:\n"
            "  - name: engine\n"
            "    path_windows: game/bin/win64/engine2.dll\n"
            "    path_linux: game/bin/linuxsteamrt64/libengine2.so\n"
            "    symbols:\n"
            "      - name: Ctor\n"
            "        category: func\n"
            "      - name: g_pCvar\n"
            "        category: gv\n"
            "      - name: SomeStruct\n"
            "        category: struct\n"
            "      - name: Missing\n"
            "        category: vfunc\n"
            "      - name: NullRva\n"
            "        category: func\n",
            encoding="utf-8",
        )
        # NullRva.yaml carries no func_rva -> must be skipped, not crash.
        (module / "NullRva.windows.yaml").write_text("func_name: NullRva\n", encoding="utf-8")
        (module / "NullRva.linux.yaml").write_text("func_name: NullRva\n", encoding="utf-8")

        return config

    def test_collect_selects_declared_funcs_and_globals_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = self._make_config(root)
            manifest = push_binsync_symbols.collect_manifest_symbols(root, "14174", config)

            self.assertEqual(manifest["engine/windows"]["functions"], [0xbab40])
            self.assertEqual(manifest["engine/windows"]["globals"], [0x688b08])
            self.assertEqual(manifest["engine/linux"]["functions"], [0x533b70])
            self.assertEqual(manifest["engine/linux"]["globals"], [0xc72230])

    def test_collect_excludes_struct_and_missing_and_null_rva(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = self._make_config(root)
            manifest = push_binsync_symbols.collect_manifest_symbols(root, "14174", config)

            for platform in ("windows", "linux"):
                # struct, undeclared-file, and null-rva symbols must not leak in.
                self.assertEqual(manifest[f"engine/{platform}"]["functions"], [0x533b70] if platform == "linux" else [0xbab40])
                self.assertEqual(len(manifest[f"engine/{platform}"]["functions"]), 1)
                self.assertEqual(len(manifest[f"engine/{platform}"]["globals"]), 1)

    def test_build_manifest_writes_json(self) -> None:
        entries = {"functions": [1, 2, 3], "globals": [4]}
        path = push_binsync_symbols.build_manifest(entries)
        try:
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle), entries)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

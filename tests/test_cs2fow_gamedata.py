import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from gamedata_contract import GeneratorContext, discover_generator_modules


SYMBOL_FIXTURES = {
    "CCheckTransmitInfo_m_nPlayerSlot": ("server", "struct_member_offset", 10, 11),
    "CCheckTransmitInfo_m_bFullUpdate": ("server", "struct_member_offset", 12, 13),
    "CGameResourceService_m_pEntitySystem": ("engine", "struct_member_offset", 14, 15),
    "CGameEventManager_vtable": ("server", "vtable_rva", "0x10", "0x11"),
    "CBaseModelEntity_FindBone": ("server", "func_rva", "0x20", "0x21"),
    "CBaseModelEntity_GetBoneTransform": ("server", "func_rva", "0x30", "0x31"),
    "UTIL_CreateEntityByName": ("server", "func_rva", "0x40", "0x41"),
    "CBaseEntity_DispatchSpawn": ("server", "func_rva", "0x50", "0x51"),
    "UTIL_Remove": ("server", "func_rva", "0x60", "0x61"),
    "CBaseEntity_Teleport": ("server", "vfunc_index", 70, 71),
    "CSmokeGrenadeProjectile_m_SmokeVolume": ("server", "struct_member_offset", 72, 73),
    "SmokeVolume_m_pStorage": ("server", "struct_member_offset", 74, 75),
    "SmokeVolume_m_nFrame": ("server", "struct_member_offset", 76, 77),
    "SmokeVolume_m_vecCenterOrigin": ("server", "struct_member_offset", 78, 79),
    "SmokeVolume_m_flStartTime": ("server", "struct_member_offset", 80, 81),
}

EXPECTED_VALUES = {
    "server_binary_size_windows": "1001",
    "server_binary_crc32_windows": "4294967295",
    "recipient_slot_offset_windows": "10",
    "checktransmit_full_update_offset_windows": "12",
    "game_entity_system_offset_windows": "14",
    "game_event_manager_vtable_rva_windows": "16",
    "lookup_bone_rva_windows": "32",
    "get_bone_transform_rva_windows": "48",
    "create_entity_by_name_rva_windows": "64",
    "dispatch_spawn_rva_windows": "80",
    "remove_entity_rva_windows": "96",
    "teleport_vtable_index_windows": "70",
    "smoke_volume_offset_windows": "72",
    "smoke_storage_offset_windows": "74",
    "smoke_frame_offset_windows": "76",
    "smoke_center_offset_windows": "78",
    "smoke_start_time_offset_windows": "80",
    "server_binary_size_linux": "2001",
    "server_binary_crc32_linux": "10",
    "recipient_slot_offset_linux": "11",
    "checktransmit_full_update_offset_linux": "13",
    "game_entity_system_offset_linux": "15",
    "game_event_manager_vtable_rva_linux": "17",
    "lookup_bone_rva_linux": "33",
    "get_bone_transform_rva_linux": "49",
    "create_entity_by_name_rva_linux": "65",
    "dispatch_spawn_rva_linux": "81",
    "remove_entity_rva_linux": "97",
    "teleport_vtable_index_linux": "71",
    "smoke_volume_offset_linux": "73",
    "smoke_storage_offset_linux": "75",
    "smoke_frame_offset_linux": "77",
    "smoke_center_offset_linux": "79",
    "smoke_start_time_offset_linux": "81",
}


class TestCS2FOWGamedata(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        cls.contract = next(
            contract
            for contract in discover_generator_modules(repo_root / "gamedata-generators")
            if contract.directory == "CS2FOW"
        )
        cls.module = cls.contract.module

    @staticmethod
    def _yaml_data():
        data = {}
        for symbol_name, (module_name, value_name, windows, linux) in SYMBOL_FIXTURES.items():
            data[symbol_name] = {
                "library": module_name,
                "category": "fixture",
                "aliases": [],
                "windows": {value_name: windows},
                "linux": {value_name: linux},
            }
        return data

    @staticmethod
    def _context():
        return GeneratorContext(
            game_version="14174",
            binaries={
                "server": {
                    "windows": {"size": 1001, "crc32": "ffffffff"},
                    "linux": {"size": 2001, "crc32": "0000000a"},
                }
            },
        )

    def _write_fixture(self, root, *, omitted=None, duplicate=None):
        path = Path(root) / self.module.GAMEDATA_PATH
        path.parent.mkdir(parents=True)
        lines = ["// fixture\r\n"]
        for key in EXPECTED_VALUES:
            if key != omitted:
                lines.append(f"{key}=999  // {key}\r\n")
                if key == duplicate:
                    lines.append(f"{key}=998\r\n")
        path.write_bytes(b"\xef\xbb\xbf" + "".join(lines).encode("utf-8"))
        return path

    @staticmethod
    def _assignments(content):
        return {
            line.split("=", 1)[0]: line.split("=", 1)[1].split("//", 1)[0].strip()
            for line in content.splitlines()
            if "=" in line
        }

    def test_contract_declares_v2_static_source_and_output(self) -> None:
        self.assertEqual(2, self.contract.api_version)
        self.assertEqual(("gamedata/cs2fow.games.txt",), self.contract.output_paths)
        self.assertEqual((), self.contract.download_sources)
        self.assertEqual(
            (
                (
                    "templates/cs2fow.games.txt",
                    "gamedata/cs2fow.games.txt",
                ),
            ),
            self.contract.static_sources,
        )

    def test_updates_all_assignments_and_preserves_formatting(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = self._write_fixture(temp_dir)
            updated, skipped, updated_symbols, skipped_symbols = self.module.update(
                self._yaml_data(),
                {},
                ["windows", "linux"],
                temp_dir,
                {},
                True,
                context=self._context(),
            )
            raw = path.read_bytes()

        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        content = raw.decode("utf-8-sig")
        self.assertIn("\r\n", content)
        self.assertIn("recipient_slot_offset_windows=10  // recipient_slot_offset_windows", content)
        self.assertEqual(EXPECTED_VALUES, self._assignments(content))
        self.assertEqual(34, updated)
        self.assertEqual(0, skipped)
        self.assertEqual(34, len(updated_symbols))
        self.assertEqual([], skipped_symbols)

    def test_platform_subset_leaves_other_platform_unchanged(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = self._write_fixture(temp_dir)
            updated, skipped, _updated_symbols, _skipped_symbols = self.module.update(
                self._yaml_data(),
                {},
                ["windows"],
                temp_dir,
                {},
                context=self._context(),
            )
            assignments = self._assignments(path.read_text(encoding="utf-8-sig"))

        self.assertEqual(17, updated)
        self.assertEqual(0, skipped)
        self.assertEqual("1001", assignments["server_binary_size_windows"])
        self.assertEqual("999", assignments["server_binary_size_linux"])

    def test_rejects_missing_and_duplicate_assignments(self) -> None:
        for kwargs, message in (
            ({"omitted": "remove_entity_rva_linux"}, "missing assignments"),
            ({"duplicate": "remove_entity_rva_linux"}, "duplicate assignment"),
        ):
            with self.subTest(message=message), TemporaryDirectory() as temp_dir:
                self._write_fixture(temp_dir, **kwargs)
                with self.assertRaisesRegex(ValueError, message):
                    self.module.update(
                        self._yaml_data(),
                        {},
                        ["windows", "linux"],
                        temp_dir,
                        {},
                        context=self._context(),
                    )

    def test_rejects_missing_snapshot_values(self) -> None:
        with TemporaryDirectory() as temp_dir:
            self._write_fixture(temp_dir)
            yaml_data = self._yaml_data()
            del yaml_data["UTIL_Remove"]["linux"]["func_rva"]
            with self.assertRaisesRegex(ValueError, "snapshot value is missing"):
                self.module.update(
                    yaml_data,
                    {},
                    ["windows", "linux"],
                    temp_dir,
                    {},
                    context=self._context(),
                )

        with TemporaryDirectory() as temp_dir:
            self._write_fixture(temp_dir)
            with self.assertRaisesRegex(ValueError, "snapshot binary metadata is missing"):
                self.module.update(
                    self._yaml_data(),
                    {},
                    ["windows", "linux"],
                    temp_dir,
                    {},
                    context=GeneratorContext(game_version="14174", binaries={}),
                )


if __name__ == "__main__":
    unittest.main()

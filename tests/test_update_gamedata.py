import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import update_gamedata
from gamedata_config_validation import GamedataConfigValidationError, validate_gamedata_config
from gamedata_diagnostics import DiagnosticAggregator, GamedataDiagnostic, diagnostic_delta
from gamedata_symbol_data import build_alias_to_name_map, merge_configs
from gamesymbol_store import DirectorySymbolStore


class RecordingStore:
    candidate_sha256 = "fixture-sha256"
    game_version = "14141"
    binaries = {
        "server": {
            "windows": {
                "size": 123,
                "crc32": "000000ff",
            }
        }
    }

    def __init__(self, payloads=None):
        self.payloads = payloads or {}
        self.reads = []

    def get(self, module, filename):
        self.reads.append(f"{module}/{filename}")
        return self.payloads.get(f"{module}/{filename}")


class TestLoadAllYamlData(unittest.TestCase):
    def test_load_all_yaml_data_skips_symbol_on_non_matching_platform(self) -> None:
        config = {
            "modules": [
                {
                    "name": "engine",
                    "symbols": [
                        {"name": "CommonGlobal", "category": "gv"},
                        {
                            "name": "WindowsOnlyGlobal",
                            "category": "gv",
                            "platform": "windows",
                        },
                    ],
                }
            ]
        }

        with TemporaryDirectory() as temp_dir:
            engine_dir = Path(temp_dir) / "14141" / "engine"
            engine_dir.mkdir(parents=True)
            (engine_dir / "CommonGlobal.windows.yaml").write_text(
                "gv_name: CommonGlobal\ngv_va: '0x180100000'\n",
                encoding="utf-8",
            )
            (engine_dir / "CommonGlobal.linux.yaml").write_text(
                "gv_name: CommonGlobal\ngv_va: '0x100000'\n",
                encoding="utf-8",
            )
            (engine_dir / "WindowsOnlyGlobal.windows.yaml").write_text(
                "gv_name: WindowsOnlyGlobal\ngv_va: '0x180200000'\n",
                encoding="utf-8",
            )

            store = DirectorySymbolStore(temp_dir, "14141")
            yaml_data, diagnostics = update_gamedata.load_all_yaml_data(config, store, ["windows", "linux"], debug=True)
            linux_only_data, _missing = update_gamedata.load_all_yaml_data(config, store, ["linux"], debug=True)

        self.assertIn("windows", yaml_data["WindowsOnlyGlobal"])
        self.assertNotIn("linux", yaml_data["WindowsOnlyGlobal"])
        self.assertNotIn("WindowsOnlyGlobal", linux_only_data)
        self.assertFalse(any(item.symbol == "WindowsOnlyGlobal" and item.platform == "linux" for item in diagnostics))

    def test_structmember_prefers_new_format_then_uses_store_legacy_fallback(self) -> None:
        config = {
            "modules": [
                {
                    "name": "server",
                    "symbols": [
                        {
                            "name": "CEntity_NewMember",
                            "category": "structmember",
                            "struct": "CEntity",
                            "member": "m_new",
                        },
                        {
                            "name": "CLegacy_OldMember",
                            "category": "structmember",
                            "struct": "CLegacy",
                            "member": "m_old",
                        },
                    ],
                }
            ]
        }
        with TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "14141" / "server"
            module_dir.mkdir(parents=True)
            (module_dir / "CEntity_NewMember.windows.yaml").write_text(
                "struct_name: CEntity\nmember_name: m_new\noffset: 0x20\n",
                encoding="utf-8",
            )
            (module_dir / "CEntity.windows.yaml").write_text(
                "struct_name: CEntity\nstruct_offsets:\n  0x10: m_new 4\n",
                encoding="utf-8",
            )
            (module_dir / "CLegacy.windows.yaml").write_text(
                "struct_name: CLegacy\nstruct_offsets:\n  0x30: m_old 4\n",
                encoding="utf-8",
            )
            data, _missing = update_gamedata.load_all_yaml_data(
                config,
                DirectorySymbolStore(temp_dir, "14141"),
                ["windows"],
                debug=True,
            )

        self.assertEqual(0x20, data["CEntity_NewMember"]["windows"]["struct_member_offset"])
        self.assertEqual(0x30, data["CLegacy_OldMember"]["windows"]["struct_member_offset"])

    def test_metadata_only_struct_does_not_read_symbol_store(self) -> None:
        store = RecordingStore()
        data, diagnostics = update_gamedata.load_all_yaml_data(
            {
                "modules": [
                    {
                        "name": "server",
                        "symbols": [{"name": "CEntity", "category": "struct"}],
                    }
                ]
            },
            store,
            ["windows", "linux"],
        )

        self.assertEqual({}, data)
        self.assertEqual([], diagnostics)
        self.assertEqual([], store.reads)

    def test_patch_alias_and_missing_diagnostics_use_canonical_store_keys(self) -> None:
        config = {
            "modules": [
                {
                    "name": "server",
                    "symbols": [
                        {
                            "name": "CCSPlayer_MovementServices_FullWalkMove_SpeedClamp",
                            "category": "patch",
                        },
                        {"name": "MissingFunction", "category": "func"},
                    ],
                }
            ]
        }
        with TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "14141" / "server"
            module_dir.mkdir(parents=True)
            (module_dir / "ServerMovementUnlock.windows.yaml").write_text(
                "patch_bytes: 90 90\n",
                encoding="utf-8",
            )
            data, missing = update_gamedata.load_all_yaml_data(
                config,
                DirectorySymbolStore(temp_dir, "14141"),
                ["windows"],
                debug=True,
            )

        patch_name = "CCSPlayer_MovementServices_FullWalkMove_SpeedClamp"
        self.assertEqual("90 90", data[patch_name]["windows"]["patch_bytes"])
        self.assertEqual("server/MissingFunction.windows.yaml", missing[0].canonical_path)

    def test_source_alias_loads_canonical_symbol_without_changing_downstream_aliases(self) -> None:
        symbol = {
            "name": "CNetworkMessages_GetNetworkGroupCount",
            "category": "vfunc",
            "source_alias": "INetworkMessages_GetNetworkGroupCount",
            "alias": "CNetworkMessages::GetNetworkGroupCount",
        }
        config = {"modules": [{"name": "networksystem", "symbols": [symbol]}]}
        store = RecordingStore(
            {
                "networksystem/INetworkMessages_GetNetworkGroupCount.windows.yaml": {
                    "vfunc_index": 12,
                }
            }
        )

        data, diagnostics = update_gamedata.load_all_yaml_data(config, store, ["windows"])

        self.assertEqual(12, data[symbol["name"]]["windows"]["vfunc_index"])
        self.assertEqual(["CNetworkMessages::GetNetworkGroupCount"], data[symbol["name"]]["aliases"])
        self.assertEqual(
            {"CNetworkMessages::GetNetworkGroupCount": symbol["name"]},
            build_alias_to_name_map(config),
        )
        self.assertEqual([], diagnostics)
        self.assertEqual(
            [
                "networksystem/CNetworkMessages_GetNetworkGroupCount.windows.yaml",
                "networksystem/INetworkMessages_GetNetworkGroupCount.windows.yaml",
            ],
            store.reads,
        )

    def test_missing_source_aliases_produce_one_diagnostic_with_all_attempts(self) -> None:
        store = RecordingStore()
        _data, diagnostics = update_gamedata.load_all_yaml_data(
            {
                "modules": [
                    {
                        "name": "networksystem",
                        "symbols": [
                            {
                                "name": "Canonical",
                                "category": "vfunc",
                                "source_alias": ["FirstAlias", "SecondAlias"],
                            }
                        ],
                    }
                ]
            },
            store,
            ["linux"],
        )

        self.assertEqual(1, len(diagnostics))
        self.assertEqual(
            (
                "networksystem/Canonical.linux.yaml",
                "networksystem/FirstAlias.linux.yaml",
                "networksystem/SecondAlias.linux.yaml",
            ),
            diagnostics[0].attempted_paths,
        )

    def test_debug_flag_does_not_change_diagnostic_collection(self) -> None:
        config = {"modules": [{"name": "engine", "symbols": [{"name": "Missing", "category": "func"}]}]}
        store = RecordingStore()

        _data, normal = update_gamedata.load_all_yaml_data(config, store, ["windows"])
        _data, debug = update_gamedata.load_all_yaml_data(config, store, ["windows"], debug=True)

        self.assertEqual(normal, debug)


class TestGamedataDiagnostics(unittest.TestCase):
    @staticmethod
    def _missing(symbol: str) -> GamedataDiagnostic:
        path = f"server/{symbol}.windows.yaml"
        return GamedataDiagnostic(
            reason="missing_yaml",
            severity="warning",
            module="server",
            symbol=symbol,
            category="func",
            platform="windows",
            canonical_path=path,
            attempted_paths=(path,),
        )

    def test_aggregation_deduplicates_semantic_identity_across_contexts(self) -> None:
        diagnostic = self._missing("SharedMissing")
        aggregator = DiagnosticAggregator()
        for context in ("base", "one", "two", "three", "four", "five"):
            aggregator.add(context, [diagnostic])

        self.assertEqual(1, aggregator.unique_warning_count)
        self.assertEqual(6, aggregator.warning_observation_count)
        self.assertEqual(5, aggregator.duplicate_warning_count)
        aggregate = aggregator.warning_aggregates()[0]
        self.assertEqual({"base", "one", "two", "three", "four", "five"}, aggregate.contexts)

    def test_diagnostic_delta_is_unique_and_deterministically_sorted(self) -> None:
        base = [self._missing("Base")]
        added_a = self._missing("Zed")
        added_b = self._missing("Alpha")

        delta = diagnostic_delta([added_a, base[0], added_b, added_a], base)

        self.assertEqual(["Alpha", "Zed"], [item.symbol for item in delta])


class TestGamedataConfigValidation(unittest.TestCase):
    @staticmethod
    def _module(*, skills, symbols):
        return {
            "name": "engine",
            "path_windows": "engine2.dll",
            "path_linux": "libengine2.so",
            "skills": skills,
            "symbols": symbols,
        }

    def test_invalid_platform_and_explicit_producer_contradiction_fail(self) -> None:
        with self.assertRaisesRegex(GamedataConfigValidationError, "engine.BadPlatform.platform"):
            validate_gamedata_config(
                {
                    "modules": [
                        self._module(
                            skills=[],
                            symbols=[{"name": "BadPlatform", "category": "func", "platform": "mac"}],
                        )
                    ]
                }
            )

        with self.assertRaisesRegex(GamedataConfigValidationError, "engine.Contradiction.platform"):
            validate_gamedata_config(
                {
                    "modules": [
                        self._module(
                            skills=[
                                {
                                    "name": "windows-producer",
                                    "platform": "windows",
                                    "expected_output": ["Contradiction.{platform}.yaml"],
                                }
                            ],
                            symbols=[{"name": "Contradiction", "category": "func", "platform": "linux"}],
                        )
                    ]
                }
            )

    def test_single_platform_producer_is_a_finding_and_dual_platform_is_allowed(self) -> None:
        windows_only = self._module(
            skills=[
                {
                    "name": "windows-producer",
                    "platform": "windows",
                    "expected_output": ["WindowsOnly.{platform}.yaml"],
                }
            ],
            symbols=[{"name": "WindowsOnly", "category": "func"}],
        )
        findings = validate_gamedata_config({"modules": [windows_only]})
        self.assertEqual(["implicit_single_platform"], [item.code for item in findings])

        dual = self._module(
            skills=[{"name": "dual-producer", "expected_output": ["Dual.{platform}.yaml"]}],
            symbols=[{"name": "Dual", "category": "func"}],
        )
        self.assertEqual([], validate_gamedata_config({"modules": [dual]}))

    def test_invalid_structmember_alias_and_source_collision_fail_before_loading(self) -> None:
        invalid_config = {
            "modules": [
                self._module(
                    skills=[],
                    symbols=[
                        {"name": "Metadata", "category": "struct", "source_alias": "Forbidden"},
                        {"name": "Member", "category": "structmember", "struct": "Missing", "member": ""},
                        {"name": "BadAlias", "category": "func", "alias": ["ok", ""]},
                    ],
                )
            ]
        }
        with self.assertRaises(GamedataConfigValidationError) as caught:
            validate_gamedata_config(invalid_config)
        message = str(caught.exception)
        self.assertIn("engine.Metadata.source_alias", message)
        self.assertIn("engine.Member.member", message)
        self.assertIn("engine.BadAlias.alias", message)

        collision_config = {
            "modules": [
                self._module(
                    skills=[],
                    symbols=[
                        {"name": "CanonicalOne", "category": "vfunc", "source_alias": "Shared"},
                        {"name": "Shared", "category": "vfunc"},
                    ],
                )
            ]
        }
        with self.assertRaisesRegex(GamedataConfigValidationError, "source_alias"):
            validate_gamedata_config(collision_config)

    def test_active_config_has_no_implicit_platform_findings(self) -> None:
        findings = validate_gamedata_config(update_gamedata.load_config("configs/14172.yaml"))
        self.assertFalse(any(item.code == "implicit_single_platform" for item in findings))


class TestConfigMergeRegression(unittest.TestCase):
    def test_overlay_updates_selected_fields_without_mutating_base(self) -> None:
        base = {
            "modules": [
                {
                    "name": "engine",
                    "symbols": [{"name": "Target", "category": "func", "alias": "Old"}],
                }
            ]
        }
        merged = merge_configs(
            base,
            {
                "modules": [
                    {
                        "name": "engine",
                        "symbols": [{"name": "Target", "alias": "New", "platform": "windows"}],
                    }
                ]
            },
        )

        symbol = merged["modules"][0]["symbols"][0]
        self.assertEqual("func", symbol["category"])
        self.assertEqual("New", symbol["alias"])
        self.assertEqual("windows", symbol["platform"])
        self.assertNotIn("platform", base["modules"][0]["symbols"][0])


class TestGenerateGamedataDiagnostics(unittest.TestCase):
    def test_generator_header_prints_only_overlay_added_diagnostics(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config_path = root / "config.yaml"
            config_path.write_text(
                "modules:\n  - name: engine\n    symbols:\n      - name: BaseMissing\n        category: func\n",
                encoding="utf-8",
            )
            source_dir = root / "generator"
            source_dir.mkdir()
            (source_dir / "config.yaml").write_text(
                "modules:\n  - name: engine\n    symbols:\n      - name: OverlayMissing\n        category: func\n",
                encoding="utf-8",
            )
            module = SimpleNamespace(update=lambda *_args: (0, 0, [], []))
            contract = SimpleNamespace(
                name="Fixture",
                directory="fixture",
                source_dir=source_dir,
                static_sources=(),
                download_sources=(),
                module=module,
            )
            output = io.StringIO()
            with (
                patch.object(update_gamedata, "open_snapshot_store", return_value=RecordingStore()),
                patch.object(update_gamedata, "discover_generator_modules", return_value=[contract]),
                patch.object(update_gamedata, "generator_contract_sha256", return_value="contract-sha256"),
                redirect_stdout(output),
            ):
                update_gamedata.generate_gamedata(
                    gamever="14141",
                    snapshot_path=root / "snapshot.yaml",
                    config_path=config_path,
                    modules_dir=root,
                    output_root=root / "output",
                    platforms=["windows"],
                )

        rendered = output.getvalue()
        generator_section = rendered.split("Updating Fixture...", 1)[1].split("YAML diagnostic summary:", 1)[0]
        self.assertIn("engine/OverlayMissing.windows.yaml", generator_section)
        self.assertNotIn("engine/BaseMissing.windows.yaml", generator_section)
        self.assertIn("Unique warning diagnostics: 2", rendered)
        self.assertIn("Warning observations: 3", rendered)
        self.assertIn("Duplicate observations suppressed: 1", rendered)

    def test_generator_api_v2_receives_immutable_snapshot_context(self) -> None:
        received = {}

        def update(*_args, context):
            received["context"] = context
            return 0, 0, [], []

        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config_path = root / "config.yaml"
            config_path.write_text("modules: []\n", encoding="utf-8")
            source_dir = root / "generator"
            source_dir.mkdir()
            contract = SimpleNamespace(
                name="Fixture",
                directory="fixture",
                api_version=2,
                source_dir=source_dir,
                static_sources=(),
                download_sources=(),
                module=SimpleNamespace(update=update),
            )
            with (
                patch.object(update_gamedata, "open_snapshot_store", return_value=RecordingStore()),
                patch.object(update_gamedata, "discover_generator_modules", return_value=[contract]),
                patch.object(update_gamedata, "generator_contract_sha256", return_value="contract-sha256"),
            ):
                update_gamedata.generate_gamedata(
                    gamever="14141",
                    snapshot_path=root / "snapshot.yaml",
                    config_path=config_path,
                    modules_dir=root,
                    output_root=root / "output",
                    platforms=["windows"],
                )

        context = received["context"]
        self.assertEqual("14141", context.game_version)
        self.assertEqual(123, context.binaries["server"]["windows"]["size"])
        with self.assertRaises(TypeError):
            context.binaries["server"]["windows"]["size"] = 0


if __name__ == "__main__":
    unittest.main()

import argparse
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cpp_tests_util
import run_cpp_tests
from gamesymbol_snapshot_lib.operations import pack_snapshot
from tests.gamesymbol_snapshot_test_support import module, skill, write_binary, write_config
from gamesymbol_store import DirectorySymbolStore, SnapshotSymbolStore


class TestParseArgsLegacyFixHeader(unittest.TestCase):
    def test_rejects_removed_fixheader_option(self) -> None:
        with patch(
            "sys.argv",
            ["run_cpp_tests.py", "-gamever", "14141", "-snapshot", "candidate.yaml", "-fixheader"],
        ):
            with self.assertRaises(SystemExit):
                run_cpp_tests.parse_args()


class TestDefaultClang(unittest.TestCase):
    @patch.object(run_cpp_tests.shutil, "which", side_effect=lambda compiler: compiler == "clang-cl")
    def test_falls_back_to_clang_cl_when_clang_plus_plus_is_missing(self, _mock_which) -> None:
        self.assertEqual("clang-cl", run_cpp_tests.resolve_default_clang())

class TestParseVftableLayouts(unittest.TestCase):
    def test_parses_single_entry_vftable_indices_header(self) -> None:
        compiler_output = (
            "VFTable indices for 'ILoopType' (1 entry).\n   0 | void ILoopType::AddEngineService(const char *) [pure]\n"
        )

        parsed = cpp_tests_util.parse_vftable_layouts(compiler_output)

        self.assertIn("ILoopType", parsed)
        self.assertEqual(1, parsed["ILoopType"]["declared_entries"])
        self.assertEqual(1, parsed["ILoopType"]["entry_count"])
        self.assertEqual(
            "AddEngineService",
            parsed["ILoopType"]["methods_by_index"][0]["member_name"],
        )

    def test_prefers_complete_vftable_for_derived_class(self) -> None:
        compiler_output = (
            "VFTable indices for 'IParent' (2 entries).\n"
            "   0 | void IParent::ParentVirtual() [pure]\n"
            "   1 | void IParent::ParentOverload(int) [pure]\n"
            "\n"
            "VFTable for 'IParent' in 'CDerived' (5 entries).\n"
            "   0 | CDerived RTTI\n"
            "   1 | void IParent::ParentVirtual() [pure]\n"
            "   2 | void IParent::ParentOverload(int) [pure]\n"
            "   3 | CDerived::~CDerived() [scalar deleting] [pure]\n"
            "   4 | void CDerived::ChildVirtual() [pure]\n"
            "\n"
            "VFTable indices for 'CDerived' (2 entries).\n"
            "   2 | CDerived::~CDerived() [scalar deleting]\n"
            "   3 | void CDerived::ChildVirtual()\n"
        )

        parsed = cpp_tests_util.parse_vftable_layouts(compiler_output)

        self.assertIn("CDerived", parsed)
        self.assertEqual(4, parsed["CDerived"]["declared_entries"])
        self.assertEqual(4, parsed["CDerived"]["entry_count"])
        self.assertEqual(
            "ParentVirtual",
            parsed["CDerived"]["methods_by_index"][0]["member_name"],
        )
        self.assertEqual(
            "ParentOverload",
            parsed["CDerived"]["methods_by_index"][1]["member_name"],
        )
        self.assertEqual(
            "~CDerived",
            parsed["CDerived"]["methods_by_index"][2]["member_name"],
        )
        self.assertEqual(
            "ChildVirtual",
            parsed["CDerived"]["methods_by_index"][3]["member_name"],
        )

    def test_prefers_complete_vftable_for_multi_level_derived_class(self) -> None:
        compiler_output = (
            "VFTable for 'IGrandParent' in 'IParent' in 'CDerived' (5 entries).\n"
            "   0 | CDerived RTTI\n"
            "   1 | void IGrandParent::GrandParentVirtual() [pure]\n"
            "   2 | void IParent::ParentVirtual() [pure]\n"
            "   3 | void CDerived::ChildVirtual() [pure]\n"
            "   4 | void CDerived::ChildTailVirtual() [pure]\n"
            "\n"
            "VFTable indices for 'CDerived' (2 entries).\n"
            "   2 | void CDerived::ChildVirtual()\n"
            "   3 | void CDerived::ChildTailVirtual()\n"
        )

        parsed = cpp_tests_util.parse_vftable_layouts(compiler_output)

        self.assertIn("CDerived", parsed)
        self.assertEqual(4, parsed["CDerived"]["declared_entries"])
        self.assertEqual(4, parsed["CDerived"]["entry_count"])
        self.assertEqual(
            "GrandParentVirtual",
            parsed["CDerived"]["methods_by_index"][0]["member_name"],
        )
        self.assertEqual(
            "ParentVirtual",
            parsed["CDerived"]["methods_by_index"][1]["member_name"],
        )
        self.assertEqual(
            "ChildTailVirtual",
            parsed["CDerived"]["methods_by_index"][3]["member_name"],
        )


class TestCompareVtableWithYaml(unittest.TestCase):
    def test_complete_derived_vftable_matches_inherited_overload_reference(self) -> None:
        compiler_output = (
            "VFTable for 'IParent' in 'CDerived' (4 entries).\n"
            "   0 | CDerived RTTI\n"
            "   1 | void IParent::ParentVirtual() [pure]\n"
            "   2 | void IParent::ParentOverload(int) [pure]\n"
            "   3 | void CDerived::ChildVirtual() [pure]\n"
            "\n"
            "VFTable indices for 'CDerived' (1 entry).\n"
            "   2 | void CDerived::ChildVirtual()\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "14167" / "server"
            module_dir.mkdir(parents=True)
            (module_dir / "CDerived_vtable.windows.yaml").write_text(
                "vtable_class: CDerived\nvtable_size: '0x18'\nvtable_numvfunc: 3\n",
                encoding="utf-8",
            )
            (module_dir / "CDerived_ParentOverload_Int.windows.yaml").write_text(
                "func_name: CDerived_ParentOverload_Int\nvtable_name: CDerived\nvfunc_index: 1\n",
                encoding="utf-8",
            )

            report = cpp_tests_util.compare_compiler_vtable_with_yaml(
                class_name="CDerived",
                compiler_output=compiler_output,
                symbol_store=DirectorySymbolStore(temp_dir, "14167"),
                platform="windows",
                reference_modules=["server"],
                pointer_size=8,
            )

        self.assertEqual([], report["differences"])

    def test_snapshot_compare_is_independent_from_directory_yaml(self) -> None:
        compiler_output = "VFTable indices for 'ITest' (1 entry).\n   0 | void ITest::First() [pure]\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            bindir = root / "bin"
            gamever = "14167"
            write_config(
                config,
                [
                    module(
                        "server",
                        [skill("find", ["ITest_vtable.{platform}.yaml", "ITest_First.{platform}.yaml"])],
                        linux=False,
                    )
                ],
            )
            module_dir = bindir / gamever / "server"
            module_dir.mkdir(parents=True)
            (module_dir / "ITest_vtable.windows.yaml").write_text(
                "vtable_size: '0x8'\nvtable_numvfunc: 1\n",
                encoding="utf-8",
            )
            (module_dir / "ITest_First.windows.yaml").write_text(
                "func_name: ITest_First\nvfunc_index: 0\n",
                encoding="utf-8",
            )
            write_binary(module_dir / "server.dll")
            snapshot = root / "candidate.yaml"
            pack_snapshot(gamever, bindir, config, snapshot)
            store = SnapshotSymbolStore.open(snapshot, expected_game_version=gamever, config_path=config)
            shutil.rmtree(bindir / gamever)

            report = cpp_tests_util.compare_compiler_vtable_with_yaml(
                class_name="ITest",
                compiler_output=compiler_output,
                symbol_store=store,
                platform="windows",
                reference_modules=["server"],
                pointer_size=8,
            )

        self.assertEqual([], report["differences"])


class TestParseRecordLayouts(unittest.TestCase):
    def test_parses_struct_member_offsets_from_record_layout(self) -> None:
        compiler_output = (
            "*** Dumping AST Record Layout\n"
            "         0 | struct SDL_Mouse\n"
            "         0 |   void *(* CreateCursor)(void *, int, int)\n"
            "        48 |   bool (* WarpMouse)(void *, float, float)\n"
            "       136 |   void * focus\n"
            "       160 |   float last_x\n"
            "           | [sizeof=304, dsize=304, align=8,\n"
            "           |  nvsize=304, nvalign=8]\n"
        )

        parsed = cpp_tests_util.parse_record_layouts(compiler_output)

        self.assertIn("SDL_Mouse", parsed)
        self.assertEqual(304, parsed["SDL_Mouse"]["sizeof"])
        self.assertEqual(4, parsed["SDL_Mouse"]["member_count"])
        self.assertEqual(
            48,
            parsed["SDL_Mouse"]["members_by_name"]["WarpMouse"]["offset"],
        )
        self.assertEqual(
            136,
            parsed["SDL_Mouse"]["members_by_name"]["focus"]["offset"],
        )


class TestCompareRecordLayoutWithYaml(unittest.TestCase):
    def test_reports_structmember_offset_mismatch(self) -> None:
        compiler_output = (
            "*** Dumping AST Record Layout\n"
            "         0 | struct SDL_Mouse\n"
            "        48 |   bool (* WarpMouse)(void *, float, float)\n"
            "       136 |   void * focus\n"
            "           | [sizeof=304, dsize=304, align=8,\n"
            "           |  nvsize=304, nvalign=8]\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "14158" / "SDL3"
            module_dir.mkdir(parents=True)
            (module_dir / "SDL_Mouse_WarpMouse.windows.yaml").write_text(
                "struct_name: SDL_Mouse\nmember_name: WarpMouse\noffset: '0x30'\n",
                encoding="utf-8",
            )
            (module_dir / "SDL_Mouse_focus.windows.yaml").write_text(
                "struct_name: SDL_Mouse\nmember_name: focus\noffset: '0x90'\n",
                encoding="utf-8",
            )

            report = cpp_tests_util.compare_compiler_record_layout_with_yaml(
                struct_name="SDL_Mouse",
                compiler_output=compiler_output,
                symbol_store=DirectorySymbolStore(temp_dir, "14158"),
                platform="windows",
                reference_modules=["SDL3"],
            )

        self.assertEqual("record_layout", report["comparison_kind"])
        self.assertTrue(report["compiler_found"])
        self.assertTrue(report["reference_found"])
        self.assertEqual(2, report["reference_members_count"])
        self.assertEqual(
            ["structmember_offset_mismatch"],
            [item["type"] for item in report["differences"]],
        )


class TestMainExitStatus(unittest.TestCase):
    @patch.object(run_cpp_tests, "open_snapshot_store")
    @patch.object(run_cpp_tests, "run_one_test")
    @patch.object(run_cpp_tests, "probe_target_support")
    @patch.object(run_cpp_tests, "get_default_target_triple")
    @patch.object(run_cpp_tests, "parse_config")
    @patch.object(run_cpp_tests, "parse_args")
    def test_returns_failure_when_record_or_vtable_compare_has_differences(
        self,
        mock_parse_args,
        mock_parse_config,
        mock_get_default_target_triple,
        mock_probe_target_support,
        mock_run_one_test,
        mock_open_snapshot_store,
    ) -> None:
        mock_parse_args.return_value = argparse.Namespace(
            configyaml="configs/14168.yaml",
            snapshot="candidate.yaml",
            gamever="14132",
            clang="clang++",
            std="c++20",
            debug=False,
        )
        mock_parse_config.return_value = [
            {
                "name": "TestLayout",
                "symbol": "ITestLayout",
                "cpp": "test.cpp",
                "target": "x86_64-pc-windows-msvc",
            }
        ]
        mock_get_default_target_triple.return_value = "x86_64-pc-windows-msvc"
        mock_probe_target_support.return_value = {"supported": True, "output": ""}
        mock_open_snapshot_store.return_value.candidate_sha256 = "sha256:test"
        mock_open_snapshot_store.return_value.game_version = "14132"
        mock_open_snapshot_store.return_value.file_count = 1
        mock_open_snapshot_store.return_value.config_sha256 = "sha256:config"
        compare_reports = [
            (
                "record layout",
                {
                    "comparison_kind": "record_layout",
                    "struct_name": "SDL_Mouse",
                    "differences": [
                        {
                            "type": "structmember_offset_mismatch",
                            "message": "SDL_Mouse::focus mismatch",
                        }
                    ],
                },
            ),
            (
                "vtable layout",
                {
                    "class_name": "ITestLayout",
                    "differences": [
                        {
                            "type": "vtable_size_mismatch",
                            "message": "ITestLayout vtable size mismatch",
                        }
                    ],
                },
            ),
        ]

        for _case_name, compare_report in compare_reports:
            with self.subTest(compare_kind=_case_name):
                mock_run_one_test.return_value = {
                    "status": "ok",
                    "command": [],
                    "output": "",
                    "compare_reports": [compare_report],
                }

                self.assertEqual(1, run_cpp_tests.main())


class TestSourcePathResolution(unittest.TestCase):
    def test_relative_cpp_paths_use_repository_root_and_reject_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cpp = root / "cpp_tests" / "example.cpp"
            cpp.parent.mkdir()
            cpp.write_text("int main() {}\n", encoding="utf-8")
            self.assertEqual(cpp.resolve(), run_cpp_tests._resolve_source_path("cpp_tests/example.cpp", root))
            with self.assertRaisesRegex(ValueError, "escapes repository root"):
                run_cpp_tests._resolve_source_path("../outside.cpp", root)


if __name__ == "__main__":
    unittest.main()

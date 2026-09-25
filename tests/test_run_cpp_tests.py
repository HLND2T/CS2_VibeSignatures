import argparse
import shutil
import subprocess
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


class TestParseVftableLayouts(unittest.TestCase):
    def test_linux_primary_table_includes_inherited_slots_only(self) -> None:
        output = (
            "Vtable for 'D' (9 entries).\n"
            " 0 | offset_to_top (0)\n 1 | D RTTI\n"
            "     -- (D, 0) vtable address --\n"
            " 2 | void A::a()\n 3 | void D::d()\n"
            " 4 | offset_to_top (-8)\n 5 | D RTTI\n"
            "     -- (B, 8) vtable address --\n"
            " 6 | void B::b()\n 7 | void B::b2()\n 8 | void B::b3()\n\n"
            "VTable indices for 'D' (1 entries).\n 1 | void D::d()\n"
        )
        parsed = cpp_tests_util.parse_vftable_layouts(output)["D"]
        self.assertEqual("complete", parsed["source_kind"])
        self.assertEqual([0, 1], list(parsed["methods_by_index"]))
        self.assertEqual(["a", "d"], [entry["member_name"] for entry in parsed["methods_by_index"].values()])
        self.assertEqual(2, parsed["entry_count"])

    def test_linux_virtual_base_metadata_does_not_become_function_slots(self) -> None:
        output = (
            "Vtable for 'ns::D' (12 entries).\n"
            " 0 | vbase_offset (8)\n 1 | offset_to_top (0)\n 2 | ns::D RTTI\n"
            "     -- (ns::D, 0) vtable address --\n"
            " 3 | ns::D::~D() [complete]\n 4 | ns::D::~D() [deleting]\n"
            " 5 | void ns::D::d()\n"
            " 6 | vcall_offset (-8)\n 7 | offset_to_top (-8)\n 8 | ns::D RTTI\n"
            " 9 | ns::D::~D() [complete]\n 10 | ns::D::~D() [deleting]\n 11 | void B::b()\n"
        )
        parsed = cpp_tests_util.parse_vftable_layouts(output)["ns::D"]
        self.assertEqual([0, 1, 2], list(parsed["methods_by_index"]))
        self.assertEqual(["~D", "~D", "d"], [entry["member_name"] for entry in parsed["methods_by_index"].values()])

    def test_msvc_larger_secondary_table_does_not_replace_primary(self) -> None:
        output = (
            "VFTable for 'A' in 'D' (3 entries).\n"
            " 0 | D RTTI\n 1 | void A::a()\n 2 | void D::d()\n\n"
            "VFTable for 'B' in 'D' (4 entries).\n"
            " 0 | D RTTI\n 1 | void B::b()\n 2 | void B::b2()\n 3 | void B::b3()\n\n"
            "VFTable indices for 'D' (1 entry).\n 1 | void D::d()\n"
        )
        parsed = cpp_tests_util.parse_vftable_layouts(output)["D"]
        self.assertEqual(["a", "d"], [entry["member_name"] for entry in parsed["methods_by_index"].values()])

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

    def test_msvc_secondary_vfptr_indices_cannot_overwrite_primary_slots(self) -> None:
        output = (
            "VFTable for 'B' in 'D' (2 entries).\n 0 | D RTTI\n 1 | void D::b()\n\n"
            "VFTable for 'A' in 'D' (2 entries).\n 0 | D RTTI\n 1 | void D::a()\n\n"
            "VFTable indices for 'D' (2 entries).\n"
            " -- accessible via vfptr at offset 0 --\n 0 | void D::a()\n"
            " -- accessible via vfptr at offset 8 --\n 0 | void D::b()\n"
        )
        parsed = cpp_tests_util.parse_vftable_layouts(output)["D"]
        self.assertTrue(parsed["layout_complete"])
        self.assertEqual("a", parsed["methods_by_index"][0]["member_name"])

    def test_msvc_ambiguous_tables_are_not_guessed_from_size(self) -> None:
        output = (
            "VFTable for 'A' in 'D' (2 entries).\n 0 | D RTTI\n 1 | void A::a()\n\n"
            "VFTable for 'B' in 'D' (3 entries).\n 0 | D RTTI\n 1 | void B::b()\n 2 | void B::b2()\n"
        )
        parsed = cpp_tests_util.parse_vftable_layouts(output)["D"]
        self.assertFalse(parsed["layout_complete"])
        self.assertEqual({}, parsed["methods_by_index"])

    def test_indices_before_complete_layout_and_no_new_methods(self) -> None:
        output = (
            "VTable indices for 'D' (1 entries).\n 0 | void D::a()\n\n"
            "Vtable for 'D' (4 entries).\n 0 | offset_to_top (0)\n 1 | D RTTI\n"
            " 2 | void D::a()\n 3 | void A::tail()\n\n"
            "Vtable for 'E' (4 entries).\n 0 | offset_to_top (0)\n 1 | E RTTI\n"
            " 2 | void A::a()\n 3 | void A::tail()\n"
        )
        parsed = cpp_tests_util.parse_vftable_layouts(output)
        for name in ("D", "E"):
            self.assertTrue(parsed[name]["layout_complete"])
            self.assertEqual(
                ["a", "tail"], [entry["member_name"] for entry in parsed[name]["methods_by_index"].values()]
            )

    def test_empty_table_and_unrelated_numbered_blocks_do_not_add_slots(self) -> None:
        output = (
            "Vtable for 'D' (2 entries).\n 0 | offset_to_top (0)\n 1 | D RTTI\n\n"
            "VTable indices for 'E' (0 entries).\n"
            " 0 | unrelated dump content\n"
        )
        parsed = cpp_tests_util.parse_vftable_layouts(output)
        self.assertTrue(parsed["D"]["layout_complete"])
        self.assertEqual(0, parsed["D"]["entry_count"])
        self.assertEqual({}, parsed["E"]["methods_by_index"])

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


@unittest.skipUnless(shutil.which("clang++"), "clang++ is required for real ABI dump regression tests")
class TestClangPrimaryVtable(unittest.TestCase):
    def test_actual_linux_and_msvc_dumps(self) -> None:
        source = """
            struct A { virtual void a() {} virtual void tail() {} };
            struct B { virtual void b() {} virtual void b2() {} virtual void b3() {} virtual void b4() {} };
            struct D : A, B { virtual void d() {} void b() override {} }; D d;
            struct E : A {}; E e;
            struct R : A { void a() override {} }; R r;
            struct V : virtual B, A { virtual void v() {} }; V v;
            namespace ns { struct X { virtual ~X() {} virtual void x() {} }; X x; }
        """
        for target, destructor_slots in (("x86_64-pc-linux-gnu", 2), ("x86_64-pc-windows-msvc", 1)):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp_dir:
                result = subprocess.run(
                    [
                        "clang++",
                        f"--target={target}",
                        "-std=c++20",
                        "-Xclang",
                        "-fdump-vtable-layouts",
                        "-x",
                        "c++",
                        "-c",
                        "-",
                        "-o",
                        str(Path(temp_dir) / "sample.o"),
                    ],
                    input=source,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                parsed = cpp_tests_util.parse_vftable_layouts(result.stdout + result.stderr)
                expected = {
                    "D": ["a", "tail", "d", "b"] if destructor_slots == 2 else ["a", "tail", "d"],
                    "E": ["a", "tail"],
                    "R": ["a", "tail"],
                    "V": ["a", "tail", "v"],
                    "ns::X": ["~X"] * destructor_slots + ["x"],
                }
                for name, methods in expected.items():
                    with self.subTest(name=name):
                        self.assertTrue(parsed[name]["layout_complete"], parsed[name])
                        self.assertEqual(list(range(len(methods))), list(parsed[name]["methods_by_index"]))
                        self.assertEqual(
                            methods, [item["member_name"] for item in parsed[name]["methods_by_index"].values()]
                        )


class TestCompareVtableWithYaml(unittest.TestCase):
    def _compare_linux_derived(self, output: str, *, expected_member: str = "a") -> dict:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "14184" / "engine"
            module_dir.mkdir(parents=True)
            (module_dir / "D_vtable.linux.yaml").write_text(
                "vtable_class: D\nvtable_size: '0x10'\nvtable_numvfunc: 2\n", encoding="utf-8"
            )
            (module_dir / "D_a.linux.yaml").write_text(
                f"func_name: D_{expected_member}\nvtable_name: D\nvfunc_index: 0\n", encoding="utf-8"
            )
            return cpp_tests_util.compare_compiler_vtable_with_yaml(
                class_name="D",
                compiler_output=output,
                symbol_store=DirectorySymbolStore(temp_dir, "14184"),
                platform="linux",
                reference_modules=["engine"],
                pointer_size=8,
            )

    def test_linux_inherited_slot_matches_and_real_mismatch_remains_visible(self) -> None:
        output = (
            "Vtable for 'D' (4 entries).\n 0 | offset_to_top (0)\n 1 | D RTTI\n"
            " 2 | void A::a()\n 3 | void D::d()\n\n"
            "VTable indices for 'D' (1 entries).\n 1 | void D::d()\n"
        )
        self.assertEqual([], self._compare_linux_derived(output)["differences"])
        report = self._compare_linux_derived(output, expected_member="wrong")
        self.assertIn("vfunc_name_mismatch", [item["type"] for item in report["differences"]])

    def test_indices_only_do_not_claim_missing_inherited_slots_or_complete_size(self) -> None:
        for index in (0, 1):
            with self.subTest(index=index):
                output = f"VTable indices for 'D' (1 entries).\n {index} | void D::d()\n"
                report = self._compare_linux_derived(output)
                types = [item["type"] for item in report["differences"]]
                self.assertIn("compiler_layout_incomplete", types)
                self.assertNotIn("vtable_size_mismatch", types)
                self.assertNotIn("vtable_numvfunc_mismatch", types)
                self.assertNotIn("vfunc_index_missing", types)
                self.assertNotIn("reference_vfunc_index_missing", types)

    def test_truncated_or_noncontiguous_complete_layout_cannot_pass(self) -> None:
        for entries in (
            " 2 | void A::a()\n",
            " 2 | void A::a()\n 4 | void D::d()\n",
            " 2 | void A::a()\n 2 | void D::d()\n",
        ):
            with self.subTest(entries=entries):
                output = "Vtable for 'D' (4 entries).\n 0 | offset_to_top (0)\n 1 | D RTTI\n" + entries
                report = self._compare_linux_derived(output)
                self.assertIn("compiler_layout_incomplete", [item["type"] for item in report["differences"]])

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
        compiler_output = "VFTable for 'ITest' (2 entries).\n   0 | ITest RTTI\n   1 | void ITest::First() [pure]\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            bindir = root / "bin"
            artifactdir = root / "bin_artifacts"
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
            module_dir = artifactdir / gamever / "server"
            module_dir.mkdir(parents=True)
            (module_dir / "ITest_vtable.windows.yaml").write_text(
                "vtable_size: '0x8'\nvtable_numvfunc: 1\n",
                encoding="utf-8",
            )
            (module_dir / "ITest_First.windows.yaml").write_text(
                "func_name: ITest_First\nvfunc_index: 0\n",
                encoding="utf-8",
            )
            write_binary(bindir / gamever / "server/server.dll")
            snapshot = root / "candidate.yaml"
            pack_snapshot(gamever, bindir, config, snapshot, artifactdir=artifactdir)
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

    def test_audits_vfunc_references_from_unconfigured_snapshot_modules(self) -> None:
        compiler_output = "VFTable for 'ITest' (2 entries).\n   0 | ITest RTTI\n   1 | void ITest::First() [pure]\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            bindir = root / "bin"
            artifactdir = root / "bin_artifacts"
            gamever = "14167"
            write_config(
                config,
                [
                    module(
                        "engine",
                        [skill("find-engine", ["ITest_First.{platform}.yaml"])],
                        linux=False,
                    ),
                    module(
                        "server",
                        [skill("find-server", ["ITest_WrongOwner.{platform}.yaml"])],
                        linux=False,
                    ),
                ],
            )
            engine_dir = artifactdir / gamever / "engine"
            engine_dir.mkdir(parents=True)
            (engine_dir / "ITest_First.windows.yaml").write_text(
                "func_name: ITest_First\nvtable_name: ITest\nvfunc_index: 0\n",
                encoding="utf-8",
            )
            write_binary(bindir / gamever / "engine/engine.dll")
            server_dir = artifactdir / gamever / "server"
            server_dir.mkdir(parents=True)
            (server_dir / "ITest_WrongOwner.windows.yaml").write_text(
                "func_name: ITest_WrongOwner\nvtable_name: ITest\nvfunc_index: 64\n",
                encoding="utf-8",
            )
            write_binary(bindir / gamever / "server/server.dll")
            snapshot = root / "candidate.yaml"
            pack_snapshot(gamever, bindir, config, snapshot, artifactdir=artifactdir)
            store = SnapshotSymbolStore.open(snapshot, expected_game_version=gamever, config_path=config)

            report = cpp_tests_util.compare_compiler_vtable_with_yaml(
                class_name="ITest",
                compiler_output=compiler_output,
                symbol_store=store,
                platform="windows",
                reference_modules=["engine"],
                merge_reference_modules=False,
                pointer_size=8,
            )

        self.assertEqual("engine", report["reference_module"])
        self.assertEqual(["engine", "server"], report["ownership_modules_checked"])
        self.assertIn(
            "reference_vfunc_index_missing",
            [item["type"] for item in report["differences"]],
        )

    def test_reports_reference_vtable_owner_mismatch(self) -> None:
        compiler_output = "VFTable for 'ITest' (2 entries).\n   0 | ITest RTTI\n   1 | void ITest::First() [pure]\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "14167" / "server"
            module_dir.mkdir(parents=True)
            (module_dir / "ITest_First.windows.yaml").write_text(
                "func_name: ITest_First\nvtable_name: WrongOwner\nvfunc_index: 0\n",
                encoding="utf-8",
            )

            report = cpp_tests_util.compare_compiler_vtable_with_yaml(
                class_name="ITest",
                compiler_output=compiler_output,
                symbol_store=DirectorySymbolStore(temp_dir, "14167"),
                platform="windows",
                reference_modules=["server"],
                pointer_size=8,
            )

        self.assertIn(
            "reference_vtable_owner_mismatch",
            [item["type"] for item in report["differences"]],
        )

    def test_reports_filename_and_func_name_owner_mismatch(self) -> None:
        compiler_output = "VFTable for 'ITest' (2 entries).\n   0 | ITest RTTI\n   1 | void ITest::First() [pure]\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "14167" / "server"
            module_dir.mkdir(parents=True)
            (module_dir / "ITest_First.windows.yaml").write_text(
                "func_name: WrongOwner_First\nvtable_name: ITest\nvfunc_index: 0\n",
                encoding="utf-8",
            )

            report = cpp_tests_util.compare_compiler_vtable_with_yaml(
                class_name="ITest",
                compiler_output=compiler_output,
                symbol_store=DirectorySymbolStore(temp_dir, "14167"),
                platform="windows",
                reference_modules=["server"],
                pointer_size=8,
            )

        self.assertIn(
            "reference_owner_mismatch",
            [item["type"] for item in report["differences"]],
        )

    def test_accepts_explicit_reference_vtable_owner(self) -> None:
        compiler_output = "VFTable for 'ITest' (2 entries).\n   0 | ITest RTTI\n   1 | void ITest::First() [pure]\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "14167" / "server"
            module_dir.mkdir(parents=True)
            (module_dir / "ITest_First.windows.yaml").write_text(
                "func_name: ITest_First\nvtable_name: CConcrete_vtable\nvfunc_index: 0\n",
                encoding="utf-8",
            )

            report = cpp_tests_util.compare_compiler_vtable_with_yaml(
                class_name="ITest",
                compiler_output=compiler_output,
                symbol_store=DirectorySymbolStore(temp_dir, "14167"),
                platform="windows",
                reference_modules=["server"],
                reference_vtable_owners=["CConcrete"],
                pointer_size=8,
            )

        self.assertEqual([], report["differences"])

    def test_excludes_configured_reference_vtable_from_merge_and_ownership_audit(self) -> None:
        compiler_output = "VFTable for 'ITest' (2 entries).\n   0 | ITest RTTI\n   1 | void ITest::First() [pure]\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "14167"
            engine_dir = root / "engine"
            engine_dir.mkdir(parents=True)
            (engine_dir / "ITest_First.windows.yaml").write_text(
                "func_name: ITest_First\nvtable_name: ITest\nvfunc_index: 0\n",
                encoding="utf-8",
            )

            server_dir = root / "server"
            server_dir.mkdir(parents=True)
            (server_dir / "CConcrete_First.windows.yaml").write_text(
                "func_name: CConcrete_First\nvtable_name: CConcrete\nvfunc_index: 0\n",
                encoding="utf-8",
            )
            (server_dir / "CConcrete_Secondary.windows.yaml").write_text(
                "func_name: CConcrete_Secondary\nvtable_name: CConcrete_vtable2\nvfunc_index: 0\n",
                encoding="utf-8",
            )
            (server_dir / "CConcrete_vtable.windows.yaml").write_text(
                "vtable_size: '0x8'\nvtable_numvfunc: 1\n",
                encoding="utf-8",
            )
            (server_dir / "CConcrete_vtable2.windows.yaml").write_text(
                "vtable_size: '0x10'\nvtable_numvfunc: 2\n",
                encoding="utf-8",
            )

            symbol_store = DirectorySymbolStore(temp_dir, "14167")
            unfiltered_report = cpp_tests_util.compare_compiler_vtable_with_yaml(
                class_name="ITest",
                compiler_output=compiler_output,
                symbol_store=symbol_store,
                platform="windows",
                reference_modules=["engine", "server"],
                alias_class_names=["CConcrete"],
                pointer_size=8,
            )
            filtered_report = cpp_tests_util.compare_compiler_vtable_with_yaml(
                class_name="ITest",
                compiler_output=compiler_output,
                symbol_store=symbol_store,
                platform="windows",
                reference_modules=["engine", "server"],
                alias_class_names=["CConcrete"],
                exclude_reference_vtables=["CConcrete_vtable2"],
                pointer_size=8,
            )

        self.assertIn(
            "reference_conflict_vfunc_name",
            [item["type"] for item in unfiltered_report["differences"]],
        )
        self.assertIn(
            "reference_conflict_vtable_size",
            [item["type"] for item in unfiltered_report["differences"]],
        )
        self.assertEqual([], filtered_report["differences"])
        self.assertCountEqual(
            [
                "server/CConcrete_Secondary.windows.yaml",
                "server/CConcrete_vtable2.windows.yaml",
            ],
            filtered_report["reference_files_excluded"],
        )
        self.assertEqual(
            ["server/CConcrete_Secondary.windows.yaml"],
            filtered_report["ownership_files_excluded"],
        )


class TestCompileAndCompareConfig(unittest.TestCase):
    @patch.object(run_cpp_tests, "compare_compiler_vtable_with_yaml")
    @patch.object(run_cpp_tests.subprocess, "run")
    def test_passes_excluded_reference_vtables_to_vtable_compare(
        self,
        mock_run,
        mock_compare,
    ) -> None:
        mock_run.return_value = argparse.Namespace(returncode=0, stdout="", stderr="")
        mock_compare.return_value = {
            "class_name": "ITest",
            "platform": "windows",
            "differences": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "test.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            result = run_cpp_tests.compile_and_compare(
                test_item={
                    "name": "ITest_MSVC",
                    "symbol": "ITest",
                    "alias_symbols": ["CConcrete"],
                    "exclude_reference_vtables": ["CConcrete_vtable2"],
                    "cpp": "test.cpp",
                    "target": "x86_64-pc-windows-msvc",
                    "additional_compiler_options": ["fdump-vtable-layouts"],
                    "reference_modules": ["engine", "server"],
                },
                args=argparse.Namespace(clang="clang++", std="c++20"),
                config_dir=root,
                symbol_store=object(),
            )

        self.assertEqual("ok", result["status"])
        self.assertEqual(
            ["CConcrete_vtable2"],
            mock_compare.call_args.kwargs["exclude_reference_vtables"],
        )


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
    def test_returns_failure_when_no_targets_are_runnable(
        self,
        mock_parse_args,
        mock_parse_config,
        mock_get_default_target_triple,
        mock_probe_target_support,
        mock_run_one_test,
        mock_open_snapshot_store,
    ) -> None:
        mock_parse_args.return_value = argparse.Namespace(
            configyaml="configs/14174.yaml",
            snapshot="candidate.yaml",
            gamever="14174",
            clang="clang++",
            std="c++20",
            debug=False,
            jobs=None,
        )
        mock_parse_config.return_value = [
            {
                "name": "UnsupportedLayout",
                "symbol": "IUnsupportedLayout",
                "cpp": "test.cpp",
                "target": "x86_64-pc-windows-msvc",
            }
        ]
        mock_get_default_target_triple.return_value = "x86_64-unknown-linux-gnu"
        mock_probe_target_support.return_value = {"supported": False, "output": "unsupported target"}
        mock_open_snapshot_store.return_value.candidate_sha256 = "sha256:test"
        mock_open_snapshot_store.return_value.game_version = "14174"
        mock_open_snapshot_store.return_value.file_count = 1
        mock_open_snapshot_store.return_value.config_sha256 = "sha256:config"

        self.assertEqual(1, run_cpp_tests.main())
        mock_run_one_test.assert_not_called()

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
            jobs=None,
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

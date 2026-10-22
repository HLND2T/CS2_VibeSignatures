import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

import ida_analyze_util as util
from ida_preprocessor_scripts import _igamesystem_dispatch_common as dispatch
from ida_preprocessor_scripts import _indirect_vcall_target_common as indirect


class TestPreprocessorOutputNames(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, stem, data):
        path = self.root / f"{stem}.linux.yaml"
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        return str(path)

    async def test_func_reuse_and_fresh_lookup_keep_artifact_key(self):
        for reused in (True, False):
            with self.subTest(reused=reused):
                output = str(self.root / f"Legacy{reused}.linux.yaml")
                key = f"Legacy{reused}"
                data = {
                    "func_name": key,
                    "func_va": "0x1000",
                    "vfunc_index": 7,
                    "vfunc_offset": "0x38",
                    "vtable_name": "Interface",
                }
                with (
                    patch.object(util, "_try_preprocess_func_without_llm", AsyncMock(return_value=data)),
                    patch.object(util, "_rename_func_in_ida", AsyncMock()) as rename,
                ):
                    result = await util.preprocess_common_skill(
                        session=object(),
                        expected_outputs=[output],
                        old_yaml_map={output: "old.yaml"} if reused else {},
                        new_binary_dir=str(self.root),
                        platform="linux",
                        func_names=[key],
                        generate_yaml_desired_fields=[
                            (key, ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"])
                        ],
                        output_name_map={key: "Interface_CanonicalMethod"},
                    )
                self.assertTrue(result)
                self.assertEqual(
                    {
                        "func_name": "Interface_CanonicalMethod",
                        "vtable_name": "Interface",
                        "vfunc_offset": "0x38",
                        "vfunc_index": 7,
                    },
                    yaml.safe_load(Path(output).read_text(encoding="utf-8")),
                )
                self.assertEqual(("0x1000", "Interface_CanonicalMethod", False), rename.call_args.args[1:])

    async def test_inherited_slot_keeps_legacy_dependency_and_canonical_name(self):
        key = "Concrete_OldMethod"
        output = str(self.root / f"{key}.linux.yaml")
        data = {
            "func_name": key,
            "func_va": "0x2000",
            "vfunc_index": 9,
            "vfunc_offset": "0x48",
            "vtable_name": "Concrete",
        }
        with (
            patch.object(util, "preprocess_index_based_vfunc_via_mcp", AsyncMock(return_value=data)) as locate,
            patch.object(util, "_rename_func_in_ida", AsyncMock()),
        ):
            result = await util.preprocess_common_skill(
                session=object(),
                expected_outputs=[output],
                new_binary_dir=str(self.root),
                platform="linux",
                inherit_vfuncs=[(key, "Concrete", "../engine/Interface_OldMethod", True)],
                generate_yaml_desired_fields=[(key, ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"])],
                output_name_map={key: "Concrete_CanonicalMethod"},
            )
        self.assertTrue(result)
        self.assertEqual("../engine/Interface_OldMethod", locate.call_args.kwargs["base_vfunc_name"])
        self.assertEqual("Concrete_CanonicalMethod", yaml.safe_load(Path(output).read_text())["func_name"])

    async def test_struct_reuse_does_not_restore_old_member_name(self):
        key = "Entity_m_bOldFlag"
        output = str(self.root / f"{key}.linux.yaml")
        with patch.object(
            util,
            "preprocess_struct_offset_sig_via_mcp",
            AsyncMock(
                return_value={
                    "struct_name": "Entity",
                    "member_name": "m_bOldFlag",
                    "offset": "0xc63",
                }
            ),
        ):
            result = await util.preprocess_common_skill(
                session=object(),
                expected_outputs=[output],
                new_binary_dir=str(self.root),
                platform="linux",
                struct_member_names=[key],
                generate_yaml_desired_fields=[(key, ["struct_name", "member_name", "offset"])],
                output_name_map={key: "Entity_m_bCanonicalFlag"},
            )
        self.assertTrue(result)
        self.assertEqual(
            {"struct_name": "Entity", "member_name": "m_bCanonicalFlag", "offset": "0xc63"},
            yaml.safe_load(Path(output).read_text()),
        )

    async def test_invalid_output_map_fails_before_lookup(self):
        for mapping in ({"Unknown": "Canonical"}, {"Known": ""}, {"Known": "../Canonical"}, {"Known": 3}, []):
            with (
                self.subTest(mapping=mapping),
                patch.object(util, "_try_preprocess_func_without_llm", AsyncMock()) as lookup,
            ):
                result = await util.preprocess_common_skill(
                    session=object(),
                    expected_outputs=[str(self.root / "Known.linux.yaml")],
                    new_binary_dir=str(self.root),
                    platform="linux",
                    func_names=["Known"],
                    generate_yaml_desired_fields=[("Known", ["func_name"])],
                    output_name_map=mapping,
                )
                self.assertFalse(result)
                lookup.assert_not_awaited()

    async def test_stale_existing_output_is_regenerated(self):
        key = "Entity_OldMethod"
        output = self.write(key, {"func_name": key, "func_va": "0x1000"})
        with (
            patch.object(
                util,
                "_try_preprocess_func_without_llm",
                AsyncMock(return_value={"func_name": key, "func_va": "0x1000"}),
            ) as lookup,
            patch.object(util, "_rename_func_in_ida", AsyncMock()),
        ):
            result = await util.preprocess_common_skill(
                session=object(),
                expected_outputs=[output],
                new_binary_dir=str(self.root),
                platform="linux",
                func_names=[key],
                generate_yaml_desired_fields=[(key, ["func_name", "func_va"])],
                output_name_map={key: "Entity_CanonicalMethod"},
            )
        self.assertTrue(result)
        lookup.assert_awaited_once()
        self.assertEqual("Entity_CanonicalMethod", yaml.safe_load(Path(output).read_text())["func_name"])

    async def test_llm_fallback_preserves_logical_identifier_and_emits_canonical_member(self):
        key = "Entity_m_bOldFlag"
        canonical = "Entity_m_bCanonicalFlag"
        reference = self.write("Setter", {"func_name": "Setter"})
        old = self.write("Old", {"struct_name": "Entity", "member_name": "m_bCanonicalFlag", "offset": "0xc63"})
        request = {
            "model": "test",
            "prompt_template": "Find the requested member.",
            "target_func_name": "Setter",
            "prompt_path": "/tmp/prompt.md",
            "reference_yaml_path": "/tmp/reference.yaml",
            "disasm_for_reference": "",
            "procedure_for_reference": "",
        }
        for member, expected in (("m_bOldFlag", True), ("m_bUnrelatedFlag", False)):
            with self.subTest(member=member):
                output = str(self.root / f"{key}.linux.yaml")
                if Path(output).exists():
                    Path(output).unlink()
                entry = {"struct_name": "Entity", "member_name": member, "offset": "0xc63", "insn_va": "0x1234"}
                with (
                    patch.object(util, "preprocess_struct_offset_sig_via_mcp", AsyncMock(return_value=None)),
                    patch.object(util, "_prepare_llm_decompile_request", return_value=request),
                    patch.object(
                        util,
                        "_load_llm_decompile_target_details_via_mcp",
                        AsyncMock(return_value=[{"disasm_code": "mov byte ptr [rdi+0xc63], 1", "procedure": "setter"}]),
                    ),
                    patch.object(
                        util, "call_llm_decompile", AsyncMock(return_value={"found_struct_offset": [entry]})
                    ) as llm,
                    patch.object(
                        util,
                        "_preprocess_direct_struct_offset_sig_via_mcp",
                        AsyncMock(return_value={"struct_name": "Entity", "member_name": member, "offset": "0xc63"}),
                    ) as locate,
                ):
                    result = await util.preprocess_common_skill(
                        session=AsyncMock(),
                        expected_outputs=[output],
                        old_yaml_map={output: old},
                        new_binary_dir=str(self.root),
                        platform="linux",
                        struct_member_names=[key],
                        generate_yaml_desired_fields=[(key, ["struct_name", "member_name", "offset"])],
                        llm_decompile_specs=[
                            {
                                "symbol_name": key,
                                "prompt_path": "prompt/call_llm_decompile.md",
                                "reference_yaml_paths": [reference],
                                "expected_result_sections": ["found_struct_offset"],
                                "dependency_policy": {"Setter.{platform}.yaml": "required"},
                            }
                        ],
                        llm_config={"_expected_inputs": [str(self.root / "Setter.linux.yaml")], "_optional_inputs": []},
                        output_name_map={key: canonical},
                        debug=True,
                    )
                self.assertEqual(expected, result)
                self.assertEqual([key], llm.call_args.kwargs["symbol_name_list"])
                self.assertIn(f"{key}: {canonical}", llm.call_args.kwargs["prompt_template"])
                if expected:
                    self.assertEqual("m_bCanonicalFlag", yaml.safe_load(Path(output).read_text())["member_name"])
                    self.assertEqual("0x1234", locate.call_args.kwargs["offset_inst_va"])
                else:
                    locate.assert_not_awaited()
                    self.assertFalse(Path(output).exists())

    async def test_member_output_name_cannot_change_struct_ownership(self):
        key = "Entity_m_bOldFlag"
        output = str(self.root / f"{key}.linux.yaml")
        with patch.object(
            util,
            "preprocess_struct_offset_sig_via_mcp",
            AsyncMock(return_value={"struct_name": "Entity", "member_name": "m_bOldFlag", "offset": "0xc63"}),
        ):
            result = await util.preprocess_common_skill(
                session=object(),
                expected_outputs=[output],
                new_binary_dir=str(self.root),
                platform="linux",
                struct_member_names=[key],
                generate_yaml_desired_fields=[(key, ["struct_name", "member_name", "offset"])],
                output_name_map={key: "OtherEntity_m_bCanonicalFlag"},
            )
        self.assertFalse(result)
        self.assertFalse(Path(output).exists())

    async def test_indirect_vcall_separates_output_name_from_source_and_target_keys(self):
        self.write("Concrete_OldMethod", {"func_va": "0x1234"})
        output = str(self.root / "Interface_OldMethod.linux.yaml")
        with patch.object(
            indirect.IndirectVcallTargetLocator,
            "collect_targets",
            AsyncMock(
                return_value=[
                    {
                        "vfunc_offset": "0x28",
                        "vfunc_index": 5,
                        "source_ea": "0x1234",
                        "source_mnemonic": "jmp",
                    }
                ]
            ),
        ):
            result = await indirect.preprocess_indirect_vcall_target_skill(
                session=object(),
                expected_outputs=[output],
                new_binary_dir=str(self.root),
                platform="linux",
                source_yaml_stem="Concrete_OldMethod",
                target_name="Interface_OldMethod",
                vtable_name="Interface",
                generate_yaml_desired_fields=[
                    ("Interface_OldMethod", ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"])
                ],
                output_name_map={"Interface_OldMethod": "Interface_CanonicalMethod"},
            )
        self.assertTrue(result)
        self.assertEqual(
            {
                "func_name": "Interface_CanonicalMethod",
                "vtable_name": "Interface",
                "vfunc_offset": "0x28",
                "vfunc_index": 5,
            },
            yaml.safe_load(Path(output).read_text()),
        )

    async def test_dispatch_chain_names_do_not_collide_with_artifact_keys(self):
        self.write("Source", {"func_va": "0x1000"})
        self.write("IGameSystem_vtable", {"vtable_entries": {41: "0x2000", 42: "0x3000"}})
        pre, begin = "IGameSystem_PreBegin", "IGameSystem_Begin"
        outputs = [str(self.root / f"{key}.linux.yaml") for key in (pre, begin)]
        entries = [{"vfunc_index": n, "vfunc_offset": n * 8} for n in (42, 41)]
        with (
            patch.object(dispatch, "_call_py_eval_json", AsyncMock(return_value={"entries": entries})),
            patch.object(
                dispatch,
                "_query_func_info",
                AsyncMock(
                    side_effect=[
                        {"func_va": "0x2000", "func_size": "0x10"},
                        {"func_va": "0x3000", "func_size": "0x20"},
                    ]
                ),
            ),
        ):
            result = await dispatch.preprocess_igamesystem_dispatch_skill(
                session=object(),
                expected_outputs=outputs,
                new_binary_dir=str(self.root),
                platform="linux",
                image_base=0,
                source_yaml_stem="Source",
                target_specs=[{"target_name": pre}, {"target_name": begin}],
                via_internal_wrapper=False,
                internal_rename_to=None,
                multi_order="index",
                output_name_map={pre: begin, begin: "IGameSystem_GameBegin"},
            )
        self.assertTrue(result)
        first, second = [yaml.safe_load(Path(p).read_text()) for p in outputs]
        self.assertEqual((begin, 41), (first["func_name"], first["vfunc_index"]))
        self.assertEqual(("IGameSystem_GameBegin", 42), (second["func_name"], second["vfunc_index"]))

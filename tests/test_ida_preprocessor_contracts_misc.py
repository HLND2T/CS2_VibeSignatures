import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from tests.ida_preprocessor_test_support import (
    FakeCallToolResult,
    load_module as _load_module,
    py_eval_payload as _py_eval_payload,
)


PROCESS_MOVEMENT_SCRIPT_PATH = Path("ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement.py")
INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH = Path("ida_preprocessor_scripts/find-g_pInterfaceGlobals_ppGlobal.py")
ONSERVER_VOICE_IS_PLAYING_DEMO_CALLEE_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/find-OnServerVoiceData_IsPlayingDemo_Callee.py"
)


def _write_is_playing_demo_source_yaml(path: Path, **overrides) -> None:
    payload = {
        "func_name": "IVEngineClient2_IsPlayingDemo",
        "vtable_name": "IVEngineClient2",
        "vfunc_offset": "0x150",
        "vfunc_index": 42,
        "vfunc_sig": "FF 90 50 01 00 00 84 C0 74 ?? 83 FD ??",
    }
    payload.update(overrides)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


class TestFindCBaseEntityCollisionRulesChanged(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_generate_yaml_desired_fields(self) -> None:
        module = _load_module(
            "ida_preprocessor_scripts/find-CBaseEntity_CollisionRulesChanged.py",
            "find_CBaseEntity_CollisionRulesChanged",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_llm_decompile_specs = [
            {
                "symbol_name": "CBaseEntity_CollisionRulesChanged",
                "prompt_path": "prompt/call_llm_decompile.md",
                "reference_yaml_paths": [
                    "references/server/PhysEnableEntityCollisions.{platform}.yaml",
                ],
                "expected_result_sections": ["found_vcall"],
                "dependency_policy": {
                    "PhysEnableEntityCollisions.{platform}.yaml": "required",
                },
            },
        ]
        expected_func_vtable_relations = [("CBaseEntity_CollisionRulesChanged", "CBaseEntity")]
        expected_generate_yaml_desired_fields = [
            (
                "CBaseEntity_CollisionRulesChanged",
                [
                    "func_name",
                    "vfunc_sig",
                    "vfunc_offset",
                    "vfunc_index",
                    "vtable_name",
                    "vfunc_sig_allow_across_function_boundary:true",
                ],
            )
        ]

        with patch.object(
            module,
            "preprocess_common_skill",
            mock_preprocess_common_skill,
        ):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess_common_skill.assert_awaited_once_with(
            session="session",
            expected_outputs=["out.yaml"],
            old_yaml_map={"k": "v"},
            new_binary_dir="bin_dir",
            platform="windows",
            image_base=0x180000000,
            func_names=["CBaseEntity_CollisionRulesChanged"],
            func_vtable_relations=expected_func_vtable_relations,
            llm_decompile_specs=expected_llm_decompile_specs,
            llm_config=None,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            debug=True,
        )


class TestFindCcsPlayerMovementServicesProcessMovement(unittest.IsolatedAsyncioTestCase):
    async def test_script_forwards_gv_backed_func_xrefs(self) -> None:
        module = _load_module(
            PROCESS_MOVEMENT_SCRIPT_PATH,
            "find_CCSPlayer_MovementServices_ProcessMovement",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_func_xrefs = [
            {
                "func_name": "CCSPlayer_MovementServices_ProcessMovement",
                "xref_strings": [],
                "xref_gvs": ["CPlayer_MovementServices_s_pRunCommandPawn"],
                "xref_signatures": [],
                "xref_funcs": [],
                "xref_floats": ["64.0", "0.5"],
                "exclude_funcs": [
                    "CPlayer_MovementServices_ForceButtons",
                    "CPlayer_MovementServices_ForceButtonState",
                ],
                "exclude_strings": [],
                "exclude_gvs": [],
                "exclude_signatures": [],
                "exclude_floats": [],
            }
        ]
        expected_func_names = [
            "CCSPlayer_MovementServices_ProcessMovement",
        ]
        expected_generate_yaml_desired_fields = [
            (
                "CCSPlayer_MovementServices_ProcessMovement",
                [
                    "func_name",
                    "func_va",
                    "func_rva",
                    "func_size",
                    "func_sig",
                ],
            ),
        ]

        with patch.object(
            module,
            "preprocess_common_skill",
            mock_preprocess_common_skill,
        ):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess_common_skill.assert_awaited_once_with(
            session="session",
            expected_outputs=["out.yaml"],
            old_yaml_map={"k": "v"},
            new_binary_dir="bin_dir",
            platform="windows",
            image_base=0x180000000,
            func_names=expected_func_names,
            func_xrefs=expected_func_xrefs,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            debug=True,
        )


class TestFindGInterfaceGlobalsPpGlobal(unittest.IsolatedAsyncioTestCase):
    def _build_entries(self, module, platform="windows"):
        return [
            {
                "index": index,
                "entry_va": hex(0x180400000 + index * 0x10),
                "interface_name": interface_name,
                "interface_name_va": hex(0x180500000 + index * 0x20),
                "pp_global_va": hex(0x180600000 + index * 0x8),
            }
            for index, (interface_name, _) in enumerate(module._expected_entries_for_platform(platform))
        ]

    async def _run_with_entries(
        self,
        module,
        actual_entries,
        drop_last_output=False,
        platform="windows",
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / f"g_pInterfaceGlobals.{platform}.yaml"
            input_path.write_text(
                "gv_name: g_pInterfaceGlobals\ngv_va: '0x1804cd5c0'\ngv_rva: '0x4cd5c0'\n",
                encoding="utf-8",
            )
            expected_outputs = [
                str(Path(temp_dir) / f"{gv_name}.{platform}.yaml")
                for gv_name in module._expected_gv_names_for_platform(platform)
            ]
            if drop_last_output:
                expected_outputs = expected_outputs[:-1]

            session = AsyncMock()
            session.call_tool.side_effect = [
                _py_eval_payload(actual_entries),
                _py_eval_payload({"renamed": True}),
            ]

            with patch.object(module, "write_gv_yaml") as mock_write:
                result = await module.preprocess_skill(
                    session=session,
                    skill_name="find-g_pInterfaceGlobals_ppGlobal",
                    expected_outputs=expected_outputs,
                    old_yaml_map={},
                    new_binary_dir=temp_dir,
                    platform=platform,
                    image_base=0x180000000,
                    debug=True,
                )

        return result, mock_write

    async def test_preprocess_skill_writes_minimal_gv_yaml_from_interface_names(
        self,
    ) -> None:
        module = _load_module(
            INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH,
            "find_g_pInterfaceGlobals_ppGlobal",
        )
        actual_entries = self._build_entries(module)

        result, mock_write = await self._run_with_entries(module, actual_entries)

        self.assertTrue(result)
        self.assertEqual(len(module.WINDOWS_EXPECTED_ENTRIES), mock_write.call_count)
        first_path, first_payload = mock_write.call_args_list[0].args
        self.assertTrue(first_path.endswith("g_pVApplication.windows.yaml"))
        self.assertEqual(
            {
                "gv_name": "g_pVApplication",
                "gv_va": "0x180600000",
                "gv_rva": "0x600000",
            },
            first_payload,
        )

    async def test_preprocess_skill_excludes_nav_globals_on_linux(self) -> None:
        module = _load_module(
            INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH,
            "find_g_pInterfaceGlobals_ppGlobal_linux",
        )
        actual_entries = self._build_entries(module, platform="linux")

        result, mock_write = await self._run_with_entries(
            module,
            actual_entries,
            platform="linux",
        )

        self.assertTrue(result)
        self.assertEqual(len(module.LINUX_EXPECTED_ENTRIES), mock_write.call_count)
        written_paths = [call_args.args[0] for call_args in mock_write.call_args_list]
        self.assertFalse(any(path.endswith("g_pNavGameTest.linux.yaml") for path in written_paths))
        self.assertFalse(any(path.endswith("g_pNavSystem.linux.yaml") for path in written_paths))
        self.assertEqual(
            ("Vrad3_001", "g_pRAD3"),
            module.LINUX_EXPECTED_ENTRIES[-1],
        )

    async def test_preprocess_skill_fails_on_missing_entry(self) -> None:
        module = _load_module(
            INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH,
            "find_g_pInterfaceGlobals_ppGlobal_missing",
        )
        actual_entries = self._build_entries(module)[:-1]

        result, mock_write = await self._run_with_entries(module, actual_entries)

        self.assertFalse(result)
        mock_write.assert_not_called()

    async def test_preprocess_skill_allows_trailing_extra_entries(self) -> None:
        module = _load_module(
            INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH,
            "find_g_pInterfaceGlobals_ppGlobal_extra",
        )
        actual_entries = self._build_entries(module)
        actual_entries.append(
            {
                "index": len(actual_entries),
                "entry_va": hex(0x180400000 + len(actual_entries) * 0x10),
                "interface_name": "ExtraInterface001",
                "interface_name_va": "0x180700000",
                "pp_global_va": "0x180710000",
            }
        )

        result, mock_write = await self._run_with_entries(module, actual_entries)

        self.assertTrue(result)
        self.assertEqual(len(module.WINDOWS_EXPECTED_ENTRIES), mock_write.call_count)
        written_paths = [call_args.args[0] for call_args in mock_write.call_args_list]
        self.assertFalse(any("ExtraInterface001" in path for path in written_paths))

    async def test_preprocess_skill_allows_entries_out_of_order(self) -> None:
        module = _load_module(
            INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH,
            "find_g_pInterfaceGlobals_ppGlobal_out_of_order",
        )
        actual_entries = self._build_entries(module)
        actual_entries[-2], actual_entries[-1] = (
            actual_entries[-1],
            actual_entries[-2],
        )

        result, mock_write = await self._run_with_entries(module, actual_entries)

        self.assertTrue(result)
        payloads = {call_args.args[1]["gv_name"]: call_args.args[1] for call_args in mock_write.call_args_list}
        self.assertEqual("0x180600370", payloads["g_pNavSystem"]["gv_va"])
        self.assertEqual("0x180600378", payloads["g_pNavGameTest"]["gv_va"])

    async def test_preprocess_skill_fails_on_interface_name_mismatch(self) -> None:
        module = _load_module(
            INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH,
            "find_g_pInterfaceGlobals_ppGlobal_mismatch",
        )
        actual_entries = self._build_entries(module)
        actual_entries[1]["interface_name"] = "WrongInterface001"

        result, mock_write = await self._run_with_entries(module, actual_entries)

        self.assertFalse(result)
        mock_write.assert_not_called()

    async def test_preprocess_skill_fails_when_expected_output_is_missing(
        self,
    ) -> None:
        module = _load_module(
            INTERFACE_GLOBALS_PPGLOBAL_SCRIPT_PATH,
            "find_g_pInterfaceGlobals_ppGlobal_missing_output",
        )
        actual_entries = self._build_entries(module)

        result, mock_write = await self._run_with_entries(
            module,
            actual_entries,
            drop_last_output=True,
        )

        self.assertFalse(result)
        mock_write.assert_not_called()


class TestCanonicalVtablePreprocessors(unittest.IsolatedAsyncioTestCase):
    MAIN_VTABLE_CASES = (
        ("CEngineClient", "_ZTV13CEngineClient + 0x10"),
        ("CEngineServer", "_ZTV13CEngineServer + 0x10"),
        ("CLoopTypeSimpleService", "_ZTV22CLoopTypeSimpleService + 0x10"),
        ("CNetSupportImpl", "_ZTV15CNetSupportImpl + 0x10"),
        ("CSplitScreenService", "_ZTV19CSplitScreenService + 0x10"),
        ("CFlattenedSerializers", "_ZTV21CFlattenedSerializers + 0x10"),
        (
            "CEntFireOutputAutoCompletionFunctor",
            "_ZTV35CEntFireOutputAutoCompletionFunctor + 0x10",
        ),
        (
            "CEntitySaveRestoreBlockHandler",
            "_ZTV30CEntitySaveRestoreBlockHandler + 0x10",
        ),
        ("CSaveRestoreBlockSet", "_ZTV20CSaveRestoreBlockSet + 0x10"),
        ("CSource2GameClients", "_ZTV19CSource2GameClients + 0x10"),
        ("CSource2GameEntities", "_ZTV20CSource2GameEntities + 0x10"),
        ("CSource2Server", "_ZTV14CSource2Server + 0x10"),
        (
            "CLoopModeFactory_CLoopModeGame",
            "_ZTV16CLoopModeFactoryI13CLoopModeGameE + 0x10",
        ),
        (
            "CEntityComponentHelperT_CBodyComponent",
            "_ZTV23CEntityComponentHelperTI14CBodyComponent32CEntityComponentHelperReferencedIS0_EE + 0x10",
        ),
    )

    async def test_main_vtable_finders_forward_platform_canonical_symbols(self) -> None:
        for class_name, linux_symbol in self.MAIN_VTABLE_CASES:
            script_path = Path(f"ida_preprocessor_scripts/find-{class_name}_vtable.py")
            for platform, expected_symbol in (
                ("windows", f"{class_name}_vtable"),
                ("linux", linux_symbol),
            ):
                with self.subTest(class_name=class_name, platform=platform):
                    module = _load_module(
                        script_path,
                        f"canonical_{class_name}_{platform}",
                    )
                    mock_preprocess_common_skill = AsyncMock(return_value=True)
                    with patch.object(
                        module,
                        "preprocess_common_skill",
                        mock_preprocess_common_skill,
                    ):
                        result = await module.preprocess_skill(
                            session="session",
                            skill_name="skill",
                            expected_outputs=["out.yaml"],
                            old_yaml_map={},
                            new_binary_dir="bin_dir",
                            platform=platform,
                            image_base=0x180000000,
                            debug=True,
                        )

                    self.assertTrue(result)
                    self.assertEqual(
                        {class_name: expected_symbol},
                        mock_preprocess_common_skill.await_args.kwargs["canonical_vtable_symbols"],
                    )

    async def test_ordinal_vtable_finders_only_override_linux_symbols(self) -> None:
        for output_stem in (
            "CSpawnGroupMgrGameSystem_vtable2",
            "CLoopTypeClientServerService_vtable2",
        ):
            script_path = Path(f"ida_preprocessor_scripts/find-{output_stem}.py")
            for platform in ("windows", "linux"):
                with self.subTest(output_stem=output_stem, platform=platform):
                    module = _load_module(
                        script_path,
                        f"canonical_{output_stem}_{platform}",
                    )
                    mock_preprocess_ordinal_vtable = AsyncMock(return_value={"vtable_symbol": output_stem})
                    with (
                        patch.object(
                            module,
                            "preprocess_ordinal_vtable_via_mcp",
                            mock_preprocess_ordinal_vtable,
                        ),
                        patch.object(module, "write_vtable_yaml"),
                    ):
                        result = await module.preprocess_skill(
                            session="session",
                            skill_name="skill",
                            expected_outputs=[f"tmp/{output_stem}.{platform}.yaml"],
                            old_yaml_map={},
                            new_binary_dir="bin_dir",
                            platform=platform,
                            image_base=0x180000000,
                            debug=True,
                        )

                    self.assertTrue(result)
                    self.assertEqual(
                        output_stem if platform == "linux" else None,
                        mock_preprocess_ordinal_vtable.await_args.kwargs["canonical_vtable_symbol"],
                    )

    async def test_source2_server_vtable2_overrides_automatic_symbol(self) -> None:
        script_path = Path("ida_preprocessor_scripts/find-CSource2Server_vtable2.py")
        for platform in ("windows", "linux"):
            with self.subTest(platform=platform):
                module = _load_module(
                    script_path,
                    f"canonical_CSource2Server_vtable2_{platform}",
                )
                automatic_payload = {
                    "vtable_class": "CSource2Server",
                    "vtable_symbol": "off_180000000",
                }
                with (
                    patch.object(module, "_read_yaml", return_value={"vtable_va": "0x1"}),
                    patch.object(
                        module,
                        "_lookup_vtable2",
                        AsyncMock(return_value=automatic_payload),
                    ),
                    patch.object(module, "write_vtable_yaml") as mock_write_vtable_yaml,
                ):
                    result = await module.preprocess_skill(
                        session="session",
                        skill_name="skill",
                        expected_outputs=[f"tmp/CSource2Server_vtable2.{platform}.yaml"],
                        old_yaml_map={},
                        new_binary_dir="bin_dir",
                        platform=platform,
                        image_base=0x180000000,
                        debug=True,
                    )

                self.assertTrue(result)
                written_payload = mock_write_vtable_yaml.call_args.args[1]
                self.assertEqual(
                    "CSource2Server_vtable2",
                    written_payload["vtable_symbol"],
                )

    async def test_source2_server_vtable2_propagates_lookup_errors(self) -> None:
        module = _load_module(
            Path("ida_preprocessor_scripts/find-CSource2Server_vtable2.py"),
            "diagnostic_CSource2Server_vtable2",
        )
        with (
            patch.object(module, "_read_yaml", return_value={"vtable_va": "0x1"}),
            patch.object(
                module,
                "_lookup_vtable2",
                AsyncMock(side_effect=RuntimeError("lookup exploded")),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "lookup exploded"):
                await module.preprocess_skill(
                    session="session",
                    skill_name="skill",
                    expected_outputs=["tmp/CSource2Server_vtable2.windows.yaml"],
                    old_yaml_map={},
                    new_binary_dir="bin_dir",
                    platform="windows",
                    image_base=0x180000000,
                    debug=False,
                )


class TestFindOnServerVoiceDataIsPlayingDemoCallee(unittest.IsolatedAsyncioTestCase):
    async def test_generates_patch_yaml_from_unique_vfunc_signature_match(self) -> None:
        module = _load_module(
            ONSERVER_VOICE_IS_PLAYING_DEMO_CALLEE_SCRIPT_PATH,
            "find_OnServerVoiceData_IsPlayingDemo_Callee",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir)
            source_path = module_dir / "IVEngineClient2_IsPlayingDemo.windows.yaml"
            output_path = module_dir / "OnServerVoiceData_IsPlayingDemo_Callee.windows.yaml"
            _write_is_playing_demo_source_yaml(source_path)

            session = AsyncMock()
            session.call_tool.return_value = FakeCallToolResult([{"matches": ["0x180aec45d"], "n": 1}])

            result = await module.preprocess_skill(
                session=session,
                skill_name="find-OnServerVoiceData_IsPlayingDemo_Callee",
                expected_outputs=[str(output_path)],
                old_yaml_map={},
                new_binary_dir=str(module_dir),
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

            payload = yaml.safe_load(output_path.read_text(encoding="utf-8"))

        self.assertTrue(result)
        session.call_tool.assert_awaited_once_with(
            name="find_bytes",
            arguments={
                "patterns": ["FF 90 50 01 00 00 84 C0 74 ?? 83 FD ??"],
                "limit": 2,
            },
        )
        self.assertEqual(
            {
                "patch_name": "OnServerVoiceData_IsPlayingDemo_Callee",
                "patch_va": "0x180aec45d",
                "patch_rva": "0xaec45d",
                "patch_sig": "FF 90 50 01 00 00 84 C0 74 ?? 83 FD ??",
                "patch_sig_disp": 0,
            },
            payload,
        )

    async def test_rejects_signature_that_does_not_start_at_the_vcall(self) -> None:
        module = _load_module(
            ONSERVER_VOICE_IS_PLAYING_DEMO_CALLEE_SCRIPT_PATH,
            "find_OnServerVoiceData_IsPlayingDemo_Callee_bad_sig",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir)
            source_path = module_dir / "IVEngineClient2_IsPlayingDemo.windows.yaml"
            output_path = module_dir / "OnServerVoiceData_IsPlayingDemo_Callee.windows.yaml"
            _write_is_playing_demo_source_yaml(
                source_path,
                vfunc_sig="48 8B 01 FF 90 50 01 00 00",
            )

            session = AsyncMock()
            result = await module.preprocess_skill(
                session=session,
                skill_name="find-OnServerVoiceData_IsPlayingDemo_Callee",
                expected_outputs=[str(output_path)],
                old_yaml_map={},
                new_binary_dir=str(module_dir),
                platform="windows",
                image_base=0x180000000,
            )

            self.assertFalse(output_path.exists())

        self.assertFalse(result)
        session.call_tool.assert_not_awaited()

    async def test_rejects_non_unique_signature_match(self) -> None:
        module = _load_module(
            ONSERVER_VOICE_IS_PLAYING_DEMO_CALLEE_SCRIPT_PATH,
            "find_OnServerVoiceData_IsPlayingDemo_Callee_multi",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir)
            source_path = module_dir / "IVEngineClient2_IsPlayingDemo.windows.yaml"
            output_path = module_dir / "OnServerVoiceData_IsPlayingDemo_Callee.windows.yaml"
            _write_is_playing_demo_source_yaml(source_path)

            session = AsyncMock()
            session.call_tool.return_value = FakeCallToolResult([{"matches": ["0x180aec45d", "0x180bed000"], "n": 2}])

            result = await module.preprocess_skill(
                session=session,
                skill_name="find-OnServerVoiceData_IsPlayingDemo_Callee",
                expected_outputs=[str(output_path)],
                old_yaml_map={},
                new_binary_dir=str(module_dir),
                platform="windows",
                image_base=0x180000000,
            )

            self.assertFalse(output_path.exists())

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()

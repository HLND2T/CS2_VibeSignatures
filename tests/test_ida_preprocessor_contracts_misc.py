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
NETWORK_MESSAGES_GET_IS_FOR_SERVER_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/find-CNetworkMessages_GetIsForServer.py"
)
NETWORK_MESSAGES_GET_SERIALIZATION_CONTEXT_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/find-CNetworkMessages_GetNetworkSerializationContextData.py"
)
FLASHBANG_PROJECTILE_SPAWN_DECOMPILES_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/find-CFlashbangProjectile_Spawn-decompiles.py"
)

LEGACY_INPUT_XREFS_CASES = (
    {
        "module_name": "find_CBaseFilter_InputTestActivator",
        "script_path": Path("ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py"),
        "target_name": "CBaseFilter_InputTestActivator",
        "windows": None,
        "linux": [
            "55 48 89 E5 41 55 41 54 49 89 F4 53 48 89 FB 48 81 EC ? ? ? ? 48 8B 07 48 8B 16",
        ],
    },
    {
        "module_name": "find_CGamePlayerEquip_InputTriggerForAllPlayers",
        "script_path": Path("ida_preprocessor_scripts/find-CGamePlayerEquip_InputTriggerForAllPlayers.py"),
        "target_name": "CGamePlayerEquip_InputTriggerForAllPlayers",
        "windows": [
            "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8B EC 48 83 EC ? 4C 8B F1",
        ],
        "linux": [
            "55 48 89 E5 41 57 41 56 41 55 41 54 49 89 FC 53 48 83 EC ? E8 ? ? ? ? "
            "C7 45 ? ? ? ? ? 89 C7 66 89 45 ? 66 83 F8 ? 75 ? 48 C7 45 ? ? ? ? ? 66 83 FF ? "
            "0F 84 ? ? ? ? 0F B7 7D ? E8 ? ? ? ? 66 89 45 ? 66 83 F8 ? 0F 84 ? ? ? ? 89 C7 "
            "E8 ? ? ? ? 0F B7 7D ? 48 89 C3 48 85 C0 74 ? 48 89 C7 E8 ? ? ? ? 48 8D 7D ? "
            "48 89 C6 E8 ? ? ? ? 0F B7 7D ? 84 C0 0F 85 ? ? ? ? EB ? 66 0F 1F 44 00 ? "
            "E8 ? ? ? ? 48 89 C3 48 85 C0 0F 84 ? ? ? ? 48 89 C7 E8 ? ? ? ? 48 8D 7D ? "
            "48 89 C6 E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 0F B7 7D ? 48 89 5D ? 66 83 FF",
        ],
    },
    {
        "module_name": "find_CGamePlayerEquip_InputTriggerForActivatedPlayer",
        "script_path": Path("ida_preprocessor_scripts/find-CGamePlayerEquip_InputTriggerForActivatedPlayer.py"),
        "target_name": "CGamePlayerEquip_InputTriggerForActivatedPlayer",
        "windows": ["48 89 5C 24 ? 56 48 83 EC ? 48 8B 1A"],
        "linux": ["55 48 89 E5 41 56 41 55 41 54 53 48 8B 1E 48 85 DB 74"],
    },
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


class TestLinuxLayoutRecovery(unittest.IsolatedAsyncioTestCase):
    def test_active_loop_recovery_rejects_dispatcher_getter_and_ambiguous_writers(self):
        module = _load_module(
            "ida_preprocessor_scripts/find-IEngineServiceMgr_GetActiveLoop.py", "active_loop_recovery"
        )
        getter = bytes.fromhex("48 8D 87 78 01 00 00 C3")
        writer = bytes.fromhex("C6 46 20 01 48 8B 57 38 C6 46 20 00 C3")
        self.assertEqual(32, module.recover_linux_active_loop_slot({28: getter, 32: writer}))
        self.assertEqual(33, module.recover_linux_active_loop_slot({29: getter, 33: writer}))
        self.assertIsNone(module.recover_linux_active_loop_slot({28: getter}))
        self.assertIsNone(module.recover_linux_active_loop_slot({32: writer, 33: writer}))

    def test_gamesystem_tail_recovery_uses_interface_not_factory_primary_indices(self):
        module = _load_module(
            "ida_preprocessor_scripts/find-CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_DestroyGameSystem-decompiles.py",
            "gamesystem_tail_recovery",
        )
        bodies = {
            100: bytes.fromhex("48 8B 47 08 C3"),
            200: b"\xc3",
            300: bytes.fromhex("48 89 77 08 C3"),
            400: bytes.fromhex("31 C0 C3"),
        }
        for start in (59, 69):
            entries = dict(zip(range(start, start + 6), [100, 200, 300, 400, 0, 0]))
            self.assertEqual(
                {"IGameSystem_SetGameSystemGlobalPtrs": start + 1, "IGameSystem_vdtor": start + 4},
                module.recover_linux_interface_slots(entries, bodies),
            )
            entries[start + 4] = 200
            self.assertIsNone(module.recover_linux_interface_slots(entries, bodies))
        self.assertIsNone(module.recover_linux_interface_slots({24: 200, 28: 100}, bodies))

    def test_entity_name_map_recovery_excludes_storage_subobject_and_rejects_ambiguity(self):
        module = _load_module("ida_preprocessor_scripts/find-CEntitySystem_m_entityNames.py", "entity_name_map")

        def fields(base):
            return [
                {"kind": "flags", "offset": base + 0xA},
                {"kind": "storage", "offset": base + 0x10},
                {"kind": "word", "offset": base + 0x18},
            ]

        self.assertEqual(0xAF0, module.recover_map_base(fields(0xAF0)))
        self.assertEqual(0xBF0, module.recover_map_base(fields(0xBF0)))
        self.assertIsNone(module.recover_map_base(fields(0xAF0)[:-1]))
        self.assertIsNone(module.recover_map_base(fields(0xAF0) + fields(0xBF0)))


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


class TestFindCFlashbangProjectileSpawnDecompiles(unittest.IsolatedAsyncioTestCase):
    async def test_preserves_cross_boundary_gravity_signature_contract(self) -> None:
        module = _load_module(
            FLASHBANG_PROJECTILE_SPAWN_DECOMPILES_SCRIPT_PATH,
            "find_CFlashbangProjectile_Spawn_decompiles",
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
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        generation_contracts = dict(mock_preprocess_common_skill.await_args.kwargs["generate_yaml_desired_fields"])
        self.assertEqual(
            [
                "func_name",
                "func_sig",
                "func_va",
                "func_rva",
                "func_size",
                "func_sig_allow_across_function_boundary:true",
            ],
            generation_contracts["CBaseEntity_SetGravityScale"],
        )


class TestFindCNetworkMessagesGetIsForServer(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_vfunc_metadata_contract(self) -> None:
        module = _load_module(
            NETWORK_MESSAGES_GET_IS_FOR_SERVER_SCRIPT_PATH,
            "find_CNetworkMessages_GetIsForServer",
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
            func_names=["CNetworkMessages_GetIsForServer"],
            func_vtable_relations=[
                ("CNetworkMessages_GetIsForServer", "CNetworkMessages"),
            ],
            generate_yaml_desired_fields=[
                (
                    "CNetworkMessages_GetIsForServer",
                    [
                        "func_name",
                        "func_va",
                        "func_rva",
                        "func_size",
                        "func_sig",
                        "vtable_name",
                        "vfunc_offset",
                        "vfunc_index",
                    ],
                ),
            ],
            debug=True,
        )


class TestFindCNetworkMessagesGetNetworkSerializationContextData(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_vfunc_metadata_contract(self) -> None:
        module = _load_module(
            NETWORK_MESSAGES_GET_SERIALIZATION_CONTEXT_SCRIPT_PATH,
            "find_CNetworkMessages_GetNetworkSerializationContextData",
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
            func_names=["CNetworkMessages_GetNetworkSerializationContextData"],
            func_vtable_relations=[
                (
                    "CNetworkMessages_GetNetworkSerializationContextData",
                    "CNetworkMessages",
                ),
            ],
            generate_yaml_desired_fields=[
                (
                    "CNetworkMessages_GetNetworkSerializationContextData",
                    [
                        "func_name",
                        "func_va",
                        "func_rva",
                        "func_size",
                        "func_sig",
                        "vtable_name",
                        "vfunc_offset",
                        "vfunc_index",
                    ],
                ),
            ],
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


class TestLegacyInputBodyXrefContracts(unittest.IsolatedAsyncioTestCase):
    """The 14182 `_API` migration moved inputs off DEFINE_INPUTFUNC (issue 1061).

    These three legacy symbols are now relocated by the signature CS2Fixes maintains for
    the body each `_API` wrapper forwards to, so the forwarded spec is the contract.
    """

    @staticmethod
    def _expected_spec(target_name, signatures):
        return [
            {
                "func_name": target_name,
                "xref_strings": [],
                "xref_gvs": [],
                "xref_signatures": signatures,
                "xref_funcs": [],
                "exclude_funcs": [],
                "exclude_strings": [],
                "exclude_gvs": [],
                "exclude_signatures": [],
            }
        ]

    async def test_scripts_forward_platform_signature_specs(self) -> None:
        for case in LEGACY_INPUT_XREFS_CASES:
            for platform in ("windows", "linux"):
                signatures = case[platform]
                if signatures is None:
                    continue
                with self.subTest(case=case["module_name"], platform=platform):
                    module = _load_module(case["script_path"], f"{case['module_name']}_{platform}")
                    mock_helper = AsyncMock(return_value=True)

                    with patch.object(module, "preprocess_common_skill", mock_helper):
                        result = await module.preprocess_skill(
                            session="session",
                            skill_name="skill",
                            expected_outputs=["out.yaml"],
                            old_yaml_map={"k": "v"},
                            new_binary_dir="bin_dir",
                            platform=platform,
                            image_base=0x180000000,
                            debug=True,
                        )

                    self.assertTrue(result)
                    mock_helper.assert_awaited_once_with(
                        session="session",
                        expected_outputs=["out.yaml"],
                        old_yaml_map={"k": "v"},
                        new_binary_dir="bin_dir",
                        platform=platform,
                        image_base=0x180000000,
                        func_names=[case["target_name"]],
                        func_xrefs=self._expected_spec(case["target_name"], signatures),
                        generate_yaml_desired_fields=[
                            (
                                case["target_name"],
                                ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
                            )
                        ],
                        debug=True,
                    )

    def test_windows_inlined_test_activator_body_is_not_declared(self) -> None:
        case = LEGACY_INPUT_XREFS_CASES[0]

        self.assertIsNone(case["windows"])
        self.assertEqual("CBaseFilter_InputTestActivator", case["target_name"])


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


class TestConvarFilterCallChain(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from ida_preprocessor_scripts import _convar_filter_chain_common

        self.chain = _convar_filter_chain_common

    async def test_inline_body_does_not_walk_helpers(self):
        with patch.object(self.chain, "preprocess_common_skill", AsyncMock(return_value=True)) as preprocess:
            self.assertTrue(await self.chain.preprocess_call_chain(session="session"))
        self.assertEqual(preprocess.await_count, 1)
        self.assertNotIn("llm_target_details_loader", preprocess.await_args.kwargs)

    async def test_deinlined_body_uses_instruction_loader(self):
        with patch.object(self.chain, "preprocess_common_skill", AsyncMock(side_effect=[False, True])) as preprocess:
            self.assertTrue(await self.chain.preprocess_call_chain(session="session"))
        self.assertIs(preprocess.await_args.kwargs["llm_target_details_loader"], self.chain.load_helper_details)

    async def test_helper_instructions_remain_available_for_validation(self):
        root = {"func_va": "0x1000", "disasm_code": "0x1000 call sub_2000"}
        helper = {"func_va": "0x2000", "disasm_code": "0x2000 jmp qword ptr [rax+80h]"}
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        with (
            patch.object(self.chain, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])),
            patch.object(
                self.chain, "parse_mcp_result", return_value={"result": '{"addresses":["0x2000"],"overflow":false}'}
            ),
            patch.object(self.chain, "_export_function_detail_via_mcp", AsyncMock(return_value=helper)),
        ):
            self.assertEqual(await self.chain.load_helper_details(session, ["Set"]), [root, helper])

    async def test_partial_or_overflowing_chains_fail_closed(self):
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        for overflow in (True, False):
            with (
                self.subTest(overflow=overflow),
                patch.object(
                    self.chain,
                    "_load_llm_decompile_target_details_via_mcp",
                    AsyncMock(return_value=[{"func_va": "0x1000"}]),
                ),
                patch.object(
                    self.chain,
                    "parse_mcp_result",
                    return_value={"result": '{"addresses":["0x2000"],"overflow":' + str(overflow).lower() + "}"},
                ),
                patch.object(self.chain, "_export_function_detail_via_mcp", AsyncMock(return_value=None)),
            ):
                self.assertEqual(await self.chain.load_helper_details(session, ["Set"]), [])

    def test_ambiguous_filter_slots_fail_closed(self):
        finder = _load_module(Path("ida_preprocessor_scripts/find-ICvar_CallFilterCallback.py"), "find_ICvar_filter")
        entry = {"func_name": "ICvar_CallFilterCallback", "vfunc_offset": "0x80"}
        self.assertEqual(finder.validate_dispatch({"found_vcall": [entry]}), [])
        self.assertTrue(finder.validate_dispatch({"found_vcall": [entry, {**entry, "vfunc_offset": "0x88"}]}))


class TestCvarIterateCallbackChain(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.finder = _load_module(
            Path("ida_preprocessor_scripts/find-ICvar_IterateConVarCallbacks.py"), "find_ICvar_IterateConVarCallbacks"
        )

    async def test_inline_dispatch_does_not_walk_helpers(self):
        with patch.object(self.finder, "preprocess_common_skill", AsyncMock(return_value=True)) as preprocess:
            self.assertTrue(await self.finder.preprocess_skill("session", "finder", [], {}, "/tmp", "linux", 0))
        self.assertEqual(preprocess.await_count, 1)
        self.assertNotIn("llm_target_details_loader", preprocess.await_args.kwargs)

    async def test_missing_inline_dispatch_uses_helper_loader(self):
        with patch.object(self.finder, "preprocess_common_skill", AsyncMock(side_effect=[False, True])) as preprocess:
            self.assertTrue(await self.finder.preprocess_skill("session", "finder", [], {}, "/tmp", "linux", 0))
        self.assertIs(preprocess.await_args.kwargs["llm_target_details_loader"], self.finder.load_helper_details)

    async def test_helper_instructions_are_exported_for_llm_validation(self):
        root = {"func_va": "0x1000", "disasm_code": "0x1000 call sub_2000"}
        helper = {"func_va": "0x2000", "disasm_code": "0x2000 call qword ptr [rax+78h]"}
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        with (
            patch.object(self.finder, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])),
            patch.object(
                self.finder, "parse_mcp_result", return_value={"result": '{"addresses":["0x2000"],"overflow":false}'}
            ),
            patch.object(self.finder, "_export_function_detail_via_mcp", AsyncMock(return_value=helper)),
        ):
            self.assertEqual(await self.finder.load_helper_details(session, ["Connect"]), [root, helper])

    async def test_incomplete_helper_export_fails_closed(self):
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        for overflow in (True, False):
            with (
                self.subTest(overflow=overflow),
                patch.object(
                    self.finder,
                    "_load_llm_decompile_target_details_via_mcp",
                    AsyncMock(return_value=[{"func_va": "0x1000"}]),
                ),
                patch.object(
                    self.finder,
                    "parse_mcp_result",
                    return_value={"result": '{"addresses":["0x2000"],"overflow":' + str(overflow).lower() + "}"},
                ),
                patch.object(self.finder, "_export_function_detail_via_mcp", AsyncMock(return_value=None)),
            ):
                self.assertEqual(await self.finder.load_helper_details(session, ["Connect"]), [])

    def test_multiple_dispatches_are_rejected(self):
        entry = {"func_name": "ICvar_IterateConVarCallbacks", "insn_va": "0x2000", "vfunc_offset": "0x78"}
        self.assertEqual(self.finder.validate_dispatch({"found_vcall": [entry]}), [])
        self.assertTrue(self.finder.validate_dispatch({"found_vcall": [entry, {**entry, "insn_va": "0x3000"}]}))


class TestCvarChangeCallbackChain(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.finder = _load_module(
            Path("ida_preprocessor_scripts/find-ICvar_CallChangeCallback.py"), "find_ICvar_CallChangeCallback"
        )

    async def test_inline_dispatch_does_not_walk_helpers(self):
        with patch.object(self.finder, "preprocess_common_skill", AsyncMock(return_value=True)) as preprocess:
            self.assertTrue(await self.finder.preprocess_skill("session", "finder", [], {}, "/tmp", "linux", 0))
        self.assertEqual(preprocess.await_count, 1)
        self.assertNotIn("llm_target_details_loader", preprocess.await_args.kwargs)

    async def test_missing_inline_dispatch_uses_helper_loader(self):
        with patch.object(self.finder, "preprocess_common_skill", AsyncMock(side_effect=[False, True])) as preprocess:
            self.assertTrue(await self.finder.preprocess_skill("session", "finder", [], {}, "/tmp", "linux", 0))
        self.assertIs(preprocess.await_args.kwargs["llm_target_details_loader"], self.finder.load_helper_details)

    async def test_helper_instructions_are_exported_for_llm_validation(self):
        root = {"func_va": "0x1000", "disasm_code": "0x1000 call sub_2000"}
        helper = {"func_va": "0x2000", "disasm_code": "0x2000 call qword ptr [rax+70h]"}
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        with (
            patch.object(self.finder, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])),
            patch.object(
                self.finder, "parse_mcp_result", return_value={"result": '{"addresses":["0x2000"],"overflow":false}'}
            ),
            patch.object(self.finder, "_export_function_detail_via_mcp", AsyncMock(return_value=helper)),
        ):
            self.assertEqual(await self.finder.load_helper_details(session, ["Setter"]), [root, helper])

    async def test_incomplete_helper_export_fails_closed(self):
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        for overflow in (True, False):
            with (
                self.subTest(overflow=overflow),
                patch.object(
                    self.finder,
                    "_load_llm_decompile_target_details_via_mcp",
                    AsyncMock(return_value=[{"func_va": "0x1000"}]),
                ),
                patch.object(
                    self.finder,
                    "parse_mcp_result",
                    return_value={"result": '{"addresses":["0x2000"],"overflow":' + str(overflow).lower() + "}"},
                ),
                patch.object(self.finder, "_export_function_detail_via_mcp", AsyncMock(return_value=None)),
            ):
                self.assertEqual(await self.finder.load_helper_details(session, ["Setter"]), [])

    def test_multiple_dispatches_are_rejected(self):
        entry = {"func_name": "ICvar_CallChangeCallback", "insn_va": "0x2000", "vfunc_offset": "0x70"}
        self.assertEqual(self.finder.validate_dispatch({"found_vcall": [entry]}), [])
        self.assertTrue(self.finder.validate_dispatch({"found_vcall": [entry, {**entry, "insn_va": "0x3000"}]}))


class TestCvarRemoveGlobalChangeCallbackChain(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.finder = _load_module(
            Path("ida_preprocessor_scripts/find-ICvar_RemoveGlobalChangeCallback.py"),
            "find_ICvar_RemoveGlobalChangeCallback",
        )

    async def test_inline_dispatch_does_not_walk_helpers(self):
        with patch.object(self.finder, "preprocess_common_skill", AsyncMock(return_value=True)) as preprocess:
            self.assertTrue(await self.finder.preprocess_skill("session", "finder", [], {}, "/tmp", "linux", 0))
        self.assertEqual(preprocess.await_count, 1)
        self.assertNotIn("llm_target_details_loader", preprocess.await_args.kwargs)

    async def test_missing_inline_dispatch_uses_helper_loader(self):
        with patch.object(self.finder, "preprocess_common_skill", AsyncMock(side_effect=[False, True])) as preprocess:
            self.assertTrue(await self.finder.preprocess_skill("session", "finder", [], {}, "/tmp", "linux", 0))
        self.assertIs(preprocess.await_args.kwargs["llm_target_details_loader"], self.finder.load_helper_details)

    async def test_helper_instructions_are_exported_for_llm_validation(self):
        root = {"func_va": "0x1000", "disasm_code": "0x1000 call sub_2000"}
        helper = {"func_va": "0x2000", "disasm_code": "0x2000 call qword ptr [rax+0B0h]"}
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        with (
            patch.object(self.finder, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])),
            patch.object(
                self.finder, "parse_mcp_result", return_value={"result": '{"addresses":["0x2000"],"overflow":false}'}
            ),
            patch.object(self.finder, "_export_function_detail_via_mcp", AsyncMock(return_value=helper)),
        ):
            self.assertEqual(await self.finder.load_helper_details(session, ["Shutdown"]), [root, helper])

    async def test_incomplete_helper_export_fails_closed(self):
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        for overflow in (True, False):
            with (
                self.subTest(overflow=overflow),
                patch.object(
                    self.finder,
                    "_load_llm_decompile_target_details_via_mcp",
                    AsyncMock(return_value=[{"func_va": "0x1000"}]),
                ),
                patch.object(
                    self.finder,
                    "parse_mcp_result",
                    return_value={"result": '{"addresses":["0x2000"],"overflow":' + str(overflow).lower() + "}"},
                ),
                patch.object(self.finder, "_export_function_detail_via_mcp", AsyncMock(return_value=None)),
            ):
                self.assertEqual(await self.finder.load_helper_details(session, ["Shutdown"]), [])


class TestCMultiplayRulesCtorDecompiles(unittest.IsolatedAsyncioTestCase):
    """CMultiplayRules_ctor is decompiled once for every interface vcall it issues."""

    def setUp(self):
        self.finder = _load_module(
            Path("ida_preprocessor_scripts/find-CMultiplayRules_ctor-decompiles.py"),
            "find_CMultiplayRules_ctor_decompiles",
        )

    def test_one_predecessor_owns_every_target(self):
        references = {
            reference_path for spec in self.finder.LLM_DECOMPILE for reference_path in spec["reference_yaml_paths"]
        }
        self.assertEqual(references, {"references/server/CMultiplayRules_ctor.{platform}.yaml"})

    def test_targets_cover_engine_and_cvar_interfaces(self):
        self.assertEqual(
            [
                "IVEngineServer2_ServerCommand",
                "IVEngineServer2_IsDedicatedServer",
                "ICvar_ResetConVarsToDefaultValuesByFlag",
            ],
            list(self.finder.TARGET_FUNCTION_NAMES),
        )
        self.assertEqual(
            {
                "IVEngineServer2_ServerCommand": "IVEngineServer2",
                "IVEngineServer2_IsDedicatedServer": "IVEngineServer2",
                "ICvar_ResetConVarsToDefaultValuesByFlag": "ICvar",
            },
            dict(self.finder.FUNC_VTABLE_RELATIONS),
        )

    def test_cvar_target_is_slim_pattern_c_without_vtable_artifact(self):
        generation_contracts = dict(self.finder.GENERATE_YAML_DESIRED_FIELDS)
        self.assertEqual(
            ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
            generation_contracts["ICvar_ResetConVarsToDefaultValuesByFlag"],
        )

    async def test_inline_body_does_not_walk_helpers(self):
        with patch.object(self.finder, "preprocess_common_skill", AsyncMock(return_value=True)) as preprocess:
            self.assertTrue(await self.finder.preprocess_skill("session", "finder", [], {}, "/tmp", "linux", 0))
        self.assertEqual(preprocess.await_count, 1)
        self.assertNotIn("llm_target_details_loader", preprocess.await_args.kwargs)

    async def test_missing_inline_dispatch_uses_helper_loader(self):
        with patch.object(self.finder, "preprocess_common_skill", AsyncMock(side_effect=[False, True])) as preprocess:
            self.assertTrue(await self.finder.preprocess_skill("session", "finder", [], {}, "/tmp", "linux", 0))
        self.assertEqual(preprocess.await_count, 2)
        self.assertIs(preprocess.await_args.kwargs["llm_target_details_loader"], self.finder.load_helper_details)


class TestFindCCvarResetConVarsToDefaultValuesByFlag(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.finder = _load_module(
            Path("ida_preprocessor_scripts/find-CCvar_ResetConVarsToDefaultValuesByFlag.py"),
            "find_CCvar_ResetConVarsToDefaultValuesByFlag",
        )

    async def test_inherits_slot_from_server_interface_yaml(self) -> None:
        preprocess_common_skill = AsyncMock(return_value=True)
        with patch.object(self.finder, "preprocess_common_skill", preprocess_common_skill):
            result = await self.finder.preprocess_skill(
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
        preprocess_common_skill.assert_awaited_once_with(
            session="session",
            expected_outputs=["out.yaml"],
            old_yaml_map={"k": "v"},
            new_binary_dir="bin_dir",
            platform="windows",
            image_base=0x180000000,
            inherit_vfuncs=[
                (
                    "CCvar_ResetConVarsToDefaultValuesByFlag",
                    "CCvar",
                    "../server/ICvar_ResetConVarsToDefaultValuesByFlag",
                    True,
                )
            ],
            generate_yaml_desired_fields=[
                (
                    "CCvar_ResetConVarsToDefaultValuesByFlag",
                    [
                        "func_name",
                        "func_va",
                        "func_rva",
                        "func_size",
                        "func_sig",
                        "vtable_name",
                        "vfunc_offset",
                        "vfunc_index",
                    ],
                )
            ],
            debug=True,
        )


class TestPostEventLocalHelperChain(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from ida_preprocessor_scripts import _llm_helper_chain_common

        self.chain = _llm_helper_chain_common

    async def test_inline_success_does_not_walk_unrelated_helpers(self):
        with patch.object(self.chain, "preprocess_common_skill", AsyncMock(return_value=True)) as preprocess:
            self.assertTrue(await self.chain.preprocess_call_chain(session="session"))
        self.assertEqual(preprocess.await_count, 1)
        self.assertNotIn("llm_target_details_loader", preprocess.await_args.kwargs)

    async def test_deinlined_fallback_uses_helper_loader(self):
        with patch.object(self.chain, "preprocess_common_skill", AsyncMock(side_effect=[False, True])) as preprocess:
            self.assertTrue(await self.chain.preprocess_call_chain(session="session"))
        self.assertIs(preprocess.await_args.kwargs["llm_target_details_loader"], self.chain.load_helper_details)

    async def test_helper_instructions_are_exported_for_validation(self):
        root = {"func_va": "0x1000", "disasm_code": "0x1000 jmp sub_2000"}
        helper = {"func_va": "0x2000", "disasm_code": "0x2000 call qword ptr [rax+58h]"}
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        with (
            patch.object(self.chain, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])),
            patch.object(
                self.chain, "parse_mcp_result", return_value={"result": '{"addresses":["0x2000"],"overflow":false}'}
            ),
            patch.object(self.chain, "_export_function_detail_via_mcp", AsyncMock(return_value=helper)),
        ):
            self.assertEqual(await self.chain.load_helper_details(session, ["FireEvent"]), [root, helper])

    async def test_overflow_or_missing_helper_export_fails_closed(self):
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        for overflow in (True, False):
            with (
                self.subTest(overflow=overflow),
                patch.object(
                    self.chain,
                    "_load_llm_decompile_target_details_via_mcp",
                    AsyncMock(return_value=[{"func_va": "0x1000"}]),
                ),
                patch.object(
                    self.chain,
                    "parse_mcp_result",
                    return_value={"result": '{"addresses":["0x2000"],"overflow":' + str(overflow).lower() + "}"},
                ),
                patch.object(self.chain, "_export_function_detail_via_mcp", AsyncMock(return_value=None)),
            ):
                self.assertEqual(await self.chain.load_helper_details(session, ["FireEvent"]), [])

    def test_multiple_calls_to_same_slot_are_allowed_but_different_slots_are_rejected(self):
        finder = _load_module(
            Path("ida_preprocessor_scripts/find-IGameEventSystem_PostEventAbstract_Local.py"), "find_PostEventLocal"
        )
        entry = {"func_name": "IGameEventSystem_PostEventAbstract_Local", "vfunc_offset": "0x70"}
        self.assertEqual(finder.validate_dispatch({"found_vcall": [entry, entry]}), [])
        self.assertTrue(finder.validate_dispatch({"found_vcall": [entry, {**entry, "vfunc_offset": "0x78"}]}))


class TestFreeEventHelperChain(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from ida_preprocessor_scripts import _llm_helper_chain_common

        self.chain = _llm_helper_chain_common

    async def test_inline_success_does_not_walk_unrelated_helpers(self):
        with patch.object(self.chain, "preprocess_common_skill", AsyncMock(return_value=True)) as preprocess:
            self.assertTrue(await self.chain.preprocess_call_chain(session="session"))
        self.assertEqual(preprocess.await_count, 1)
        self.assertNotIn("llm_target_details_loader", preprocess.await_args.kwargs)

    async def test_deinlined_fallback_uses_helper_loader(self):
        with patch.object(self.chain, "preprocess_common_skill", AsyncMock(side_effect=[False, True])) as preprocess:
            self.assertTrue(await self.chain.preprocess_call_chain(session="session"))
        self.assertIs(preprocess.await_args.kwargs["llm_target_details_loader"], self.chain.load_helper_details)

    async def test_helper_instructions_are_exported_for_validation(self):
        root = {"func_va": "0x1000", "disasm_code": "0x1000 jmp sub_2000"}
        helper = {"func_va": "0x2000", "disasm_code": "0x2000 call qword ptr [rax+58h]"}
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        with (
            patch.object(self.chain, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])),
            patch.object(
                self.chain, "parse_mcp_result", return_value={"result": '{"addresses":["0x2000"],"overflow":false}'}
            ),
            patch.object(self.chain, "_export_function_detail_via_mcp", AsyncMock(return_value=helper)),
        ):
            self.assertEqual(await self.chain.load_helper_details(session, ["FireEvent"]), [root, helper])

    async def test_overflow_or_missing_helper_export_fails_closed(self):
        session = type("Session", (), {"call_tool": AsyncMock(return_value={})})()
        for overflow in (True, False):
            with (
                self.subTest(overflow=overflow),
                patch.object(
                    self.chain,
                    "_load_llm_decompile_target_details_via_mcp",
                    AsyncMock(return_value=[{"func_va": "0x1000"}]),
                ),
                patch.object(
                    self.chain,
                    "parse_mcp_result",
                    return_value={"result": '{"addresses":["0x2000"],"overflow":' + str(overflow).lower() + "}"},
                ),
                patch.object(self.chain, "_export_function_detail_via_mcp", AsyncMock(return_value=None)),
            ):
                self.assertEqual(await self.chain.load_helper_details(session, ["FireEvent"]), [])

    def test_multiple_calls_to_same_slot_are_allowed_but_different_slots_are_rejected(self):
        finder = _load_module(Path("ida_preprocessor_scripts/find-IGameEventManager2_FreeEvent.py"), "find_FreeEvent")
        entry = {"func_name": "IGameEventManager2_FreeEvent", "vfunc_offset": "0x58"}
        self.assertEqual(finder.validate_dispatch({"found_vcall": [entry, entry]}), [])
        self.assertTrue(finder.validate_dispatch({"found_vcall": [entry, {**entry, "vfunc_offset": "0x60"}]}))


if __name__ == "__main__":
    unittest.main()

import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from tests.ida_preprocessor_test_support import load_module


class TestRegisterConCommandContracts(unittest.IsolatedAsyncioTestCase):
    async def test_wrappers_forward_literal_command_contracts(self) -> None:
        cases = [
            {
                "name": "bot_add",
                "script_path": Path("ida_preprocessor_scripts/find-BotAdd_CommandHandler.py"),
                "module_name": "find_BotAdd_CommandHandler",
                "platform": "linux",
                "image_base": 0x400000,
                "target_name": "BotAdd_CommandHandler",
                "command_name": "bot_add",
                "help_string": ("bot_add <t|ct> <type> <difficulty> <name> - Adds a bot matching the given criteria."),
            },
            {
                "name": "sc_dumpworld",
                "script_path": Path("ida_preprocessor_scripts/find-SC_DumpWorld_CommandHandler.py"),
                "module_name": "find_SC_DumpWorld_CommandHandler",
                "platform": "windows",
                "image_base": 0x180000000,
                "target_name": "SC_DumpWorld_CommandHandler",
                "command_name": "sc_dumpworld",
                "help_string": "Dump a list of the objects in a sceneworld (Usage: sc_dumpworld <world_index>)",
            },
        ]

        for case in cases:
            with self.subTest(case=case["name"]):
                module = load_module(case["script_path"], case["module_name"])
                mock_helper = AsyncMock(return_value=True)

                with patch.object(module, "preprocess_registerconcommand_skill", mock_helper):
                    result = await module.preprocess_skill(
                        session="session",
                        skill_name="skill",
                        expected_outputs=["out.yaml"],
                        old_yaml_map={"k": "v"},
                        new_binary_dir="bin_dir",
                        platform=case["platform"],
                        image_base=case["image_base"],
                        debug=True,
                    )

                self.assertTrue(result)
                target_name = case["target_name"]
                mock_helper.assert_awaited_once_with(
                    session="session",
                    expected_outputs=["out.yaml"],
                    new_binary_dir="bin_dir",
                    platform=case["platform"],
                    image_base=case["image_base"],
                    target_name=target_name,
                    generate_yaml_desired_fields=[
                        (
                            target_name,
                            ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
                        )
                    ],
                    command_name=case["command_name"],
                    help_string=case["help_string"],
                    rename_to=target_name,
                    search_window_before_call=96,
                    search_window_after_xref=96,
                    debug=True,
                )


class TestFindSCDumpWorldCommandHandlerDecompiles(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_llm_targets(self) -> None:
        module = load_module(
            Path("ida_preprocessor_scripts/find-SC_DumpWorld_CommandHandler-decompiles.py"),
            "find_SC_DumpWorld_CommandHandler_decompiles",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_func_names = [
            "ISceneSystem_GetWorldsInfo",
            "ISceneWorld_GetObjectsInfo",
            "ISceneWorld_GetWorldName",
            "ISceneSystem_GetObjectBounds",
            "ISceneSystem_GetObjectClassName",
        ]
        expected_struct_member_names = [
            "CSceneObject_pDesc",
            "CSceneObject_nFlags",
            "CSceneObject_fOriginX",
            "CSceneObject_fOriginY",
            "CSceneObject_fOriginZ",
            "CSceneObject_nClassIndex",
        ]
        expected_func_vtable_relations = [
            ("ISceneSystem_GetWorldsInfo", "ISceneSystem"),
            ("ISceneWorld_GetObjectsInfo", "ISceneWorld"),
            ("ISceneWorld_GetWorldName", "ISceneWorld"),
            ("ISceneSystem_GetObjectBounds", "ISceneSystem"),
            ("ISceneSystem_GetObjectClassName", "ISceneSystem"),
        ]
        expected_llm_decompile_specs = [
            {
                "symbol_name": symbol_name,
                "prompt_path": "prompt/call_llm_decompile.md",
                "reference_yaml_paths": [
                    "references/scenesystem/SC_DumpWorld_CommandHandler.{platform}.yaml",
                ],
                "expected_result_sections": [section],
                "dependency_policy": {
                    "SC_DumpWorld_CommandHandler.{platform}.yaml": "required",
                },
            }
            for symbol_name, section in [
                *[(name, "found_vcall") for name in expected_func_names],
                *[(name, "found_struct_offset") for name in expected_struct_member_names],
            ]
        ]
        expected_generate_yaml_desired_fields = [
            *[
                (
                    name,
                    ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
                )
                for name in expected_func_names
            ],
            *[
                (
                    name,
                    ["struct_name", "member_name", "offset", "size", "offset_sig", "offset_sig_disp"],
                )
                for name in expected_struct_member_names
            ],
        ]
        llm_config = {
            "model": "gpt-4.1-mini",
            "api_key": "test-api-key",
            "base_url": "https://example.invalid/v1",
        }

        with patch.object(module, "preprocess_common_skill", mock_preprocess_common_skill):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                llm_config=llm_config,
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
            struct_member_names=expected_struct_member_names,
            func_vtable_relations=expected_func_vtable_relations,
            llm_decompile_specs=expected_llm_decompile_specs,
            llm_config=llm_config,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            debug=True,
        )


class TestDefineInputFuncContracts(unittest.IsolatedAsyncioTestCase):
    async def test_wrappers_forward_literal_input_contracts(self) -> None:
        cases = [
            (
                "show_hud_hint",
                Path("ida_preprocessor_scripts/find-ShowHudHint.py"),
                "find_ShowHudHint",
                "ShowHudHint",
                "ShowHudHint",
                0x10,
            ),
            (
                "api_test_activator",
                Path("ida_preprocessor_scripts/find-CBaseFilter_API_TestActivator.py"),
                "find_CBaseFilter_API_TestActivator",
                "CBaseFilter_API_TestActivator",
                "CBaseFilter_API::TestActivator",
                0x48,
            ),
            (
                "api_trigger_for_all_players",
                Path("ida_preprocessor_scripts/find-CGamePlayerEquip_API_TriggerForAllPlayers.py"),
                "find_CGamePlayerEquip_API_TriggerForAllPlayers",
                "CGamePlayerEquip_API_TriggerForAllPlayers",
                "CGamePlayerEquip_API::TriggerForAllPlayers",
                0x48,
            ),
            (
                "api_trigger_for_activated_player",
                Path("ida_preprocessor_scripts/find-CGamePlayerEquip_API_TriggerForActivatedPlayer.py"),
                "find_CGamePlayerEquip_API_TriggerForActivatedPlayer",
                "CGamePlayerEquip_API_TriggerForActivatedPlayer",
                "CGamePlayerEquip_API::TriggerForActivatedPlayer",
                0x48,
            ),
        ]

        for case_name, script_path, module_name, target_name, input_name, handler_ptr_offset in cases:
            with self.subTest(case=case_name):
                module = load_module(script_path, module_name)
                mock_helper = AsyncMock(return_value=True)

                with patch.object(module, "preprocess_define_inputfunc_skill", mock_helper):
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
                mock_helper.assert_awaited_once_with(
                    session="session",
                    expected_outputs=["out.yaml"],
                    platform="windows",
                    image_base=0x180000000,
                    target_name=target_name,
                    input_name=input_name,
                    generate_yaml_desired_fields=[
                        (
                            target_name,
                            ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
                        )
                    ],
                    handler_ptr_offset=handler_ptr_offset,
                    allowed_segment_names=(".data",),
                    rename_to=target_name,
                    debug=True,
                )


class TestIndirectVcallWrapperContracts(unittest.IsolatedAsyncioTestCase):
    async def test_wrappers_forward_literal_vcall_contracts(self) -> None:
        cases = [
            (
                "handle_input_event",
                Path("ida_preprocessor_scripts/find-ILoopMode_HandleInputEvent.py"),
                "find_ILoopMode_HandleInputEvent",
                "windows",
                "CLoopTypeClientServerService_HandleInputEvent",
                "ILoopMode_HandleInputEvent",
                "ILoopMode",
                True,
            ),
            (
                "pre_world_update",
                Path("ida_preprocessor_scripts/find-ISource2Server_PreWorldUpdate.py"),
                "find_ISource2Server_PreWorldUpdate",
                "linux",
                "CNetworkGameServer_PreWorldUpdate",
                "ISource2Server_PreWorldUpdate",
                "ISource2Server",
                True,
            ),
            (
                "post_data_update",
                Path("ida_preprocessor_scripts/find-CEntityInstance_PostDataUpdate.py"),
                "find_CEntityInstance_PostDataUpdate",
                "linux",
                "CEntityInstance_PostDataUpdateDelta",
                "CEntityInstance_PostDataUpdate",
                "CEntityInstance",
                True,
            ),
            (
                "add_change_accessor_path",
                Path("ida_preprocessor_scripts/find-CEntityInstance_AddChangeAccessorPath.py"),
                "find_CEntityInstance_AddChangeAccessorPath",
                "linux",
                "EntityInstanceAddChangeAccessorPath",
                "CEntityInstance_AddChangeAccessorPath",
                "CEntityInstance",
                True,
            ),
            (
                "server_end_simulate",
                Path("ida_preprocessor_scripts/find-INetworkGameServer_ServerEndSimulate.py"),
                "find_INetworkGameServer_ServerEndSimulate",
                "windows",
                "CNetworkServerService_OnServerEndSimulate",
                "INetworkGameServer_ServerEndSimulate",
                "INetworkGameServer",
                None,
            ),
        ]

        for case in cases:
            case_name, script_path, module_name, platform, source_name, target_name, vtable_name, resolve = case
            with self.subTest(case=case_name):
                module = load_module(script_path, module_name)
                mock_helper = AsyncMock(return_value=True)

                with patch.object(module, "preprocess_indirect_vcall_target_skill", mock_helper):
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
                expected_kwargs = {
                    "session": "session",
                    "expected_outputs": ["out.yaml"],
                    "new_binary_dir": "bin_dir",
                    "platform": platform,
                    "source_yaml_stem": source_name,
                    "target_name": target_name,
                    "vtable_name": vtable_name,
                    "generate_yaml_desired_fields": [
                        (
                            target_name,
                            ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"],
                        )
                    ],
                    "debug": True,
                }
                if resolve is not None:
                    expected_kwargs["resolve_load_then_branch"] = resolve
                self.assertEqual(expected_kwargs, mock_helper.await_args.kwargs)


if __name__ == "__main__":
    unittest.main()

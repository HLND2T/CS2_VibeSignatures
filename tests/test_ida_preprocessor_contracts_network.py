import re
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from tests.ida_preprocessor_test_support import load_module as _load_module


FLATTENED_SERIALIZERS_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/find-CFlattenedSerializers_CreateFieldChangedEventQueue.py"
)
SET_IS_FOR_SERVER_SCRIPT_PATH = Path("ida_preprocessor_scripts/find-CNetworkMessages_SetIsForServer.py")
I_SET_IS_FOR_SERVER_SCRIPT_PATH = Path("ida_preprocessor_scripts/find-INetworkMessages_SetIsForServer.py")
NETWORK_GROUP_STATS_SCRIPT_PATH = Path("ida_preprocessor_scripts/find-CNetworkSystem_SendNetworkStats-decompiles.py")
FIND_NETWORK_GROUP_SCRIPT_PATH = Path("ida_preprocessor_scripts/find-CNetworkMessages_FindNetworkGroup.py")
I_GET_LOGGING_CHANNEL_WINDOWS_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/find-INetworkMessages_GetLoggingChannel-windows.py"
)
I_GET_LOGGING_CHANNEL_LINUX_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/find-INetworkMessages_GetLoggingChannel-linux.py"
)
CNETWORK_SERVER_SERVICE_INIT_SCRIPT_PATH = Path("ida_preprocessor_scripts/find-CNetworkServerService_Init.py")
CLIENT_PRINTF_DECOMPILES_SCRIPT_PATH = Path("ida_preprocessor_scripts/find-CEngineServer_ClientPrintf-decompiles.py")


class TestClientListLlmContract(unittest.TestCase):
    def test_client_list_requires_dword_cmp_instruction(self) -> None:
        module = _load_module(
            CLIENT_PRINTF_DECOMPILES_SCRIPT_PATH,
            "find_CEngineServer_ClientPrintf_decompiles",
        )
        spec = next(item for item in module.LLM_DECOMPILE if item["symbol_name"] == "CNetworkGameServer_ClientList")

        self.assertEqual(["found_struct_offset"], spec["expected_result_sections"])
        self.assertEqual(4, spec["expected_size"])
        self.assertEqual(2, len(spec["instruction_rules"]))
        self.assertEqual(
            ["cmp reg, [base+offset]", "cmp [base+offset], reg"],
            [rule["text"] for rule in spec["instruction_rules"]],
        )
        self.assertTrue(any(re.fullmatch(rule["regex"], "cmp ebx, [r12+248h]") for rule in spec["instruction_rules"]))
        self.assertTrue(any(re.fullmatch(rule["regex"], "cmp [r12+248h], ebx") for rule in spec["instruction_rules"]))
        self.assertFalse(any(re.fullmatch(rule["regex"], "mov rax, [r12+250h]") for rule in spec["instruction_rules"]))


class TestInheritVfuncWrapperContracts(unittest.IsolatedAsyncioTestCase):
    async def test_wrappers_forward_literal_inherit_contracts(self) -> None:
        cases = [
            (
                "flattened_serializers",
                FLATTENED_SERIALIZERS_SCRIPT_PATH,
                "find_CFlattenedSerializers_CreateFieldChangedEventQueue",
                "windows",
                "CFlattenedSerializers_CreateFieldChangedEventQueue",
                "CFlattenedSerializers",
                "../server/IFlattenedSerializers_CreateFieldChangedEventQueue",
                True,
                True,
            ),
            (
                "set_is_for_server",
                SET_IS_FOR_SERVER_SCRIPT_PATH,
                "find_CNetworkMessages_SetIsForServer_impl",
                "windows",
                "CNetworkMessages_SetIsForServer",
                "CNetworkMessages",
                "../engine/INetworkMessages_SetIsForServer",
                False,
                False,
            ),
            (
                "set_network_serialization_context",
                Path("ida_preprocessor_scripts/find-CNetworkMessages_SetNetworkSerializationContextData.py"),
                "find_CNetworkMessages_SetNetworkSerializationContextData",
                "linux",
                "CNetworkMessages_SetNetworkSerializationContextData",
                "CNetworkMessages",
                "../server/INetworkMessages_SetNetworkSerializationContextData",
                True,
                True,
            ),
        ]

        for case in cases:
            (
                case_name,
                script_path,
                module_name,
                platform,
                target_name,
                vtable_name,
                source_path,
                include_sig,
                generate_func_sig,
            ) = case
            with self.subTest(case=case_name):
                module = _load_module(script_path, module_name)
                mock_helper = AsyncMock(return_value=True)
                fields = ["func_name", "func_va", "func_rva", "func_size"]
                if include_sig:
                    fields.append("func_sig")
                fields.extend(["vtable_name", "vfunc_offset", "vfunc_index"])

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
                    inherit_vfuncs=[(target_name, vtable_name, source_path, generate_func_sig)],
                    generate_yaml_desired_fields=[(target_name, fields)],
                    debug=True,
                )


class TestLoggingChannelWrapperContracts(unittest.IsolatedAsyncioTestCase):
    async def test_platform_wrappers_forward_literal_llm_contracts(self) -> None:
        cases = [
            (
                "windows",
                I_GET_LOGGING_CHANNEL_WINDOWS_SCRIPT_PATH,
                "find_INetworkMessages_GetLoggingChannel_windows",
                "CNetworkUtlVectorEmbedded_TryLateResolve_m_vecRenderAttributes",
            ),
            (
                "linux",
                I_GET_LOGGING_CHANNEL_LINUX_SCRIPT_PATH,
                "find_INetworkMessages_GetLoggingChannel_linux",
                "CNetworkUtlVectorEmbedded_NetworkStateChanged_m_vecRenderAttributes",
            ),
        ]
        llm_config = {"model": "gpt-4.1-mini", "api_key": "test-api-key"}

        for platform, script_path, module_name, reference_name in cases:
            with self.subTest(platform=platform):
                module = _load_module(script_path, module_name)
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
                        llm_config=llm_config,
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
                    func_names=["INetworkMessages_GetLoggingChannel"],
                    func_vtable_relations=[("INetworkMessages_GetLoggingChannel", "INetworkMessages")],
                    llm_decompile_specs=[
                        {
                            "symbol_name": "INetworkMessages_GetLoggingChannel",
                            "prompt_path": "prompt/call_llm_decompile.md",
                            "reference_yaml_paths": [f"references/server/{reference_name}.{{platform}}.yaml"],
                            "expected_result_sections": ["found_vcall"],
                            "dependency_policy": {f"{reference_name}.{{platform}}.yaml": "required"},
                        }
                    ],
                    llm_config=llm_config,
                    generate_yaml_desired_fields=[
                        (
                            "INetworkMessages_GetLoggingChannel",
                            [
                                "func_name",
                                "vfunc_sig",
                                "vfunc_sig_max_match:10",
                                "vfunc_offset",
                                "vfunc_index",
                                "vtable_name",
                            ],
                        )
                    ],
                    debug=True,
                )


class TestFindINetworkMessagesSetIsForServer(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_llm_and_vtable_wiring(self) -> None:
        module = _load_module(
            I_SET_IS_FOR_SERVER_SCRIPT_PATH,
            "find_INetworkMessages_SetIsForServer",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_llm_decompile_specs = [
            {
                "symbol_name": "INetworkMessages_SetIsForServer",
                "prompt_path": "prompt/call_llm_decompile.md",
                "reference_yaml_paths": [
                    "references/engine/CNetworkServerService_Init.{platform}.yaml",
                ],
                "expected_result_sections": ["found_vcall"],
                "dependency_policy": {
                    "CNetworkServerService_Init.{platform}.yaml": "required",
                },
            },
        ]
        expected_func_vtable_relations = [("INetworkMessages_SetIsForServer", "INetworkMessages")]
        expected_generate_yaml_desired_fields = [
            (
                "INetworkMessages_SetIsForServer",
                [
                    "func_name",
                    "vfunc_sig",
                    "vfunc_offset",
                    "vfunc_index",
                    "vtable_name",
                ],
            )
        ]
        llm_config = {
            "model": "gpt-4.1-mini",
            "api_key": "test-api-key",
            "base_url": "https://example.invalid/v1",
        }

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
            func_names=["INetworkMessages_SetIsForServer"],
            func_vtable_relations=expected_func_vtable_relations,
            llm_decompile_specs=expected_llm_decompile_specs,
            llm_config=llm_config,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            debug=True,
        )


class TestFindCNetworkMessagesGetNetworkGroupStats(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_llm_and_vtable_wiring(self) -> None:
        module = _load_module(
            NETWORK_GROUP_STATS_SCRIPT_PATH,
            "find_INetworkMessages_GetNetworkGroupStats",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_llm_decompile_specs = [
            {
                "symbol_name": "INetworkMessages_GetNetworkGroupCount",
                "prompt_path": "prompt/call_llm_decompile.md",
                "reference_yaml_paths": [
                    "references/networksystem/CNetworkSystem_SendNetworkStats.{platform}.yaml",
                ],
                "expected_result_sections": ["found_vcall"],
                "dependency_policy": {
                    "CNetworkSystem_SendNetworkStats.{platform}.yaml": "required",
                },
            },
            {
                "symbol_name": "INetworkMessages_GetNetworkGroupName",
                "prompt_path": "prompt/call_llm_decompile.md",
                "reference_yaml_paths": [
                    "references/networksystem/CNetworkSystem_SendNetworkStats.{platform}.yaml",
                ],
                "expected_result_sections": ["found_vcall"],
                "dependency_policy": {
                    "CNetworkSystem_SendNetworkStats.{platform}.yaml": "required",
                },
            },
            {
                "symbol_name": "INetworkMessages_GetNetworkGroupColor",
                "prompt_path": "prompt/call_llm_decompile.md",
                "reference_yaml_paths": [
                    "references/networksystem/CNetworkSystem_SendNetworkStats.{platform}.yaml",
                ],
                "expected_result_sections": ["found_vcall"],
                "dependency_policy": {
                    "CNetworkSystem_SendNetworkStats.{platform}.yaml": "required",
                },
            },
        ]
        expected_func_vtable_relations = [
            ("INetworkMessages_GetNetworkGroupCount", "INetworkMessages"),
            ("INetworkMessages_GetNetworkGroupName", "INetworkMessages"),
            ("INetworkMessages_GetNetworkGroupColor", "INetworkMessages"),
        ]
        expected_generate_yaml_desired_fields = [
            (
                "INetworkMessages_GetNetworkGroupCount",
                [
                    "func_name",
                    "vfunc_sig",
                    "vfunc_offset",
                    "vfunc_index",
                    "vtable_name",
                ],
            ),
            (
                "INetworkMessages_GetNetworkGroupName",
                [
                    "func_name",
                    "vfunc_sig",
                    "vfunc_offset",
                    "vfunc_index",
                    "vtable_name",
                ],
            ),
            (
                "INetworkMessages_GetNetworkGroupColor",
                [
                    "func_name",
                    "vfunc_sig",
                    "vfunc_offset",
                    "vfunc_index",
                    "vtable_name",
                ],
            ),
        ]
        llm_config = {
            "model": "gpt-4.1-mini",
            "api_key": "test-api-key",
            "base_url": "https://example.invalid/v1",
        }

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
            func_names=[
                "INetworkMessages_GetNetworkGroupCount",
                "INetworkMessages_GetNetworkGroupName",
                "INetworkMessages_GetNetworkGroupColor",
            ],
            func_vtable_relations=expected_func_vtable_relations,
            llm_decompile_specs=expected_llm_decompile_specs,
            llm_config=llm_config,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            debug=True,
        )


class TestFindCNetworkMessagesFindNetworkGroup(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_llm_and_vtable_wiring(self) -> None:
        module = _load_module(
            FIND_NETWORK_GROUP_SCRIPT_PATH,
            "find_CNetworkMessages_FindNetworkGroup",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_inherit_vfuncs = [
            (
                "CNetworkMessages_FindNetworkGroup",
                "CNetworkMessages",
                "../engine/INetworkMessages_FindNetworkGroup",
                True,
            )
        ]
        expected_func_vtable_relations = [("CNetworkMessages_FindNetworkGroup", "CNetworkMessages")]
        expected_generate_yaml_desired_fields = [
            (
                "CNetworkMessages_FindNetworkGroup",
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
        ]
        llm_config = {
            "model": "gpt-4.1-mini",
            "api_key": "test-api-key",
            "base_url": "https://example.invalid/v1",
        }

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
            func_names=["CNetworkMessages_FindNetworkGroup"],
            func_vtable_relations=expected_func_vtable_relations,
            inherit_vfuncs=expected_inherit_vfuncs,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            llm_config=llm_config,
            debug=True,
        )


class TestFindINetworkMessagesFindNetworkGroup(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_llm_and_vtable_wiring(self) -> None:
        module = _load_module(
            "ida_preprocessor_scripts/find-INetworkMessages_FindNetworkGroup.py",
            "find_INetworkMessages_FindNetworkGroup",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_llm_decompile_specs = [
            {
                "symbol_name": "INetworkMessages_FindNetworkGroup",
                "prompt_path": "prompt/call_llm_decompile.md",
                "reference_yaml_paths": [
                    "references/engine/CNetworkGameClient_RecordEntityBandwidth.{platform}.yaml",
                ],
                "expected_result_sections": ["found_vcall"],
                "dependency_policy": {
                    "CNetworkGameClient_RecordEntityBandwidth.{platform}.yaml": "required",
                },
            },
        ]
        expected_func_vtable_relations = [("INetworkMessages_FindNetworkGroup", "INetworkMessages")]
        expected_generate_yaml_desired_fields = [
            (
                "INetworkMessages_FindNetworkGroup",
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
        llm_config = {
            "model": "gpt-4.1-mini",
            "api_key": "test-api-key",
            "base_url": "https://example.invalid/v1",
        }

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
            func_names=["INetworkMessages_FindNetworkGroup"],
            func_vtable_relations=expected_func_vtable_relations,
            llm_decompile_specs=expected_llm_decompile_specs,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            llm_config=llm_config,
            debug=True,
        )


class TestFindCNetworkServerServiceInit(unittest.IsolatedAsyncioTestCase):
    async def test_script_forwards_dict_func_xrefs(self) -> None:
        module = _load_module(
            CNETWORK_SERVER_SERVICE_INIT_SCRIPT_PATH,
            "find_CNetworkServerService_Init",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_func_xrefs = [
            {
                "func_name": "CNetworkServerService_Init",
                "xref_strings": [
                    "ServerToClient",
                    "Entities",
                    "Local Player",
                    "Other Players",
                ],
                "xref_gvs": [],
                "xref_signatures": [],
                "xref_funcs": [],
                "exclude_funcs": [],
                "exclude_strings": [],
                "exclude_gvs": [],
                "exclude_signatures": [],
            }
        ]
        expected_func_vtable_relations = [("CNetworkServerService_Init", "CNetworkServerService")]
        expected_generate_yaml_desired_fields = [
            (
                "CNetworkServerService_Init",
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
            func_names=["CNetworkServerService_Init"],
            func_xrefs=expected_func_xrefs,
            func_vtable_relations=expected_func_vtable_relations,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            debug=True,
        )


if __name__ == "__main__":
    unittest.main()

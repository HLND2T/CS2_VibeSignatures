import importlib.util
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


FLATTENED_SERIALIZERS_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CFlattenedSerializers_CreateFieldChangedEventQueue-impl.py"
)
SET_IS_FOR_SERVER_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CNetworkMessages_SetIsForServer-impl.py"
)
REALLOCATING_FACTORY_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_vtable.py"
)
REALLOCATING_FACTORY_DEALLOCATE_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Deallocate-impl.py"
)


def _load_module(script_path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        script_path,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestFindCFlattenedSerializersCreateFieldChangedEventQueueImpl(
    unittest.IsolatedAsyncioTestCase
):
    async def test_preprocess_skill_forwards_expected_inherit_vfuncs(self) -> None:
        module = _load_module(
            FLATTENED_SERIALIZERS_SCRIPT_PATH,
            "find_CFlattenedSerializers_CreateFieldChangedEventQueue_impl",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_inherit_vfuncs = [
            (
                "CFlattenedSerializers_CreateFieldChangedEventQueue",
                "CFlattenedSerializers",
                "../server/CFlattenedSerializers_CreateFieldChangedEventQueue",
                True,
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
            inherit_vfuncs=expected_inherit_vfuncs,
            debug=True,
        )


class TestFindCNetworkMessagesSetIsForServerImpl(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_expected_inherit_vfuncs(self) -> None:
        module = _load_module(
            SET_IS_FOR_SERVER_SCRIPT_PATH,
            "find_CNetworkMessages_SetIsForServer_impl",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_inherit_vfuncs = [
            (
                "CNetworkMessages_SetIsForServer",
                "CNetworkMessages",
                "../engine/CNetworkMessages_SetIsForServer",
                True,
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
            inherit_vfuncs=expected_inherit_vfuncs,
            debug=True,
        )


class TestFindCGameSystemReallocatingFactoryCSpawnGroupMgrGameSystemVtable(
    unittest.IsolatedAsyncioTestCase
):
    async def test_preprocess_skill_forwards_expected_vtable_and_aliases(self) -> None:
        module = _load_module(
            REALLOCATING_FACTORY_SCRIPT_PATH,
            "find_CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_vtable",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_vtable_class_names = [
            "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem"
        ]
        expected_mangled_class_names = {
            "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem": [
                "??_7?$CGameSystemReallocatingFactory@VCSpawnGroupMgrGameSystem@@V1@@@6B@",
                "_ZTV30CGameSystemReallocatingFactoryI24CSpawnGroupMgrGameSystemS0_E",
            ]
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
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess_common_skill.assert_awaited_once_with(
            session="session",
            expected_outputs=["out.yaml"],
            vtable_class_names=expected_vtable_class_names,
            mangled_class_names=expected_mangled_class_names,
            platform="windows",
            image_base=0x180000000,
            debug=True,
        )


class TestFindCGameSystemReallocatingFactoryCSpawnGroupMgrGameSystemDeallocateImpl(
    unittest.IsolatedAsyncioTestCase
):
    async def test_preprocess_skill_forwards_expected_inherit_vfuncs(self) -> None:
        module = _load_module(
            REALLOCATING_FACTORY_DEALLOCATE_SCRIPT_PATH,
            "find_CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Deallocate_impl",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_inherit_vfuncs = [
            (
                "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Deallocate",
                "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
                "../client/IGameSystemFactory_Deallocate",
                True,
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
            inherit_vfuncs=expected_inherit_vfuncs,
            debug=True,
        )


if __name__ == "__main__":
    unittest.main()

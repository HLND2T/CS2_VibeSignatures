import importlib.util
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CFlattenedSerializers_CreateFieldChangedEventQueue-impl.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "find_CFlattenedSerializers_CreateFieldChangedEventQueue_impl",
        SCRIPT_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestFindCFlattenedSerializersCreateFieldChangedEventQueueImpl(
    unittest.IsolatedAsyncioTestCase
):
    async def test_preprocess_skill_forwards_expected_inherit_vfuncs(self) -> None:
        module = _load_module()
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


if __name__ == "__main__":
    unittest.main()

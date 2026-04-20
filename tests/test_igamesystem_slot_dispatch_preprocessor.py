import importlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import yaml


def _import_slot_dispatch_module():
    return importlib.import_module(
        "ida_preprocessor_scripts._igamesystem_slot_dispatch_common"
    )


def _write_dispatcher_yaml(
    tmpdir: str,
    platform: str,
    payload: dict[str, object],
) -> Path:
    new_binary_dir = Path(tmpdir)
    dispatcher_yaml = (
        new_binary_dir / f"IGameSystem_LoopPostInitAllSystems.{platform}.yaml"
    )
    dispatcher_yaml.write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )
    return new_binary_dir


def _duplicate_slot_payload() -> dict[str, object]:
    return {
        "entries": [
            {
                "source_ea": "0x18050013E",
                "source_kind": "wrapper",
                "vfunc_offset": "0x28",
                "vfunc_index": 5,
            },
            {
                "source_ea": "0x18050018D",
                "source_kind": "wrapper",
                "vfunc_offset": "0x28",
                "vfunc_index": 5,
            },
        ]
    }


async def _run_preprocess(module: object, session: AsyncMock, new_binary_dir: Path) -> bool:
    return await module.preprocess_igamesystem_slot_dispatch_skill(
        session=session,
        expected_outputs=["/tmp/IGameSystem_GamePostInit.windows.yaml"],
        new_binary_dir=str(new_binary_dir),
        platform="windows",
        dispatcher_yaml_stem="IGameSystem_LoopPostInitAllSystems",
        target_specs=[
            {
                "target_name": "IGameSystem_GamePostInit",
                "vtable_name": "IGameSystem",
                "dispatch_rank": 0,
            }
        ],
        multi_order="index",
        expected_dispatch_count=1,
        debug=True,
    )


def _assert_slot_only_yaml(mock_write: object) -> None:
    mock_write.assert_called_once_with(
        "/tmp/IGameSystem_GamePostInit.windows.yaml",
        {
            "func_name": "IGameSystem_GamePostInit",
            "vtable_name": "IGameSystem",
            "vfunc_offset": "0x28",
            "vfunc_index": 5,
        },
    )


class TestPreprocessIgameSystemSlotDispatchSkill(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_deduplicates_unique_slots_and_writes_slot_only_yaml(
        self,
    ) -> None:
        module = _import_slot_dispatch_module()
        session = AsyncMock()

        with TemporaryDirectory() as tmpdir:
            new_binary_dir = _write_dispatcher_yaml(
                tmpdir,
                "windows",
                {"func_va": "0x1805000C0"},
            )

            with patch.object(
                module,
                "_call_py_eval_json",
                AsyncMock(return_value=_duplicate_slot_payload()),
            ), patch.object(module, "write_func_yaml") as mock_write:
                result = await _run_preprocess(module, session, new_binary_dir)

        self.assertTrue(result)
        _assert_slot_only_yaml(mock_write)

    async def test_preprocess_skill_rejects_dispatcher_yaml_without_func_va(self) -> None:
        module = _import_slot_dispatch_module()
        session = AsyncMock()

        with TemporaryDirectory() as tmpdir:
            new_binary_dir = Path(tmpdir)
            dispatcher_yaml = (
                new_binary_dir / "IGameSystem_LoopPostInitAllSystems.windows.yaml"
            )
            dispatcher_yaml.write_text(
                yaml.safe_dump({"func_name": "IGameSystem_LoopPostInitAllSystems"}),
                encoding="utf-8",
            )

            with patch.object(
                module,
                "_call_py_eval_json",
                AsyncMock(),
            ) as mock_py_eval, patch.object(module, "write_func_yaml") as mock_write:
                result = await module.preprocess_igamesystem_slot_dispatch_skill(
                    session=session,
                    expected_outputs=["/tmp/IGameSystem_GamePostInit.windows.yaml"],
                    new_binary_dir=str(new_binary_dir),
                    platform="windows",
                    dispatcher_yaml_stem="IGameSystem_LoopPostInitAllSystems",
                    target_specs=[
                        {
                            "target_name": "IGameSystem_GamePostInit",
                            "vtable_name": "IGameSystem",
                        }
                    ],
                    multi_order="index",
                    expected_dispatch_count=1,
                    debug=True,
                )

        self.assertFalse(result)
        mock_py_eval.assert_not_awaited()
        mock_write.assert_not_called()


class TestGamePostInitSkill(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_delegates_to_slot_dispatch_helper(self) -> None:
        module = importlib.import_module(
            "ida_preprocessor_scripts.find-IGameSystem_GamePostInit"
        )
        session = AsyncMock()

        with patch.object(
            module,
            "preprocess_igamesystem_slot_dispatch_skill",
            AsyncMock(return_value=True),
        ) as mock_helper:
            result = await module.preprocess_skill(
                session=session,
                skill_name="find-IGameSystem_GamePostInit",
                expected_outputs=["/tmp/IGameSystem_GamePostInit.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp/bin/server",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        mock_helper.assert_awaited_once_with(
            session=session,
            expected_outputs=["/tmp/IGameSystem_GamePostInit.windows.yaml"],
            new_binary_dir="/tmp/bin/server",
            platform="windows",
            dispatcher_yaml_stem="IGameSystem_LoopPostInitAllSystems",
            target_specs=[
                {
                    "target_name": "IGameSystem_GamePostInit",
                    "vtable_name": "IGameSystem",
                    "dispatch_rank": 0,
                }
            ],
            multi_order="index",
            expected_dispatch_count=1,
            debug=True,
        )


class TestGamePostInitConfig(unittest.TestCase):
    def test_config_registers_gamepostinit_skill_and_symbol(self) -> None:
        config = yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8"))
        server_modules = [
            module for module in config["modules"] if module.get("name") == "server"
        ]
        self.assertEqual(1, len(server_modules))
        server_module = server_modules[0]
        skills = [
            skill
            for skill in server_module.get("skills", [])
            if skill.get("name") == "find-IGameSystem_GamePostInit"
        ]
        symbols = [
            symbol
            for symbol in server_module.get("symbols", [])
            if symbol.get("name") == "IGameSystem_GamePostInit"
        ]
        self.assertEqual(1, len(skills))
        self.assertEqual(1, len(symbols))
        skill = skills[0]
        symbol = symbols[0]

        self.assertEqual(
            ["IGameSystem_GamePostInit.{platform}.yaml"],
            skill["expected_output"],
        )
        self.assertEqual(
            ["IGameSystem_LoopPostInitAllSystems.{platform}.yaml"],
            skill["expected_input"],
        )
        self.assertEqual("vfunc", symbol["category"])
        self.assertIn("IGameSystem::GamePostInit", symbol["alias"])

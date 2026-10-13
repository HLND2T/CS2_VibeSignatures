import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from ida_analyze_util import _build_llm_decompile_specs_map, _validate_llm_decompile_dependency_policy
from tests.ida_preprocessor_test_support import load_module


class TestCheckParmPredecessorSelection(unittest.IsolatedAsyncioTestCase):
    async def test_selects_current_helper_only_for_matching_platform(self):
        module = load_module("ida_preprocessor_scripts/find-ICommandLine_CheckParm.py", "find_checkparm_selection")
        with tempfile.TemporaryDirectory() as directory:
            artifact_dir = Path(directory) / "server"
            artifact_dir.mkdir()
            helper = artifact_dir / "CCSBotManager_StartFrame_ShouldUpdate.linux.yaml"
            helper.write_text("func_va: '0x1000'\n", encoding="utf-8")
            for platform, predecessor in (
                ("windows", "CCSBotManager_StartFrame"),
                ("linux", "CCSBotManager_StartFrame_ShouldUpdate"),
            ):
                with self.subTest(platform=platform):
                    common = AsyncMock(return_value=True)
                    with patch.object(module, "preprocess_common_skill", common):
                        self.assertTrue(
                            await module.preprocess_skill(
                                session=object(),
                                skill_name="find-ICommandLine_CheckParm",
                                expected_outputs=[f"ICommandLine_CheckParm.{platform}.yaml"],
                                old_yaml_map={},
                                new_binary_dir=str(artifact_dir),
                                platform=platform,
                                image_base=0,
                            )
                        )
                    specs = common.await_args.kwargs["llm_decompile_specs"]
                    normalized = _build_llm_decompile_specs_map(specs)
                    self.assertIsNotNone(normalized)
                    reference = Path("ida_preprocessor_scripts") / specs[0]["reference_yaml_paths"][0]
                    self.assertIn(f"func_name: {predecessor}\n", reference.read_text(encoding="utf-8"))
                    self.assertTrue(
                        _validate_llm_decompile_dependency_policy(
                            normalized,
                            {
                                "_expected_inputs": [f"CCSBotManager_StartFrame.{platform}.yaml"],
                                "_optional_inputs": [f"CCSBotManager_StartFrame_ShouldUpdate.{platform}.yaml"],
                            },
                            str(artifact_dir),
                            platform,
                        )
                    )
            helper.unlink()
            common = AsyncMock(return_value=True)
            with patch.object(module, "preprocess_common_skill", common):
                await module.preprocess_skill(object(), "finder", [], {}, str(artifact_dir), "linux", 0)
            self.assertEqual(common.await_args.kwargs["llm_decompile_specs"], module.LLM_DECOMPILE)

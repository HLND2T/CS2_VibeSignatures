import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts._init_game_server_anchor import (
    VFUNC_OFFSET,
    load_anchor,
    select_anchor,
    validate_result,
)
from tests.ida_preprocessor_test_support import load_module, py_eval_payload


class TestInitGameServerAnchor(unittest.IsolatedAsyncioTestCase):
    def test_select_anchor_requires_one_network_system_call(self) -> None:
        anchor = {"insn_va": 0x1800F81F2, "insn_disasm": "call qword ptr [rax+118h]"}
        self.assertEqual(anchor, select_anchor([anchor]))
        with self.assertRaisesRegex(ValueError, "expected one"):
            select_anchor([])

    def test_validator_rejects_an_unrelated_virtual_call(self) -> None:
        anchor = {"insn_va": 0x1800F81F2, "insn_disasm": "call qword ptr [rax+118h]"}
        expected = {
            "found_vcall": [
                {
                    "func_name": "INetworkSystem_GetFakeLag",
                    "insn_va": hex(anchor["insn_va"]),
                    "vfunc_offset": hex(VFUNC_OFFSET),
                }
            ]
        }
        self.assertEqual([], validate_result(expected, anchor))

        wrong = {
            "found_vcall": [
                {
                    "func_name": "INetworkSystem_GetFakeLag",
                    "insn_va": "0x1800f8577",
                    "vfunc_offset": "0x58",
                }
            ]
        }
        self.assertIn("g_pNetworkSystem", validate_result(wrong, anchor)[0])

    async def test_load_anchor_reads_current_artifacts_and_probes_ida(self) -> None:
        with TemporaryDirectory() as temporary:
            artifact_dir = Path(temporary)
            (artifact_dir / "CSteam3ServerS1_InitGameServer.windows.yaml").write_text(
                "func_va: '0x1800f8000'\n", encoding="utf-8"
            )
            (artifact_dir / "g_pNetworkSystem.windows.yaml").write_text("gv_va: '0x180123450'\n", encoding="utf-8")
            session = AsyncMock()
            session.call_tool.return_value = py_eval_payload(
                [{"insn_va": 0x1800F81F2, "insn_disasm": "call qword ptr [rax+118h]"}]
            )

            anchor = await load_anchor(session, artifact_dir, "windows")

        self.assertEqual(0x1800F81F2, anchor["insn_va"])
        session.call_tool.assert_awaited_once()
        request = session.call_tool.await_args.kwargs
        self.assertEqual("py_eval", request["name"])
        self.assertIn("_probe_anchor(6443466752, 6443643984)", request["arguments"]["code"])


class TestInitGameServerFinder(unittest.IsolatedAsyncioTestCase):
    def test_agent_fallback_documents_all_required_vcall_outputs(self) -> None:
        skill_path = Path(".claude/skills/find-CSteam3ServerS1_InitGameServer-decompiles/SKILL.md")

        skill = skill_path.read_text(encoding="utf-8")

        self.assertIn("name: find-CSteam3ServerS1_InitGameServer-decompiles", skill)
        self.assertIn("INetworkSystem_GetFakeLag", skill)
        self.assertIn("INetworkServerService_IsActiveInGame", skill)
        self.assertIn("func_addr=None", skill)
        self.assertIn("func_sig=None", skill)

    async def test_preprocess_requires_the_verified_get_fake_lag_anchor(self) -> None:
        module = load_module(
            Path("ida_preprocessor_scripts/find-CSteam3ServerS1_InitGameServer-decompiles.py"),
            "find_CSteam3ServerS1_InitGameServer_decompiles",
        )
        anchor = {"insn_va": 0x1800F81F2, "insn_disasm": "call qword ptr [rax+118h]"}
        helper = AsyncMock(return_value=True)
        with (
            patch.object(module, "load_anchor", AsyncMock(return_value=anchor)),
            patch.object(module, "preprocess_common_skill", helper),
        ):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                llm_config={"model": "test"},
            )

        self.assertTrue(result)
        validator = helper.await_args.kwargs["llm_result_validator"]
        self.assertEqual(
            [],
            validator(
                {
                    "found_vcall": [
                        {
                            "func_name": "INetworkSystem_GetFakeLag",
                            "insn_va": "0x1800f81f2",
                            "vfunc_offset": "0x118",
                        }
                    ]
                }
            ),
        )
        self.assertNotEqual(
            [],
            validator(
                {
                    "found_vcall": [
                        {
                            "func_name": "INetworkSystem_GetFakeLag",
                            "insn_va": "0x1800f8577",
                            "vfunc_offset": "0x58",
                        }
                    ]
                }
            ),
        )


if __name__ == "__main__":
    unittest.main()

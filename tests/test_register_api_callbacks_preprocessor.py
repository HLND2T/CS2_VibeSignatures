import importlib
import importlib.util
import json
import os
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml


def _import_common_module():
    return importlib.import_module("ida_preprocessor_scripts._register_api_callbacks")


def _import_finder_module():
    path = Path("ida_preprocessor_scripts/find-GameStateAPI_RegisterAPIs-extract-apis.py")
    spec = importlib.util.spec_from_file_location("find_gamestate_api_callbacks", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _FakeTextContent:
    def __init__(self, text: str) -> None:
        self.text = text


class _FakeCallToolResult:
    def __init__(self, payload: dict[str, object]) -> None:
        self.content = [_FakeTextContent(json.dumps(payload))]


def _py_eval_payload(payload: object) -> _FakeCallToolResult:
    return _FakeCallToolResult(
        {
            "result": json.dumps(payload),
            "stdout": "",
            "stderr": "",
        }
    )


class TestRegisterApiCallbacksPyEval(unittest.TestCase):
    def test_builder_embeds_exact_string_and_windows_slot_recovery(self) -> None:
        module = _import_common_module()
        code = module._build_register_api_callbacks_py_eval(
            platform="windows",
            source_func_va="0x180010000",
            api_names=["IsLatched", "GetPlayerPremierRankStatsObject"],
            search_window_after_xref=96,
            search_window_before_call=96,
        )

        self.assertIn("target_texts = api_names", code)
        self.assertIn("strings = idautils.Strings(default_setup=False)", code)
        self.assertIn("callback_arg", code)
        self.assertIn("('rcx', 'rdx', 'r8', 'r9')", code)
        self.assertIn("_recover_stack_slot", code)
        self.assertIn("_recover_slot_value", code)
        compile(code, "<register_api_callbacks>", "exec")

    def test_py_eval_extracts_standard_and_extended_registration_calls(self) -> None:
        module = _import_common_module()
        source_func_va = 0x1000
        api_string_1 = 0x3000
        api_string_2 = 0x3010
        help_string = 0x3020
        api_string_3 = 0x3030
        callback_1 = 0x5000
        callback_2 = 0x6000
        callback_3 = 0x6500
        register_1 = 0x7000
        build_name = 0x7100
        register_2 = 0x7200
        register_3 = 0x7300
        stack_slot = 0x30

        o_reg = 1
        o_displ = 2
        o_near = 3
        o_mem = 4
        instructions = {
            0x1000: ("lea", ("rax", "sub_5000"), (o_reg, o_near), (0, callback_1)),
            0x1004: ("mov", ("[rsp+30h]", "rax"), (o_displ, o_reg), (stack_slot, 0)),
            0x1008: ("lea", ("r8", "aHelp"), (o_reg, o_mem), (0, help_string)),
            0x100C: ("lea", ("rdx", "[rsp+30h]"), (o_reg, o_displ), (0, stack_slot)),
            0x1010: ("lea", ("rcx", "aIslatched"), (o_reg, o_mem), (0, api_string_1)),
            0x1014: ("call", ("sub_7000", ""), (o_near, 0), (register_1, 0)),
            0x1020: ("lea", ("rdx", "aPremier"), (o_reg, o_mem), (0, api_string_2)),
            0x1024: ("call", ("sub_7100", ""), (o_near, 0), (build_name, 0)),
            0x1028: ("lea", ("rax", "sub_6000"), (o_reg, o_near), (0, callback_2)),
            0x102C: ("mov", ("[rsp+30h]", "rax"), (o_displ, o_reg), (stack_slot, 0)),
            0x1030: ("lea", ("r9", "aHelp"), (o_reg, o_mem), (0, help_string)),
            0x1034: ("lea", ("r8", "[rsp+30h]"), (o_reg, o_displ), (0, stack_slot)),
            0x1038: ("lea", ("rdx", "aPremier"), (o_reg, o_mem), (0, api_string_2)),
            0x103C: ("mov", ("rcx", "rbx"), (o_reg, o_reg), (0, 0)),
            0x1040: ("call", ("sub_7200", ""), (o_near, 0), (register_2, 0)),
            0x1050: ("lea", ("rax", "sub_6500"), (o_reg, o_near), (0, callback_3)),
            0x1054: ("mov", ("[rsp+30h]", "rax"), (o_displ, o_reg), (stack_slot, 0)),
            0x1058: ("lea", ("rdx", "[rsp+30h]"), (o_reg, o_displ), (0, stack_slot)),
            0x105C: ("lea", ("rcx", "aLocalHost"), (o_reg, o_mem), (0, api_string_3)),
            0x1060: ("jmp", ("sub_7300", ""), (o_near, 0), (register_3, 0)),
        }
        heads = sorted(instructions)

        class FakeFunc:
            def __init__(self, start_ea: int, end_ea: int) -> None:
                self.start_ea = start_ea
                self.end_ea = end_ea

        class FakeXref:
            def __init__(self, frm: int) -> None:
                self.frm = frm

        class FakeString:
            def __init__(self, ea: int, text: str) -> None:
                self.ea = ea
                self.text = text

            def __str__(self) -> str:
                return self.text

        class FakeStrings:
            def __init__(self, default_setup: bool = True) -> None:
                self.default_setup = default_setup

            def __iter__(self):
                return iter(
                    [
                        FakeString(api_string_1, "IsLatched"),
                        FakeString(api_string_2, "GetPlayerPremierRankStatsObject"),
                        FakeString(api_string_3, "BIsLocalServerHost"),
                    ]
                )

        def fake_get_func(ea: int):
            if ea == source_func_va:
                return FakeFunc(source_func_va, 0x1100)
            if ea in (callback_1, callback_2, callback_3, register_1, build_name, register_2, register_3):
                return FakeFunc(ea, ea + 0x20)
            return None

        def fake_prev_head(start_ea: int, min_ea: int) -> int:
            return next((head for head in reversed(heads) if min_ea <= head < start_ea), -1)

        def fake_next_head(start_ea: int, max_ea: int) -> int:
            return next((head for head in heads if start_ea < head < max_ea), -1)

        def fake_xrefs_to(ea: int, _flags: int):
            if ea == api_string_1:
                return [FakeXref(0x1010)]
            if ea == api_string_2:
                return [FakeXref(0x1020), FakeXref(0x1038)]
            if ea == api_string_3:
                return [FakeXref(0x105C)]
            return []

        fake_idaapi = types.SimpleNamespace(
            o_reg=o_reg,
            o_displ=o_displ,
            o_imm=5,
            o_mem=o_mem,
            o_near=o_near,
            o_far=6,
            BADADDR=-1,
            get_func=fake_get_func,
        )
        fake_idc = types.SimpleNamespace(
            prev_head=fake_prev_head,
            next_head=fake_next_head,
            print_insn_mnem=lambda ea: instructions.get(ea, ("", (), (), ()))[0],
            print_operand=lambda ea, index: instructions.get(ea, ("", ("", ""), (), ()))[1][index],
            get_operand_type=lambda ea, index: instructions.get(ea, ("", (), (-1, -1), ()))[2][index],
            get_operand_value=lambda ea, index: instructions.get(ea, ("", (), (), (0, 0)))[3][index],
            is_code=lambda flags: bool(flags),
        )
        fake_idautils = types.SimpleNamespace(Strings=FakeStrings, XrefsTo=fake_xrefs_to)
        fake_ida_bytes = types.SimpleNamespace(get_full_flags=lambda ea: ea in instructions)
        fake_ida_nalt = types.SimpleNamespace(STRTYPE_C=0)
        with patch.dict(os.environ, {"CS2VIBE_STRING_MIN_LENGTH": ""}, clear=True):
            code = module._build_register_api_callbacks_py_eval(
                platform="windows",
                source_func_va=hex(source_func_va),
                api_names=["IsLatched", "GetPlayerPremierRankStatsObject", "BIsLocalServerHost"],
                search_window_after_xref=96,
                search_window_before_call=96,
            )
        namespace: dict[str, object] = {}

        with patch.dict(
            "sys.modules",
            {
                "idaapi": fake_idaapi,
                "ida_bytes": fake_ida_bytes,
                "idautils": fake_idautils,
                "ida_nalt": fake_ida_nalt,
                "idc": fake_idc,
            },
        ):
            exec(code, namespace)

        payload = json.loads(namespace["result"])
        self.assertTrue(payload["ok"], payload)
        entries = {entry["api_name"]: entry for entry in payload["entries"]}
        self.assertEqual(hex(callback_1), entries["IsLatched"]["callback_va"])
        self.assertEqual("rdx", entries["IsLatched"]["callback_arg"])
        self.assertEqual(hex(callback_2), entries["GetPlayerPremierRankStatsObject"]["callback_va"])
        self.assertEqual("r8", entries["GetPlayerPremierRankStatsObject"]["callback_arg"])
        self.assertEqual(hex(callback_3), entries["BIsLocalServerHost"]["callback_va"])
        self.assertEqual("rdx", entries["BIsLocalServerHost"]["callback_arg"])


class TestGameStateApiCallbackFinder(unittest.IsolatedAsyncioTestCase):
    async def test_finder_declares_105_unique_apis_and_delegates(self) -> None:
        module = _import_finder_module()
        api_names = [spec["api_name"] for spec in module.TARGET_SPECS]
        target_names = [spec["target_name"] for spec in module.TARGET_SPECS]

        self.assertEqual(105, len(api_names))
        self.assertEqual(105, len(set(api_names)))
        self.assertEqual("IsLatched", api_names[0])
        self.assertEqual("BIsLocalServerHost", api_names[-1])
        self.assertEqual(
            [f"GameStateAPI_{api_name}" for api_name in api_names],
            target_names,
        )
        self.assertEqual(105, len(module.GENERATE_YAML_DESIRED_FIELDS))

        with patch.object(
            module,
            "preprocess_register_api_callbacks_skill",
            AsyncMock(return_value=True),
        ) as mock_preprocess:
            result = await module.preprocess_skill(
                session=AsyncMock(),
                skill_name="find-GameStateAPI_RegisterAPIs-extract-apis",
                expected_outputs=["out"],
                old_yaml_map={},
                new_binary_dir="bin",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        kwargs = mock_preprocess.await_args.kwargs
        self.assertEqual("GameStateAPI_RegisterAPIs", kwargs["source_yaml_stem"])
        self.assertIs(module.TARGET_SPECS, kwargs["target_specs"])
        self.assertIs(module.GENERATE_YAML_DESIRED_FIELDS, kwargs["generate_yaml_desired_fields"])

    async def test_14172_config_matches_finder_inventory(self) -> None:
        module = _import_finder_module()
        config = yaml.safe_load(Path("configs/14172.yaml").read_text(encoding="utf-8"))
        client = next(item for item in config["modules"] if item["name"] == "client")
        skill = next(item for item in client["skills"] if item["name"] == "find-GameStateAPI_RegisterAPIs-extract-apis")

        self.assertEqual("windows", skill["platform"])
        self.assertEqual(
            [f"{name}.{{platform}}.yaml" for name in module.TARGET_FUNCTION_NAMES],
            skill["expected_output"],
        )
        self.assertEqual(
            ["GameStateAPI_RegisterAPIs.{platform}.yaml"],
            skill["expected_input"],
        )

        symbols = {item["name"]: item for item in client["symbols"]}
        for spec in module.TARGET_SPECS:
            symbol = symbols[spec["target_name"]]
            self.assertEqual("func", symbol["category"])
            self.assertEqual("windows", symbol["platform"])
            self.assertEqual([f"GameStateAPI::{spec['api_name']}"], symbol["alias"])


class TestPreprocessRegisterApiCallbacksSkill(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_writes_all_targets_after_all_payloads_resolve(self) -> None:
        module = _import_common_module()
        specs = [
            {"api_name": "IsLatched", "target_name": "GameStateAPI_IsLatched"},
            {"api_name": "GetPlayerSlot", "target_name": "GameStateAPI_GetPlayerSlot"},
        ]
        desired_fields = [
            (name, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
            for name in ("GameStateAPI_IsLatched", "GameStateAPI_GetPlayerSlot")
        ]
        entries = [
            {"api_name": "IsLatched", "callback_va": "0x180050000"},
            {"api_name": "GetPlayerSlot", "callback_va": "0x180060000"},
        ]

        async def fake_query(_session, func_va, debug=False):
            _ = debug
            return {"func_va": func_va, "func_size": "0x20"}

        async def fake_sig(session, func_va, image_base, **_kwargs):
            _ = (session, image_base)
            return {
                "func_sig": f"SIG {func_va}",
                "func_rva": hex(int(func_va, 0) - 0x180000000),
                "func_size": "0x20",
            }

        with (
            patch.object(module, "_read_source_func_va", return_value="0x180010000"),
            patch.object(module, "_collect_register_api_entries", AsyncMock(return_value=entries)),
            patch.object(module, "_query_func_info", AsyncMock(side_effect=fake_query)),
            patch.object(module, "preprocess_gen_func_sig_via_mcp", AsyncMock(side_effect=fake_sig)),
            patch.object(module, "write_func_yaml") as mock_write,
            patch.object(module, "_rename_func_best_effort", AsyncMock()),
        ):
            result = await module.preprocess_register_api_callbacks_skill(
                session=AsyncMock(),
                expected_outputs=[
                    "/tmp/GameStateAPI_IsLatched.windows.yaml",
                    "/tmp/GameStateAPI_GetPlayerSlot.windows.yaml",
                ],
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                source_yaml_stem="GameStateAPI_RegisterAPIs",
                target_specs=specs,
                generate_yaml_desired_fields=desired_fields,
                debug=True,
            )

        self.assertTrue(result)
        self.assertEqual(2, mock_write.call_count)
        self.assertEqual(
            {"GameStateAPI_IsLatched", "GameStateAPI_GetPlayerSlot"},
            {call.args[1]["func_name"] for call in mock_write.call_args_list},
        )

    async def test_preprocess_does_not_write_partial_outputs_when_target_is_missing(self) -> None:
        module = _import_common_module()
        with (
            patch.object(module, "_read_source_func_va", return_value="0x180010000"),
            patch.object(
                module,
                "_collect_register_api_entries",
                AsyncMock(return_value=[{"api_name": "IsLatched", "callback_va": "0x180050000"}]),
            ),
            patch.object(module, "write_func_yaml") as mock_write,
        ):
            result = await module.preprocess_register_api_callbacks_skill(
                session=AsyncMock(),
                expected_outputs=[
                    "/tmp/GameStateAPI_IsLatched.windows.yaml",
                    "/tmp/GameStateAPI_GetPlayerSlot.windows.yaml",
                ],
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                source_yaml_stem="GameStateAPI_RegisterAPIs",
                target_specs=[
                    {"api_name": "IsLatched", "target_name": "GameStateAPI_IsLatched"},
                    {"api_name": "GetPlayerSlot", "target_name": "GameStateAPI_GetPlayerSlot"},
                ],
                generate_yaml_desired_fields=[
                    ("GameStateAPI_IsLatched", ["func_name", "func_va"]),
                    ("GameStateAPI_GetPlayerSlot", ["func_name", "func_va"]),
                ],
                debug=True,
            )

        self.assertFalse(result)
        mock_write.assert_not_called()


if __name__ == "__main__":
    unittest.main()

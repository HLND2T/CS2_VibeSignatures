import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

import ida_analyze_util


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


def _write_yaml(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


class TestPreprocessIndexBasedVfuncViaMcp(unittest.IsolatedAsyncioTestCase):
    async def test_reads_sibling_module_yaml_and_derives_index_from_offset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            gamever_dir = Path(temp_dir) / "bin" / "14141"
            current_module_dir = gamever_dir / "schemasystem"
            sibling_module_dir = gamever_dir / "server"
            target_output = current_module_dir / "CDerived_CreateFieldChangedEventQueue.windows.yaml"

            _write_yaml(
                sibling_module_dir / "CFlattenedSerializers_CreateFieldChangedEventQueue.windows.yaml",
                {
                    "vtable_name": "CFlattenedSerializers",
                    "vfunc_offset": "0x118",
                },
            )
            _write_yaml(
                current_module_dir / "CDerived_vtable.windows.yaml",
                {
                    "vtable_entries": {
                        35: "0x180001180",
                    }
                },
            )

            session = AsyncMock()
            session.call_tool.return_value = _py_eval_payload(
                {
                    "func_va": "0x180001180",
                    "func_size": "0x40",
                }
            )

            result = await ida_analyze_util.preprocess_index_based_vfunc_via_mcp(
                session=session,
                target_func_name="CDerived_CreateFieldChangedEventQueue",
                target_output=str(target_output),
                old_yaml_map={},
                new_binary_dir=str(current_module_dir),
                platform="windows",
                image_base=0x180000000,
                base_vfunc_name="../server/CFlattenedSerializers_CreateFieldChangedEventQueue",
                inherit_vtable_class="CDerived",
                generate_func_sig=False,
                debug=False,
            )

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(35, result["vfunc_index"])
            self.assertEqual("0x118", result["vfunc_offset"])
            self.assertEqual("CDerived_CreateFieldChangedEventQueue", result["func_name"])
            self.assertEqual("0x1180", result["func_rva"])
            session.call_tool.assert_awaited_once()

    async def test_returns_none_for_misaligned_vfunc_offset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"

            _write_yaml(
                module_dir / "CBaseEntity_Touch.windows.yaml",
                {
                    "vtable_name": "CBaseEntity",
                    "vfunc_offset": "0x11a",
                },
            )
            _write_yaml(
                module_dir / "CDerived_vtable.windows.yaml",
                {
                    "vtable_entries": {
                        35: "0x180001180",
                    }
                },
            )

            session = AsyncMock()

            result = await ida_analyze_util.preprocess_index_based_vfunc_via_mcp(
                session=session,
                target_func_name="CDerived_Touch",
                target_output=str(module_dir / "CDerived_Touch.windows.yaml"),
                old_yaml_map={},
                new_binary_dir=str(module_dir),
                platform="windows",
                image_base=0x180000000,
                base_vfunc_name="CBaseEntity_Touch",
                inherit_vtable_class="CDerived",
                generate_func_sig=False,
                debug=False,
            )

            self.assertIsNone(result)
            session.call_tool.assert_not_awaited()

    async def test_returns_none_for_mismatched_vfunc_index_and_offset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"

            _write_yaml(
                module_dir / "CBaseEntity_Touch.windows.yaml",
                {
                    "vtable_name": "CBaseEntity",
                    "vfunc_index": 34,
                    "vfunc_offset": "0x118",
                },
            )
            _write_yaml(
                module_dir / "CDerived_vtable.windows.yaml",
                {
                    "vtable_entries": {
                        35: "0x180001180",
                    }
                },
            )

            session = AsyncMock()

            result = await ida_analyze_util.preprocess_index_based_vfunc_via_mcp(
                session=session,
                target_func_name="CDerived_Touch",
                target_output=str(module_dir / "CDerived_Touch.windows.yaml"),
                old_yaml_map={},
                new_binary_dir=str(module_dir),
                platform="windows",
                image_base=0x180000000,
                base_vfunc_name="CBaseEntity_Touch",
                inherit_vtable_class="CDerived",
                generate_func_sig=False,
                debug=False,
            )

            self.assertIsNone(result)
            session.call_tool.assert_not_awaited()

    async def test_returns_none_for_base_vfunc_path_outside_gamever_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"
            session = AsyncMock()

            result = await ida_analyze_util.preprocess_index_based_vfunc_via_mcp(
                session=session,
                target_func_name="CDerived_Touch",
                target_output=str(module_dir / "CDerived_Touch.windows.yaml"),
                old_yaml_map={},
                new_binary_dir=str(module_dir),
                platform="windows",
                image_base=0x180000000,
                base_vfunc_name="../../outside/CBaseEntity_Touch",
                inherit_vtable_class="CDerived",
                generate_func_sig=False,
                debug=False,
            )

            self.assertIsNone(result)
            session.call_tool.assert_not_awaited()


class TestVtableAliasSupport(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_common_skill_rejects_invalid_mangled_class_names(self) -> None:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/Foo_vtable.windows.yaml"],
            vtable_class_names=["Foo"],
            mangled_class_names=["bad-config"],
            platform="windows",
            image_base=0x180000000,
            generate_yaml_desired_fields=[("Foo", ["vtable_class"])],
            debug=False,
        )

        self.assertFalse(result)

    def test_build_vtable_py_eval_embeds_candidate_symbols(self) -> None:
        py_code = ida_analyze_util._build_vtable_py_eval(
            "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
            [
                "??_7?$CGameSystemReallocatingFactory@VCSpawnGroupMgrGameSystem@@V1@@@6B@",
                "_ZTV30CGameSystemReallocatingFactoryI24CSpawnGroupMgrGameSystemS0_E",
            ],
        )

        self.assertIn(
            '"CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem"',
            py_code,
        )
        self.assertIn("candidate_symbols = [", py_code)
        self.assertIn(
            "??_7?$CGameSystemReallocatingFactory@VCSpawnGroupMgrGameSystem@@V1@@@6B@",
            py_code,
        )
        self.assertIn(
            "_ZTV30CGameSystemReallocatingFactoryI24CSpawnGroupMgrGameSystemS0_E",
            py_code,
        )

    async def test_preprocess_common_skill_passes_aliases_to_vtable_lookup(self) -> None:
        alias_map = {
            "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem": [
                "??_7?$CGameSystemReallocatingFactory@VCSpawnGroupMgrGameSystem@@V1@@@6B@",
                "_ZTV30CGameSystemReallocatingFactoryI24CSpawnGroupMgrGameSystemS0_E",
            ]
        }
        fake_vtable_data = {
            "vtable_class": "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
            "vtable_symbol": "??_7?$CGameSystemReallocatingFactory@VCSpawnGroupMgrGameSystem@@V1@@@6B@",
            "vtable_va": "0x180010000",
            "vtable_rva": "0x10000",
            "vtable_size": "0x20",
            "vtable_numvfunc": 4,
            "vtable_entries": {0: "0x180020000"},
        }

        with patch.object(
            ida_analyze_util,
            "preprocess_vtable_via_mcp",
            AsyncMock(return_value=fake_vtable_data),
        ) as mock_preprocess_vtable, patch.object(
            ida_analyze_util,
            "write_vtable_yaml",
        ) as mock_write_vtable_yaml:
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=[
                    "/tmp/CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_vtable.windows.yaml"
                ],
                vtable_class_names=[
                    "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem"
                ],
                mangled_class_names=alias_map,
                platform="windows",
                image_base=0x180000000,
                generate_yaml_desired_fields=[
                    (
                        "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
                        [
                            "vtable_class",
                            "vtable_symbol",
                            "vtable_va",
                            "vtable_rva",
                            "vtable_size",
                            "vtable_numvfunc",
                            "vtable_entries",
                        ],
                    )
                ],
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess_vtable.assert_awaited_once_with(
            session="session",
            class_name="CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
            image_base=0x180000000,
            platform="windows",
            debug=True,
            symbol_aliases=alias_map[
                "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem"
            ],
        )
        mock_write_vtable_yaml.assert_called_once()

    async def test_preprocess_func_sig_uses_aliases_when_generating_missing_vtable_yaml(self) -> None:
        alias_map = {
            "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem": [
                "??_7?$CGameSystemReallocatingFactory@VCSpawnGroupMgrGameSystem@@V1@@@6B@",
                "_ZTV30CGameSystemReallocatingFactoryI24CSpawnGroupMgrGameSystemS0_E",
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"
            old_dir = Path(temp_dir) / "old"
            new_path = module_dir / "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Think.windows.yaml"
            old_path = old_dir / "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Think.windows.yaml"

            old_dir.mkdir(parents=True, exist_ok=True)
            module_dir.mkdir(parents=True, exist_ok=True)
            old_path.write_text(
                yaml.safe_dump(
                    {
                        "vtable_name": "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
                        "vfunc_sig": "AA BB CC DD",
                        "vfunc_index": 1,
                        "func_va": "0x180001111",
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )

            session = AsyncMock()
            session.call_tool.side_effect = [
                _FakeCallToolResult([{"matches": ["0x180003000"], "n": 1}]),
                _py_eval_payload(
                    {
                        "func_va": "0x180004000",
                        "func_size": "0x40",
                    }
                ),
            ]

            with patch.object(
                ida_analyze_util,
                "preprocess_vtable_via_mcp",
                AsyncMock(
                    return_value={
                        "vtable_class": "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
                        "vtable_symbol": "_ZTV30CGameSystemReallocatingFactoryI24CSpawnGroupMgrGameSystemS0_E + 0x10",
                        "vtable_va": "0x180001000",
                        "vtable_rva": "0x1000",
                        "vtable_size": "0x10",
                        "vtable_numvfunc": 2,
                        "vtable_entries": {
                            0: "0x180002000",
                            1: "0x180004000",
                        },
                    }
                ),
            ) as mock_preprocess_vtable:
                result = await ida_analyze_util.preprocess_func_sig_via_mcp(
                    session=session,
                    new_path=str(new_path),
                    old_path=str(old_path),
                    image_base=0x180000000,
                    new_binary_dir=str(module_dir),
                    platform="windows",
                    func_name="CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Think",
                    debug=True,
                    mangled_class_names=alias_map,
                )

        self.assertIsNotNone(result)
        mock_preprocess_vtable.assert_awaited_once_with(
            session,
            "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
            0x180000000,
            "windows",
            True,
            alias_map[
                "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem"
            ],
        )

    async def test_func_vtable_relations_use_aliases_for_index_enrichment(self) -> None:
        alias_map = {
            "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem": [
                "??_7?$CGameSystemReallocatingFactory@VCSpawnGroupMgrGameSystem@@V1@@@6B@",
                "_ZTV30CGameSystemReallocatingFactoryI24CSpawnGroupMgrGameSystemS0_E",
            ]
        }

        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Think",
                    "func_va": "0x180004000",
                    "func_rva": "0x4000",
                    "func_size": "0x40",
                    "func_sig": "AA BB",
                }
            ),
        ) as mock_preprocess_func, patch.object(
            ida_analyze_util,
            "preprocess_vtable_via_mcp",
            AsyncMock(
                return_value={
                    "vtable_class": "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
                    "vtable_symbol": "??_7?$CGameSystemReallocatingFactory@VCSpawnGroupMgrGameSystem@@V1@@@6B@",
                    "vtable_va": "0x180001000",
                    "vtable_rva": "0x1000",
                    "vtable_size": "0x20",
                    "vtable_numvfunc": 4,
                    "vtable_entries": {
                        0: "0x180003000",
                        1: "0x180004000",
                    },
                }
            ),
        ) as mock_preprocess_vtable, patch.object(
            ida_analyze_util,
            "write_func_yaml",
        ) as mock_write_func_yaml, patch.object(
            ida_analyze_util,
            "_rename_func_in_ida",
            AsyncMock(return_value=None),
        ):
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=[
                    "/tmp/CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Think.windows.yaml"
                ],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                func_names=[
                    "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Think"
                ],
                func_vtable_relations=[
                    (
                        "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Think",
                        "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
                    )
                ],
                generate_yaml_desired_fields=[
                    (
                        "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Think",
                        ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"],
                    )
                ],
                mangled_class_names=alias_map,
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess_func.assert_awaited_once()
        mock_preprocess_vtable.assert_awaited_once_with(
            session="session",
            class_name="CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
            image_base=0x180000000,
            platform="windows",
            debug=True,
            symbol_aliases=alias_map[
                "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem"
            ],
        )
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(1, written_payload["vfunc_index"])
        self.assertEqual("0x8", written_payload["vfunc_offset"])


class TestGenerateYamlDesiredFieldsContract(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_common_skill_rejects_missing_generate_yaml_desired_fields(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "Foo",
                    "func_va": "0x180004000",
                    "func_rva": "0x4000",
                    "func_size": "0x40",
                    "func_sig": "AA BB",
                }
            ),
        ) as mock_preprocess_func_sig, patch.object(
            ida_analyze_util,
            "write_func_yaml",
        ) as mock_write_func_yaml, patch.object(
            ida_analyze_util,
            "_rename_func_in_ida",
            AsyncMock(return_value=None),
        ):
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=["/tmp/Foo.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                func_names=["Foo"],
                generate_yaml_desired_fields=None,
                debug=True,
            )

        self.assertFalse(result)
        mock_preprocess_func_sig.assert_not_awaited()
        mock_write_func_yaml.assert_not_called()

    async def test_preprocess_common_skill_rejects_missing_desired_fields_before_any_write(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "Foo",
                    "func_va": "0x180004000",
                    "func_rva": "0x4000",
                    "func_size": "0x40",
                    "func_sig": "AA BB",
                }
            ),
        ) as mock_preprocess_func_sig, patch.object(
            ida_analyze_util,
            "preprocess_vtable_via_mcp",
            AsyncMock(
                return_value={
                    "vtable_class": "Bar",
                    "vtable_symbol": "??_7Bar@@6B@",
                    "vtable_va": "0x180001000",
                    "vtable_rva": "0x1000",
                    "vtable_size": "0x20",
                    "vtable_numvfunc": 2,
                    "vtable_entries": {0: "0x180003000", 1: "0x180004000"},
                }
            ),
        ) as mock_preprocess_vtable, patch.object(
            ida_analyze_util,
            "write_func_yaml",
        ) as mock_write_func_yaml, patch.object(
            ida_analyze_util,
            "write_vtable_yaml",
        ) as mock_write_vtable_yaml:
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=[
                    "/tmp/Foo.windows.yaml",
                    "/tmp/Bar_vtable.windows.yaml",
                ],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                func_names=["Foo"],
                vtable_class_names=["Bar"],
                generate_yaml_desired_fields=[("Foo", ["func_name"])],
                debug=True,
            )

        self.assertFalse(result)
        mock_preprocess_func_sig.assert_not_awaited()
        mock_preprocess_vtable.assert_not_awaited()
        mock_write_func_yaml.assert_not_called()
        mock_write_vtable_yaml.assert_not_called()

    async def test_preprocess_common_skill_filters_func_payload_by_desired_fields(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "Foo",
                    "func_va": "0x180004000",
                    "func_rva": "0x4000",
                    "func_size": "0x40",
                    "func_sig": "AA BB",
                }
            ),
        ), patch.object(
            ida_analyze_util,
            "preprocess_vtable_via_mcp",
            AsyncMock(
                return_value={
                    "vtable_class": "Bar",
                    "vtable_symbol": "??_7Bar@@6B@",
                    "vtable_va": "0x180001000",
                    "vtable_rva": "0x1000",
                    "vtable_size": "0x20",
                    "vtable_numvfunc": 2,
                    "vtable_entries": {
                        0: "0x180003000",
                        1: "0x180004000",
                    },
                }
            ),
        ) as mock_preprocess_vtable, patch.object(
            ida_analyze_util,
            "write_func_yaml",
        ) as mock_write_func_yaml, patch.object(
            ida_analyze_util,
            "_rename_func_in_ida",
            AsyncMock(return_value=None),
        ):
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=["/tmp/Foo.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                func_names=["Foo"],
                func_vtable_relations=[("Foo", "Bar")],
                generate_yaml_desired_fields=[
                    ("Foo", ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"])
                ],
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess_vtable.assert_awaited_once_with(
            session="session",
            class_name="Bar",
            image_base=0x180000000,
            platform="windows",
            debug=True,
            symbol_aliases=None,
        )
        mock_write_func_yaml.assert_called_once()
        self.assertEqual(
            {
                "func_name": "Foo",
                "vtable_name": "Bar",
                "vfunc_offset": "0x8",
                "vfunc_index": 1,
            },
            mock_write_func_yaml.call_args.args[1],
        )

    async def test_preprocess_common_skill_rejects_missing_requested_func_field(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "Foo",
                    "func_va": "0x180004000",
                    "func_sig": "AA BB",
                }
            ),
        ), patch.object(
            ida_analyze_util,
            "write_func_yaml",
        ) as mock_write_func_yaml, patch.object(
            ida_analyze_util,
            "_rename_func_in_ida",
            AsyncMock(return_value=None),
        ) as mock_rename_func:
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=["/tmp/Foo.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                func_names=["Foo"],
                generate_yaml_desired_fields=[("Foo", ["func_name", "func_va", "func_rva"])],
                debug=True,
            )

        self.assertFalse(result)
        mock_write_func_yaml.assert_not_called()
        mock_rename_func.assert_not_awaited()

    async def test_preprocess_common_skill_does_not_rename_when_write_fails(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "Foo",
                    "func_va": "0x180004000",
                    "func_sig": "AA BB",
                }
            ),
        ), patch.object(
            ida_analyze_util,
            "write_func_yaml",
            side_effect=OSError("boom"),
        ), patch.object(
            ida_analyze_util,
            "_rename_func_in_ida",
            AsyncMock(return_value=None),
        ) as mock_rename_func:
            with self.assertRaises(OSError):
                await ida_analyze_util.preprocess_common_skill(
                    session="session",
                    expected_outputs=["/tmp/Foo.windows.yaml"],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=["Foo"],
                    generate_yaml_desired_fields=[("Foo", ["func_name"])],
                    debug=True,
                )

        mock_rename_func.assert_not_awaited()

    async def test_preprocess_common_skill_defers_rename_until_all_targets_succeed(
        self,
    ) -> None:
        async def _preprocess_func_side_effect(**kwargs):
            func_name = kwargs["func_name"]
            if func_name == "Foo":
                return {
                    "func_name": "Foo",
                    "func_va": "0x180004000",
                }
            if func_name == "Bar":
                return {
                    "func_name": "Bar",
                    "func_va": "0x180005000",
                }
            return None

        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(side_effect=_preprocess_func_side_effect),
        ), patch.object(
            ida_analyze_util,
            "write_func_yaml",
        ) as mock_write_func_yaml, patch.object(
            ida_analyze_util,
            "_rename_func_in_ida",
            AsyncMock(return_value=None),
        ) as mock_rename_func:
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=[
                    "/tmp/Foo.windows.yaml",
                    "/tmp/Bar.windows.yaml",
                ],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                func_names=["Foo", "Bar"],
                generate_yaml_desired_fields=[
                    ("Foo", ["func_name"]),
                    ("Bar", ["func_name", "func_rva"]),
                ],
                debug=True,
            )

        self.assertFalse(result)
        mock_write_func_yaml.assert_called_once_with(
            "/tmp/Foo.windows.yaml",
            {"func_name": "Foo"},
        )
        mock_rename_func.assert_not_awaited()

    async def test_preprocess_common_skill_renames_after_all_writes_succeed(
        self,
    ) -> None:
        events = []

        async def _rename_side_effect(_session, _func_va_hex, func_name, _debug):
            events.append(("rename", func_name))

        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(
                side_effect=[
                    {"func_name": "Foo", "func_va": "0x180001000", "func_sig": "AA"},
                    {"func_name": "Bar", "func_va": "0x180002000", "func_sig": "BB"},
                ]
            ),
        ), patch.object(
            ida_analyze_util,
            "write_func_yaml",
        ) as mock_write_func_yaml, patch.object(
            ida_analyze_util,
            "_rename_func_in_ida",
            AsyncMock(side_effect=_rename_side_effect),
        ):
            mock_write_func_yaml.side_effect = (
                lambda path, _data: events.append(("write", path))
            )
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=[
                    "/tmp/Foo.windows.yaml",
                    "/tmp/Bar.windows.yaml",
                ],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                func_names=["Foo", "Bar"],
                generate_yaml_desired_fields=[
                    ("Foo", ["func_name"]),
                    ("Bar", ["func_name"]),
                ],
                debug=True,
            )

        self.assertTrue(result)
        self.assertEqual(
            [
                ("write", "/tmp/Foo.windows.yaml"),
                ("write", "/tmp/Bar.windows.yaml"),
                ("rename", "Foo"),
                ("rename", "Bar"),
            ],
            events,
        )

    async def test_preprocess_common_skill_filters_vtable_payload_by_desired_fields(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_vtable_via_mcp",
            AsyncMock(
                return_value={
                    "vtable_class": "Foo",
                    "vtable_symbol": "??_7Foo@@6B@",
                    "vtable_va": "0x180001000",
                    "vtable_rva": "0x1000",
                    "vtable_size": "0x20",
                    "vtable_numvfunc": 4,
                    "vtable_entries": {0: "0x180010000"},
                }
            ),
        ), patch.object(
            ida_analyze_util,
            "write_vtable_yaml",
        ) as mock_write_vtable_yaml:
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=["/tmp/Foo_vtable.windows.yaml"],
                vtable_class_names=["Foo"],
                platform="windows",
                image_base=0x180000000,
                generate_yaml_desired_fields=[
                    ("Foo", ["vtable_class", "vtable_entries"])
                ],
                debug=True,
            )

        self.assertTrue(result)
        mock_write_vtable_yaml.assert_called_once_with(
            "/tmp/Foo_vtable.windows.yaml",
            {
                "vtable_class": "Foo",
                "vtable_entries": {0: "0x180010000"},
            },
        )


class TestLlmDecompileSupport(unittest.IsolatedAsyncioTestCase):
    def test_parse_llm_decompile_response_normalizes_all_sections(self) -> None:
        response_text = """
```yaml
found_vcall:
  - insn_va: 0x180777700
    insn_disasm: " call    [rax+68h] "
    vfunc_offset: 0x68
    func_name: " ILoopMode_OnLoopActivate "
  - invalid: true
found_call:
  - insn_va: 0x180888800
    insn_disasm: " call    sub_180999900 "
    func_name: " CLoopModeGame_RegisterEventMapInternal "
  - insn_disasm: call    sub_missing
found_gv:
  - insn_va: 0x180444400
    insn_disasm: " mov     rcx, cs:qword_180666600 "
    gv_name: " s_GameEventManager "
  - insn_va: 0x180000001
found_struct_offset:
  - insn_va: 0x1801BA12A
    insn_disasm: " mov     rcx, [r14+58h] "
    offset: 0x58
    struct_name: " CGameResourceService "
    member_name: " m_pEntitySystem "
  - member_name: only_member
```
""".strip()

        parsed = ida_analyze_util.parse_llm_decompile_response(response_text)

        self.assertEqual(
            {
                "found_vcall": [
                    {
                        "insn_va": "0x180777700",
                        "insn_disasm": "call    [rax+68h]",
                        "vfunc_offset": "0x68",
                        "func_name": "ILoopMode_OnLoopActivate",
                    }
                ],
                "found_call": [
                    {
                        "insn_va": "0x180888800",
                        "insn_disasm": "call    sub_180999900",
                        "func_name": "CLoopModeGame_RegisterEventMapInternal",
                    }
                ],
                "found_gv": [
                    {
                        "insn_va": "0x180444400",
                        "insn_disasm": "mov     rcx, cs:qword_180666600",
                        "gv_name": "s_GameEventManager",
                    }
                ],
                "found_struct_offset": [
                    {
                        "insn_va": "0x1801BA12A",
                        "insn_disasm": "mov     rcx, [r14+58h]",
                        "offset": "0x58",
                        "struct_name": "CGameResourceService",
                        "member_name": "m_pEntitySystem",
                    }
                ],
            },
            parsed,
        )

    async def test_call_llm_decompile_uses_shared_llm_helper_and_parses_yaml(
        self,
    ) -> None:
        response_text = """
```yaml
found_vcall:
  - insn_va: 0x180777700
    insn_disasm: " call    [rax+68h] "
    vfunc_offset: 0x68
    func_name: " ILoopMode_OnLoopActivate "
found_call: []
found_gv: []
found_struct_offset: []
```
""".strip()

        with patch.object(
            ida_analyze_util,
            "call_llm_text",
            return_value=response_text,
            create=True,
        ) as mock_call_llm_text:
            parsed = await ida_analyze_util.call_llm_decompile(
                client=object(),
                model="gpt-4.1-mini",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
            )

        self.assertEqual(
            {
                "found_vcall": [
                    {
                        "insn_va": "0x180777700",
                        "insn_disasm": "call    [rax+68h]",
                        "vfunc_offset": "0x68",
                        "func_name": "ILoopMode_OnLoopActivate",
                    }
                ],
                "found_call": [],
                "found_gv": [],
                "found_struct_offset": [],
            },
            parsed,
        )
        mock_call_llm_text.assert_called_once()
        self.assertEqual("gpt-4.1-mini", mock_call_llm_text.call_args.kwargs["model"])
        self.assertEqual(0.1, mock_call_llm_text.call_args.kwargs["temperature"])

    async def test_call_llm_decompile_fails_closed_when_shared_helper_raises(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "call_llm_text",
            side_effect=RuntimeError("llm unavailable"),
            create=True,
        ):
            parsed = await ida_analyze_util.call_llm_decompile(
                client=object(),
                model="gpt-4.1-mini",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
            )

        self.assertEqual(
            {
                "found_vcall": [],
                "found_call": [],
                "found_gv": [],
                "found_struct_offset": [],
            },
            parsed,
        )

    async def test_preprocess_func_sig_via_mcp_supports_direct_vtable_generation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session = AsyncMock()
            session.call_tool.return_value = _py_eval_payload(
                {
                    "func_va": "0x180123450",
                    "func_size": "0x40",
                }
            )

            with patch.object(
                ida_analyze_util,
                "preprocess_vtable_via_mcp",
                AsyncMock(
                    return_value={
                        "vtable_class": "CLoopModeGame",
                        "vtable_symbol": "??_7CLoopModeGame@@6B@",
                        "vtable_va": "0x180001000",
                        "vtable_rva": "0x1000",
                        "vtable_size": "0x90",
                        "vtable_numvfunc": 32,
                        "vtable_entries": {13: "0x180123450"},
                    }
                ),
            ), patch.object(
                ida_analyze_util,
                "preprocess_gen_func_sig_via_mcp",
                AsyncMock(
                    return_value={
                        "func_va": "0x180123450",
                        "func_rva": "0x123450",
                        "func_size": "0x40",
                        "func_sig": "48 89 ??",
                    }
                ),
            ):
                result = await ida_analyze_util.preprocess_func_sig_via_mcp(
                    session=session,
                    new_path=f"{temp_dir}/CLoopModeGame_OnLoopActivate.windows.yaml",
                    old_path=None,
                    image_base=0x180000000,
                    new_binary_dir=temp_dir,
                    platform="windows",
                    func_name="CLoopModeGame_OnLoopActivate",
                    direct_vtable_class="CLoopModeGame",
                    direct_vfunc_offset="0x68",
                    debug=False,
                )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("CLoopModeGame_OnLoopActivate", result["func_name"])
        self.assertEqual("0x180123450", result["func_va"])
        self.assertEqual("48 89 ??", result["func_sig"])
        self.assertEqual("CLoopModeGame", result["vtable_name"])
        self.assertEqual("0x68", result["vfunc_offset"])
        self.assertEqual(13, result["vfunc_index"])

    async def test_preprocess_gen_struct_offset_sig_via_mcp_generates_current_version_sig(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                self.assertIn("DecodeInstruction", arguments["code"])
                self.assertIn("ida_bytes.get_bytes", arguments["code"])
                return _py_eval_payload(
                    [
                        {
                            "offset_inst_va": "0x1801BA12A",
                            "insts": [
                                {
                                    "size": 4,
                                    "bytes": "498b4e58",
                                    "wild": [3],
                                },
                                {
                                    "size": 3,
                                    "bytes": "4885c9",
                                    "wild": [],
                                },
                            ],
                        }
                    ]
                )
            if name == "find_bytes":
                self.assertEqual(
                    ["49 8B 4E ??"],
                    arguments["patterns"],
                )
                return _FakeCallToolResult(
                    [
                        {
                            "matches": ["0x1801BA12A"],
                            "n": 1,
                        }
                    ]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_struct_offset_sig_via_mcp(
            session=session,
            struct_name="CGameResourceService",
            member_name="m_pEntitySystem",
            offset="0x58",
            offset_inst_va="0x1801BA12A",
            image_base=0x180000000,
            min_sig_bytes=4,
            debug=False,
        )

        self.assertEqual(
            {
                "struct_name": "CGameResourceService",
                "member_name": "m_pEntitySystem",
                "offset": "0x58",
                "offset_sig": "49 8B 4E ??",
            },
            result,
        )

    async def test_preprocess_common_skill_uses_llm_decompile_vcall_fallback_for_func_yaml(
        self,
    ) -> None:
        func_name = "CLoopModeGame_OnLoopActivate"
        output_path = f"/tmp/{func_name}.windows.yaml"
        target_detail_payload = {
            "func_name": "CNetworkGameClient_RecordEntityBandwidth",
            "func_va": "0x180555500",
            "disasm_code": "mov     rax, [rcx]\ncall    qword ptr [rax+68h]",
            "procedure": "return this->vfptr[13](this);",
        }
        normalized_payload = {
            "found_vcall": [
                {
                    "insn_va": "0x180777700",
                    "insn_disasm": "call    [rax+68h]",
                    "vfunc_offset": "0x68",
                    "func_name": func_name,
                }
            ],
            "found_call": [],
            "found_gv": [],
            "found_struct_offset": [],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            session = AsyncMock()
            prompt_text = (
                "ref={disasm_for_reference}|{procedure_for_reference}|"
                "target={disasm_code}|{procedure}|symbols={symbol_name_list}"
            )
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                prompt_text,
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": "mov rax, [rcx]",
                    "procedure": "return this->vfptr[13](this);",
                },
            )
            fake_client = object()

            async def _session_call_tool(*, name, arguments):
                self.assertEqual("py_eval", name)
                code = arguments["code"]
                if "candidate_names =" in code:
                    return _py_eval_payload(
                        [
                            {
                                "name": target_detail_payload["func_name"],
                                "func_va": target_detail_payload["func_va"],
                            }
                        ]
                    )
                if "'disasm_code': get_disasm(func_start)" in code:
                    return _py_eval_payload(target_detail_payload)
                raise AssertionError(f"unexpected py_eval code: {code}")

            session.call_tool.side_effect = _session_call_tool

            with patch.object(
                ida_analyze_util,
                "_get_preprocessor_scripts_dir",
                return_value=preprocessor_dir,
            ), patch.object(
                ida_analyze_util,
                "create_openai_client",
                return_value=fake_client,
                create=True,
            ), patch.object(
                ida_analyze_util,
                "preprocess_func_sig_via_mcp",
                AsyncMock(return_value=None),
            ), patch.object(
                ida_analyze_util,
                "_get_func_basic_info_via_mcp",
                AsyncMock(
                    return_value={
                        "func_va": "0x180123450",
                        "func_rva": "0x123450",
                        "func_size": "0x40",
                    }
                ),
            ), patch.object(
                ida_analyze_util,
                "preprocess_gen_func_sig_via_mcp",
                AsyncMock(return_value={"func_sig": "40 53"}),
            ), patch.object(
                ida_analyze_util,
                "call_llm_decompile",
                create=True,
                new_callable=AsyncMock,
                return_value=normalized_payload,
            ) as mock_call_llm_decompile, patch.object(
                ida_analyze_util,
                "preprocess_vtable_via_mcp",
                AsyncMock(
                    return_value={
                        "vtable_class": "CLoopModeGame",
                        "vtable_symbol": "??_7CLoopModeGame@@6B@",
                        "vtable_va": "0x180001000",
                        "vtable_rva": "0x1000",
                        "vtable_size": "0x90",
                        "vtable_numvfunc": 32,
                        "vtable_entries": {13: "0x180123450"},
                    }
                ),
            ), patch.object(
                ida_analyze_util,
                "write_func_yaml",
            ) as mock_write_func_yaml, patch.object(
                ida_analyze_util,
                "_rename_func_in_ida",
                AsyncMock(return_value=None),
            ):
                result = await ida_analyze_util.preprocess_common_skill(
                    session=session,
                    expected_outputs=[output_path],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    func_vtable_relations=[(func_name, "CLoopModeGame")],
                    generate_yaml_desired_fields=[
                        (
                            func_name,
                            ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"],
                        )
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        )
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_call_llm_decompile.assert_awaited_once()
        self.assertIs(fake_client, mock_call_llm_decompile.call_args.kwargs["client"])
        self.assertEqual(
            "gpt-4.1-mini",
            mock_call_llm_decompile.call_args.kwargs["model"],
        )
        self.assertEqual(
            prompt_text,
            mock_call_llm_decompile.call_args.kwargs["prompt_template"],
        )
        self.assertEqual(
            "mov rax, [rcx]",
            mock_call_llm_decompile.call_args.kwargs["disasm_for_reference"],
        )
        self.assertEqual(
            "return this->vfptr[13](this);",
            mock_call_llm_decompile.call_args.kwargs["procedure_for_reference"],
        )
        self.assertEqual(
            target_detail_payload["disasm_code"],
            mock_call_llm_decompile.call_args.kwargs["disasm_code"],
        )
        self.assertEqual(
            target_detail_payload["procedure"],
            mock_call_llm_decompile.call_args.kwargs["procedure"],
        )
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(func_name, written_payload["func_name"])
        self.assertEqual("0x68", written_payload["vfunc_offset"])
        self.assertEqual(13, written_payload["vfunc_index"])

    async def test_preprocess_common_skill_llm_fallback_skips_missing_reference_yaml(
        self,
    ) -> None:
        func_name = "CLoopModeGame_OnLoopActivate"
        output_path = f"/tmp/{func_name}.windows.yaml"

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )

            with patch.object(
                ida_analyze_util,
                "_get_preprocessor_scripts_dir",
                return_value=preprocessor_dir,
            ), patch.object(
                ida_analyze_util,
                "preprocess_func_sig_via_mcp",
                AsyncMock(return_value=None),
            ), patch.object(
                ida_analyze_util,
                "create_openai_client",
                create=True,
            ) as mock_create_openai_client, patch.object(
                ida_analyze_util,
                "call_llm_decompile",
                create=True,
                new_callable=AsyncMock,
            ) as mock_call_llm_decompile, patch.object(
                ida_analyze_util,
                "write_func_yaml",
            ) as mock_write_func_yaml:
                result = await ida_analyze_util.preprocess_common_skill(
                    session="session",
                    expected_outputs=[output_path],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    func_vtable_relations=[(func_name, "CLoopModeGame")],
                    generate_yaml_desired_fields=[
                        (
                            func_name,
                            ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"],
                        )
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/missing.yaml",
                        )
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

                self.assertFalse(result)
                mock_create_openai_client.assert_not_called()
                mock_call_llm_decompile.assert_not_awaited()
                mock_write_func_yaml.assert_not_called()

    async def test_preprocess_common_skill_uses_llm_decompile_direct_call_fallback_without_vtable_relation(
        self,
    ) -> None:
        func_name = "CNetworkMessages_FindNetworkGroup"
        output_path = f"/tmp/{func_name}.windows.yaml"
        target_detail_payload = {
            "func_name": "CNetworkGameClient_RecordEntityBandwidth",
            "func_va": "0x180555500",
            "disasm_code": "call    sub_180222200",
            "procedure": "return CNetworkMessages::FindNetworkGroup(this, group);",
        }
        normalized_payload = {
            "found_vcall": [],
            "found_call": [
                {
                    "insn_va": "0x180777700",
                    "insn_disasm": "call    sub_180222200",
                    "func_name": func_name,
                }
            ],
            "found_gv": [],
            "found_struct_offset": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            session = AsyncMock()
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": "call    sub_180222200",
                    "procedure": target_detail_payload["procedure"],
                },
            )

            async def _session_call_tool(*, name, arguments):
                self.assertEqual("py_eval", name)
                code = arguments["code"]
                if "candidate_names =" in code:
                    return _py_eval_payload(
                        [
                            {
                                "name": target_detail_payload["func_name"],
                                "func_va": target_detail_payload["func_va"],
                            }
                        ]
                    )
                if "'disasm_code': get_disasm(func_start)" in code:
                    return _py_eval_payload(target_detail_payload)
                raise AssertionError(f"unexpected py_eval code: {code}")

            session.call_tool.side_effect = _session_call_tool

            with patch.object(
                ida_analyze_util,
                "_get_preprocessor_scripts_dir",
                return_value=preprocessor_dir,
            ), patch.object(
                ida_analyze_util,
                "create_openai_client",
                return_value=object(),
                create=True,
            ), patch.object(
                ida_analyze_util,
                "preprocess_func_sig_via_mcp",
                AsyncMock(return_value=None),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(return_value="0x180123450"),
            ) as mock_resolve_direct_call_target, patch.object(
                ida_analyze_util,
                "_get_func_basic_info_via_mcp",
                AsyncMock(
                    return_value={
                        "func_va": "0x180123450",
                        "func_rva": "0x123450",
                        "func_size": "0x40",
                    }
                ),
            ), patch.object(
                ida_analyze_util,
                "preprocess_gen_func_sig_via_mcp",
                AsyncMock(return_value={"func_sig": "40 53"}),
            ), patch.object(
                ida_analyze_util,
                "call_llm_decompile",
                create=True,
                new_callable=AsyncMock,
                return_value=normalized_payload,
            ) as mock_call_llm_decompile, patch.object(
                ida_analyze_util,
                "write_func_yaml",
            ) as mock_write_func_yaml, patch.object(
                ida_analyze_util,
                "_rename_func_in_ida",
                AsyncMock(return_value=None),
            ):
                result = await ida_analyze_util.preprocess_common_skill(
                    session=session,
                    expected_outputs=[output_path],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    generate_yaml_desired_fields=[(func_name, ["func_name", "func_va"])],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        )
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_call_llm_decompile.assert_awaited_once()
        mock_resolve_direct_call_target.assert_awaited_once_with(
            session,
            "0x180777700",
            debug=True,
        )
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(func_name, written_payload["func_name"])
        self.assertEqual("0x180123450", written_payload["func_va"])
        self.assertNotIn("vtable_name", written_payload)

    async def test_preprocess_common_skill_uses_slot_only_fallback_when_vtable_unavailable(
        self,
    ) -> None:
        func_name = "INetworkMessages_FindNetworkGroup"
        output_path = f"/tmp/{func_name}.windows.yaml"
        target_detail_payload = {
            "func_name": "CNetworkGameClient_RecordEntityBandwidth",
            "func_va": "0x180555500",
            "disasm_code": "call    qword ptr [rax+78h]",
            "procedure": "return this->vfptr[15](this, group);",
        }
        normalized_payload = {
            "found_vcall": [
                {
                    "insn_va": "0x18004ABC3",
                    "insn_disasm": "call    qword ptr [rax+78h]",
                    "vfunc_offset": "0x78",
                    "func_name": func_name,
                },
                {
                    "insn_va": "0x18004AC0A",
                    "insn_disasm": "call    qword ptr [rax+78h]",
                    "vfunc_offset": "0x78",
                    "func_name": func_name,
                },
            ],
            "found_call": [],
            "found_gv": [],
            "found_struct_offset": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            session = AsyncMock()
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": "call    qword ptr [rax+78h]",
                    "procedure": target_detail_payload["procedure"],
                },
            )

            async def _session_call_tool(*, name, arguments):
                self.assertEqual("py_eval", name)
                code = arguments["code"]
                if "candidate_names =" in code:
                    return _py_eval_payload(
                        [
                            {
                                "name": target_detail_payload["func_name"],
                                "func_va": target_detail_payload["func_va"],
                            }
                        ]
                    )
                if "'disasm_code': get_disasm(func_start)" in code:
                    return _py_eval_payload(target_detail_payload)
                raise AssertionError(f"unexpected py_eval code: {code}")

            session.call_tool.side_effect = _session_call_tool

            with patch.object(
                ida_analyze_util,
                "_get_preprocessor_scripts_dir",
                return_value=preprocessor_dir,
            ), patch.object(
                ida_analyze_util,
                "create_openai_client",
                return_value=object(),
                create=True,
            ), patch.object(
                ida_analyze_util,
                "preprocess_func_sig_via_mcp",
                AsyncMock(return_value=None),
            ), patch.object(
                ida_analyze_util,
                "preprocess_vtable_via_mcp",
                AsyncMock(return_value=None),
            ), patch.object(
                ida_analyze_util,
                "call_llm_decompile",
                create=True,
                new_callable=AsyncMock,
                return_value=normalized_payload,
            ), patch.object(
                ida_analyze_util,
                "write_func_yaml",
            ) as mock_write_func_yaml, patch.object(
                ida_analyze_util,
                "_rename_func_in_ida",
                AsyncMock(return_value=None),
            ):
                result = await ida_analyze_util.preprocess_common_skill(
                    session=session,
                    expected_outputs=[output_path],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    func_vtable_relations=[(func_name, "CNetworkMessages")],
                    generate_yaml_desired_fields=[
                        (
                            func_name,
                            ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"],
                        )
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        )
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(func_name, written_payload["func_name"])
        self.assertEqual("CNetworkMessages", written_payload["vtable_name"])
        self.assertEqual("0x78", written_payload["vfunc_offset"])
        self.assertEqual(15, written_payload["vfunc_index"])
        self.assertNotIn("func_va", written_payload)


if __name__ == "__main__":
    unittest.main()

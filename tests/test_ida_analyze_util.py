import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, call, patch

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


def _function_detail_export_py_eval(func_va: str | int) -> str:
    if isinstance(func_va, str):
        func_va_int = int(func_va, 0)
    else:
        func_va_int = int(func_va)
    return ida_analyze_util.build_function_detail_export_py_eval(func_va_int)


def _write_yaml(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


class TestPreprocessIndexBasedVfuncViaMcp(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_common_skill_emits_slot_only_inherited_vfunc(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"
            target_output = module_dir / "ILoopMode_LoopInit.windows.yaml"

            _write_yaml(
                module_dir / "CLoopModeGame_LoopInit.windows.yaml",
                {
                    "vtable_name": "CLoopModeGame",
                    "vfunc_offset": "0x28",
                },
            )

            session = AsyncMock()

            result = await ida_analyze_util.preprocess_common_skill(
                session=session,
                expected_outputs=[str(target_output)],
                old_yaml_map={},
                new_binary_dir=str(module_dir),
                platform="windows",
                image_base=0x180000000,
                inherit_vfuncs=[
                    (
                        "ILoopMode_LoopInit",
                        "ILoopMode",
                        "CLoopModeGame_LoopInit",
                        False,
                    ),
                ],
                generate_yaml_desired_fields=[
                    (
                        "ILoopMode_LoopInit",
                        [
                            "func_name",
                            "vtable_name",
                            "vfunc_offset",
                            "vfunc_index",
                        ],
                    ),
                ],
                debug=False,
            )

            self.assertTrue(result)
            session.call_tool.assert_not_awaited()
            self.assertEqual(
                {
                    "func_name": "ILoopMode_LoopInit",
                    "vtable_name": "ILoopMode",
                    "vfunc_offset": "0x28",
                    "vfunc_index": 5,
                },
                yaml.safe_load(target_output.read_text(encoding="utf-8")),
            )

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

    async def test_forwards_boundary_flag_when_generating_func_sig(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"
            target_output = module_dir / "CDerived_Touch.windows.yaml"

            _write_yaml(
                module_dir / "CBaseEntity_Touch.windows.yaml",
                {
                    "vtable_name": "CBaseEntity",
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
            session.call_tool.return_value = _py_eval_payload(
                {
                    "func_va": "0x180001180",
                    "func_size": "0x40",
                }
            )

            with patch.object(
                ida_analyze_util,
                "preprocess_gen_func_sig_via_mcp",
                AsyncMock(
                    return_value={
                        "func_sig": "48 89 ??",
                    }
                ),
            ) as mock_gen_sig:
                result = await ida_analyze_util.preprocess_index_based_vfunc_via_mcp(
                    session=session,
                    target_func_name="CDerived_Touch",
                    target_output=str(target_output),
                    old_yaml_map={},
                    new_binary_dir=str(module_dir),
                    platform="windows",
                    image_base=0x180000000,
                    base_vfunc_name="CBaseEntity_Touch",
                    inherit_vtable_class="CDerived",
                    generate_func_sig=True,
                    allow_func_sig_across_function_boundary=True,
                    debug=False,
                )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("48 89 ??", result["func_sig"])
        mock_gen_sig.assert_awaited_once()
        self.assertTrue(
            mock_gen_sig.await_args.kwargs["allow_across_function_boundary"]
        )


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

    def test_build_vtable_py_eval_resolves_exact_windows_rtti_alias(self) -> None:
        rtti_symbol = (
            "??_R4?$CEntityComponentHelperT@VCBodyComponent@@V?"
            "$CEntityComponentHelperReferenced@VCBodyComponent@@@@@@6B@"
        )
        vfuncs = [
            0x1801CA460,
            0x1801BAE70,
            0x1801BC640,
            0x1801BBB40,
            0x1801B52D0,
            0x1801BB090,
        ]

        result = self._run_vtable_py_eval(
            class_name="CEntityComponentHelperT_CBodyComponent",
            symbol_aliases=[
                rtti_symbol,
                "_ZTV23CEntityComponentHelperTI14CBodyComponent32"
                "CEntityComponentHelperReferencedIS0_EE",
            ],
            name_to_ea={rtti_symbol: 0x181917500},
            name_by_ea={0x1815A1618: "CEntityComponentHelperT_CBodyComponent_vtable"},
            data_refs={0x181917500: [0x1815A1610]},
            ptr_values={
                0x1815A1618 + idx * 8: vfunc
                for idx, vfunc in enumerate(vfuncs)
            }
            | {0x1815A1648: 0},
            func_addrs=set(vfuncs),
        )

        self.assertEqual(
            "CEntityComponentHelperT_CBodyComponent_vtable",
            result["vtable_symbol"],
        )
        self.assertEqual("0x1815a1618", result["vtable_va"])
        self.assertEqual(6, result["vtable_numvfunc"])
        self.assertEqual(
            {str(idx): hex(vfunc) for idx, vfunc in enumerate(vfuncs)},
            result["vtable_entries"],
        )

    def _run_vtable_py_eval(
        self,
        *,
        class_name: str,
        symbol_aliases: list[str],
        name_to_ea: dict[str, int],
        name_by_ea: dict[int, str],
        data_refs: dict[int, list[int]],
        ptr_values: dict[int, int],
        func_addrs: set[int],
    ) -> dict[str, object]:
        py_code = ida_analyze_util._build_vtable_py_eval(
            class_name,
            symbol_aliases=symbol_aliases,
        )
        exec_globals = {"__builtins__": __builtins__}

        with patch.dict(
            sys.modules,
            self._build_fake_vtable_ida_modules(
                name_to_ea=name_to_ea,
                name_by_ea=name_by_ea,
                data_refs=data_refs,
                ptr_values=ptr_values,
                func_addrs=func_addrs,
            ),
            clear=False,
        ):
            exec(py_code, exec_globals)

        return json.loads(exec_globals["result"])

    def _build_fake_vtable_ida_modules(
        self,
        *,
        name_to_ea: dict[str, int],
        name_by_ea: dict[int, str],
        data_refs: dict[int, list[int]],
        ptr_values: dict[int, int],
        func_addrs: set[int],
    ) -> dict[str, types.ModuleType]:
        ida_auto = types.ModuleType("ida_auto")
        ida_auto.auto_wait = lambda: None

        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = -1
        idaapi.inf_is_64bit = lambda: True
        idaapi.get_func = lambda ea: (
            types.SimpleNamespace(start_ea=ea, end_ea=ea + 1)
            if ea in func_addrs
            else None
        )
        idaapi.add_func = lambda ea: None

        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.DELIT_SIMPLE = 0
        ida_bytes.del_items = lambda *args: None
        ida_bytes.get_qword = lambda ea: ptr_values.get(ea, 0)
        ida_bytes.get_dword = lambda ea: 0
        ida_bytes.get_full_flags = lambda ea: 1 if ea in func_addrs else 0
        ida_bytes.is_code = lambda flags: bool(flags)

        ida_name = types.ModuleType("ida_name")
        ida_name.get_name_ea = lambda badaddr, name: name_to_ea.get(name, badaddr)
        ida_name.get_name = lambda ea: name_by_ea.get(ea, "")

        idautils = types.ModuleType("idautils")
        idautils.DataRefsTo = lambda ea: data_refs.get(ea, [])

        idc = types.ModuleType("idc")
        idc.create_insn = lambda ea: True

        ida_segment = self._build_fake_vtable_ida_segment_module()
        return {
            "ida_auto": ida_auto,
            "ida_bytes": ida_bytes,
            "ida_name": ida_name,
            "idaapi": idaapi,
            "ida_segment": ida_segment,
            "idautils": idautils,
            "idc": idc,
        }

    def _build_fake_vtable_ida_segment_module(self) -> types.ModuleType:
        ida_segment = types.ModuleType("ida_segment")
        ida_segment.SEGPERM_EXEC = 1
        rdata_seg = types.SimpleNamespace(
            start_ea=0x181500000,
            end_ea=0x182000000,
            perm=0,
        )
        text_seg = types.SimpleNamespace(
            start_ea=0x180000000,
            end_ea=0x181000000,
            perm=1,
        )
        ida_segment.get_segm_by_name = (
            lambda name: rdata_seg if name == ".rdata" else None
        )
        ida_segment.getseg = lambda ea: (
            rdata_seg if rdata_seg.start_ea <= ea < rdata_seg.end_ea else
            text_seg if text_seg.start_ea <= ea < text_seg.end_ea else
            None
        )
        return ida_segment

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


class TestVtableEntryRecoverySupport(unittest.IsolatedAsyncioTestCase):
    def test_build_vtable_py_eval_embeds_debug_flag(self) -> None:
        py_code = ida_analyze_util._build_vtable_py_eval(
            "CSource2Client",
            debug=True,
        )

        self.assertIn('"CSource2Client"', py_code)
        self.assertIn("debug_enabled = True", py_code)
        self.assertNotIn("DEBUG_PLACEHOLDER", py_code)

    async def test_preprocess_vtable_via_mcp_forwards_debug_to_builder(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "vtable_class": "CSource2Client",
                "vtable_symbol": "_ZTV14CSource2Client + 0x10",
                "vtable_va": "0x424f6c0",
                "vtable_size": "0x18",
                "vtable_numvfunc": 3,
                "vtable_entries": {
                    "0": "0x174e400",
                    "1": "0x174dcd0",
                    "2": "0x17481f0",
                },
            }
        )

        with patch.object(
            ida_analyze_util,
            "_build_vtable_py_eval",
            return_value="py-code",
        ) as mock_build:
            result = await ida_analyze_util.preprocess_vtable_via_mcp(
                session=session,
                class_name="CSource2Client",
                image_base=0x400000,
                platform="linux",
                debug=True,
            )

        self.assertEqual(
            {
                "vtable_class": "CSource2Client",
                "vtable_symbol": "_ZTV14CSource2Client + 0x10",
                "vtable_va": "0x424f6c0",
                "vtable_rva": hex(0x424F6C0 - 0x400000),
                "vtable_size": "0x18",
                "vtable_numvfunc": 3,
                "vtable_entries": {
                    0: "0x174e400",
                    1: "0x174dcd0",
                    2: "0x17481f0",
                },
            },
            result,
        )
        mock_build.assert_called_once_with(
            "CSource2Client",
            symbol_aliases=None,
            debug=True,
        )
        session.call_tool.assert_awaited_once_with(
            name="py_eval",
            arguments={"code": "py-code"},
        )

    def test_build_vtable_py_eval_recovers_exec_entries_to_func_start(self) -> None:
        py_code = ida_analyze_util._build_vtable_py_eval(
            "CSource2Client",
            debug=True,
        )

        self.assertIn(
            "import ida_auto, ida_bytes, ida_name, idaapi, ida_segment, idautils, idc, json",
            py_code,
        )
        self.assertIn("def _debug(message):", py_code)
        self.assertIn("def _resolve_vtable_func_start(ptr_value):", py_code)
        self.assertIn(
            "ida_bytes.del_items(ptr_value, ida_bytes.DELIT_SIMPLE, ptr_size)",
            py_code,
        )
        self.assertIn("idc.create_insn(ptr_value)", py_code)
        self.assertIn("idaapi.add_func(ptr_value)", py_code)
        self.assertIn("ida_auto.auto_wait()", py_code)
        self.assertIn("func_start = _resolve_vtable_func_start(ptr_value)", py_code)
        self.assertIn("entries[count] = hex(func_start)", py_code)

    def test_build_vtable_py_eval_rejects_uncovered_recovery_result(self) -> None:
        py_code = ida_analyze_util._build_vtable_py_eval(
            "CSource2Client",
            debug=True,
        )

        self.assertIn("if func is None:", py_code)
        self.assertIn(
            'f"    Preprocess vtable: no function covers {hex(ptr_value)} after recovery"',
            py_code,
        )
        self.assertIn(
            "if not (func.start_ea <= ptr_value < func.end_ea):",
            py_code,
        )
        self.assertIn(
            'f"{hex(func.start_ea)} does not cover {hex(ptr_value)}"',
            py_code,
        )


class TestVtableArtifactStemSupport(unittest.IsolatedAsyncioTestCase):
    def test_normalizes_plain_class_name_to_primary_vtable_artifact(self) -> None:
        self.assertEqual(
            "CSpawnGroupMgrGameSystem_vtable",
            ida_analyze_util._normalize_vtable_artifact_stem(
                "CSpawnGroupMgrGameSystem"
            ),
        )

    def test_preserves_primary_vtable_artifact_stem(self) -> None:
        self.assertEqual(
            "CSpawnGroupMgrGameSystem_vtable",
            ida_analyze_util._normalize_vtable_artifact_stem(
                "CSpawnGroupMgrGameSystem_vtable"
            ),
        )

    def test_preserves_numbered_vtable_artifact_stem(self) -> None:
        self.assertEqual(
            "CSpawnGroupMgrGameSystem_vtable2",
            ida_analyze_util._normalize_vtable_artifact_stem(
                "CSpawnGroupMgrGameSystem_vtable2"
            ),
        )

    def test_builds_vtable_yaml_path_without_double_suffix(self) -> None:
        self.assertEqual(
            os.path.join(
                "/tmp/server",
                "CSpawnGroupMgrGameSystem_vtable2.windows.yaml",
            ),
            ida_analyze_util._build_vtable_yaml_path(
                "/tmp/server",
                "CSpawnGroupMgrGameSystem_vtable2",
                "windows",
            ),
        )

    async def test_func_vtable_relation_reads_numbered_vtable_artifact(self) -> None:
        func_name = "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate"
        artifact_stem = "CSpawnGroupMgrGameSystem_vtable2"

        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir)
            target_output = module_dir / f"{func_name}.windows.yaml"
            _write_yaml(
                module_dir / f"{artifact_stem}.windows.yaml",
                {
                    "vtable_entries": {
                        56: "0x1803a75c0",
                    }
                },
            )

            with patch.object(
                ida_analyze_util,
                "preprocess_func_sig_via_mcp",
                AsyncMock(
                    return_value={
                        "func_name": func_name,
                        "func_va": "0x1803a75c0",
                        "func_rva": "0x3a75c0",
                        "func_size": "0x40",
                    }
                ),
            ) as mock_preprocess_func, patch.object(
                ida_analyze_util,
                "preprocess_vtable_via_mcp",
                AsyncMock(return_value=None),
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
                    expected_outputs=[str(target_output)],
                    old_yaml_map={},
                    new_binary_dir=str(module_dir),
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    func_vtable_relations=[
                        (func_name, artifact_stem),
                    ],
                    generate_yaml_desired_fields=[
                        (
                            func_name,
                            [
                                "func_name",
                                "vtable_name",
                                "vfunc_offset",
                                "vfunc_index",
                            ],
                        )
                    ],
                    debug=True,
                )

        self.assertTrue(result)
        mock_preprocess_func.assert_awaited_once()
        mock_preprocess_vtable.assert_not_awaited()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(artifact_stem, written_payload["vtable_name"])
        self.assertEqual(56, written_payload["vfunc_index"])
        self.assertEqual("0x1c0", written_payload["vfunc_offset"])

    async def test_preprocess_func_sig_reads_artifact_stem_yaml_without_regeneration(
        self,
    ) -> None:
        artifact_stem = "CSpawnGroupMgrGameSystem_vtable2"

        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "Foo.windows.yaml"
            new_path = Path(temp_dir) / "Foo.new.windows.yaml"
            _write_yaml(
                old_path,
                {
                    "func_name": "Foo",
                    "vfunc_sig": "FF 90 C0 01 00 00",
                    "vtable_name": artifact_stem,
                    "vfunc_offset": "0x1c0",
                    "vfunc_index": 56,
                    "func_va": "0x180111111",
                },
            )
            _write_yaml(
                Path(temp_dir) / f"{artifact_stem}.windows.yaml",
                {
                    "vtable_entries": {
                        56: "0x1803a75c0",
                    }
                },
            )

            session = AsyncMock()

            async def _session_call_tool(*, name: str, arguments: dict[str, object]):
                if name == "find_bytes":
                    self.assertEqual(["FF 90 C0 01 00 00"], arguments["patterns"])
                    return _FakeCallToolResult(
                        [
                            {
                                "matches": ["0x180012340"],
                                "n": 1,
                            }
                        ]
                    )
                if name == "py_eval":
                    return _py_eval_payload(
                        {
                            "func_va": "0x1803a75c0",
                            "func_size": "0x40",
                        }
                    )
                raise AssertionError(f"unexpected MCP tool: {name}")

            session.call_tool.side_effect = _session_call_tool

            with patch.object(
                ida_analyze_util,
                "preprocess_vtable_via_mcp",
                AsyncMock(return_value=None),
            ) as mock_preprocess_vtable:
                result = await ida_analyze_util.preprocess_func_sig_via_mcp(
                    session=session,
                    new_path=str(new_path),
                    old_path=str(old_path),
                    image_base=0x180000000,
                    new_binary_dir=temp_dir,
                    platform="windows",
                    debug=True,
                )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("0x1803a75c0", result["func_va"])
        self.assertEqual(artifact_stem, result["vtable_name"])
        mock_preprocess_vtable.assert_not_awaited()

    async def test_preprocess_func_sig_fails_closed_for_missing_artifact_stem_yaml(
        self,
    ) -> None:
        artifact_stem = "CSpawnGroupMgrGameSystem_vtable2"

        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "Foo.windows.yaml"
            new_path = Path(temp_dir) / "Foo.new.windows.yaml"
            _write_yaml(
                old_path,
                {
                    "func_name": "Foo",
                    "vfunc_sig": "FF 90 C0 01 00 00",
                    "vtable_name": artifact_stem,
                    "vfunc_offset": "0x1c0",
                    "vfunc_index": 56,
                    "func_va": "0x180111111",
                },
            )

            session = AsyncMock()
            session.call_tool.return_value = _FakeCallToolResult(
                [
                    {
                        "matches": ["0x180012340"],
                        "n": 1,
                    }
                ]
            )

            with patch.object(
                ida_analyze_util,
                "preprocess_vtable_via_mcp",
                AsyncMock(return_value={"vtable_entries": {56: "0x1803a75c0"}}),
            ) as mock_preprocess_vtable:
                result = await ida_analyze_util.preprocess_func_sig_via_mcp(
                    session=session,
                    new_path=str(new_path),
                    old_path=str(old_path),
                    image_base=0x180000000,
                    new_binary_dir=temp_dir,
                    platform="windows",
                    debug=True,
                )

        self.assertIsNone(result)
        mock_preprocess_vtable.assert_not_awaited()
        session.call_tool.assert_awaited_once()

    async def test_preprocess_index_based_vfunc_reads_numbered_artifact_vtable_yaml(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"
            target_output = module_dir / "CDerived_Touch.windows.yaml"

            _write_yaml(
                module_dir / "CBaseEntity_Touch.windows.yaml",
                {
                    "vtable_name": "CBaseEntity",
                    "vfunc_offset": "0x118",
                },
            )
            _write_yaml(
                module_dir / "CDerived_vtable2.windows.yaml",
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
                target_func_name="CDerived_Touch",
                target_output=str(target_output),
                old_yaml_map={},
                new_binary_dir=str(module_dir),
                platform="windows",
                image_base=0x180000000,
                base_vfunc_name="CBaseEntity_Touch",
                inherit_vtable_class="CDerived_vtable2",
                generate_func_sig=False,
                debug=False,
            )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("CDerived_vtable2", result["vtable_name"])
        self.assertEqual(35, result["vfunc_index"])
        self.assertEqual("0x118", result["vfunc_offset"])

    async def test_preprocess_direct_func_sig_reads_artifact_stem_yaml(self) -> None:
        artifact_stem = "CSpawnGroupMgrGameSystem_vtable2"

        with tempfile.TemporaryDirectory() as temp_dir:
            _write_yaml(
                Path(temp_dir) / f"{artifact_stem}.windows.yaml",
                {
                    "vtable_entries": {
                        56: "0x1803a75c0",
                    }
                },
            )

            with patch.object(
                ida_analyze_util,
                "_get_func_basic_info_via_mcp",
                AsyncMock(return_value={"func_size": "0x40"}),
            ), patch.object(
                ida_analyze_util,
                "preprocess_vtable_via_mcp",
                AsyncMock(return_value=None),
            ) as mock_preprocess_vtable:
                result = await ida_analyze_util._preprocess_direct_func_sig_via_mcp(
                    session=AsyncMock(),
                    new_path=str(Path(temp_dir) / "Foo.windows.yaml"),
                    image_base=0x180000000,
                    platform="windows",
                    func_name="Foo",
                    direct_vtable_class=artifact_stem,
                    direct_vfunc_offset="0x1c0",
                    debug=True,
                )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("0x1803a75c0", result["func_va"])
        self.assertEqual(56, result["vfunc_index"])
        self.assertEqual(artifact_stem, result["vtable_name"])
        mock_preprocess_vtable.assert_not_awaited()

    async def test_preprocess_func_xrefs_reads_artifact_stem_vtable_yaml(self) -> None:
        with patch.object(
            ida_analyze_util,
            "_load_symbol_addr_from_current_yaml",
            return_value=0x180200000,
        ) as mock_load_symbol, patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_ea",
            AsyncMock(return_value=set()),
        ) as mock_collect_ea, patch.object(
            ida_analyze_util,
            "_read_yaml_file",
            return_value={
                "vtable_entries": {
                    0: "0x180200000",
                    1: "0x180300000",
                }
            },
        ) as mock_read_yaml, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="CLoopModeGame_LoopInit",
                xref_strings=[],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=["CLoopModeGame_LoopInitInternal"],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                new_binary_dir="bin_dir",
                platform="linux",
                image_base=0x180000000,
                vtable_class="CLoopModeGame_vtable2",
                debug=True,
            )

        self.assertIsNotNone(result)
        mock_collect_ea.assert_awaited_once_with(
            session="session",
            target_ea=0x180200000,
            debug=True,
        )
        mock_read_yaml.assert_called_once_with(
            str(Path("bin_dir") / "CLoopModeGame_vtable2.linux.yaml")
        )
        self.assertEqual(0x180200000, mock_gen_sig.await_args.kwargs["func_va"])
        mock_load_symbol.assert_called_once()


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

    async def test_normalize_generate_yaml_desired_fields_parses_vfunc_sig_max_match_directive(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "func_name",
                        "vfunc_sig",
                        "vfunc_sig_max_match:10",
                    ],
                )
            ],
            debug=True,
        )

        self.assertEqual(
            {
                "Foo": {
                    "desired_output_fields": [
                        "func_name",
                        "vfunc_sig",
                        "vfunc_sig_max_match",
                    ],
                    "generation_options": {
                        "vfunc_sig_max_match": 10,
                    },
                }
            },
            result,
        )

    async def test_normalize_generate_yaml_desired_fields_rejects_vfunc_sig_max_match_without_vfunc_sig(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "func_name",
                        "vfunc_sig_max_match:10",
                    ],
                )
            ],
            debug=True,
        )

        self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_invalid_vfunc_sig_max_match_value(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "func_name",
                        "vfunc_sig",
                        "vfunc_sig_max_match:abc",
                    ],
                )
            ],
            debug=True,
        )

        self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_bare_vfunc_sig_max_match_field(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "func_name",
                        "vfunc_sig",
                        "vfunc_sig_max_match",
                    ],
                )
            ],
            debug=True,
        )

        self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_duplicate_vfunc_sig_max_match_directive(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "func_name",
                        "vfunc_sig",
                        "vfunc_sig_max_match:10",
                        "vfunc_sig_max_match:12",
                    ],
                )
            ],
            debug=True,
        )

        self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_zero_vfunc_sig_max_match_value(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "func_name",
                        "vfunc_sig",
                        "vfunc_sig_max_match:0",
                    ],
                )
            ],
            debug=True,
        )

        self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_negative_vfunc_sig_max_match_value(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "func_name",
                        "vfunc_sig",
                        "vfunc_sig_max_match:-1",
                    ],
                )
            ],
            debug=True,
        )

        self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_bare_gv_boundary_flag(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "gv_sig",
                        "gv_sig_allow_across_function_boundary",
                    ],
                )
            ],
            debug=True,
        )

        self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_invalid_gv_boundary_flag_value(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "gv_sig",
                        "gv_sig_allow_across_function_boundary: false",
                    ],
                )
            ],
            debug=True,
        )

        self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_duplicate_gv_boundary_flag(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "gv_sig",
                        "gv_sig_allow_across_function_boundary: true",
                        "gv_sig_allow_across_function_boundary: true",
                    ],
                )
            ],
            debug=True,
        )

        self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_parses_signature_boundary_flags(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "func_name",
                        "func_sig_allow_across_function_boundary: true",
                        "vfunc_sig",
                        "vfunc_sig_allow_across_function_boundary: true",
                        "gv_sig",
                        "gv_sig_allow_across_function_boundary: true",
                        "offset_sig",
                        "offset_sig_allow_across_function_boundary: true",
                    ],
                )
            ],
            debug=True,
        )

        self.assertEqual(
            {
                "Foo": {
                    "desired_output_fields": [
                        "func_name",
                        "func_sig_allow_across_function_boundary",
                        "vfunc_sig",
                        "vfunc_sig_allow_across_function_boundary",
                        "gv_sig",
                        "gv_sig_allow_across_function_boundary",
                        "offset_sig",
                        "offset_sig_allow_across_function_boundary",
                    ],
                    "generation_options": {
                        "func_sig_allow_across_function_boundary": True,
                        "vfunc_sig_allow_across_function_boundary": True,
                        "gv_sig_allow_across_function_boundary": True,
                        "offset_sig_allow_across_function_boundary": True,
                    },
                }
            },
            result,
        )

    async def test_normalize_generate_yaml_desired_fields_rejects_bare_signature_boundary_flags(
        self,
    ) -> None:
        bare_specs = [
            ("func_name", "func_sig_allow_across_function_boundary"),
            ("vfunc_sig", "vfunc_sig_allow_across_function_boundary"),
            ("offset_sig", "offset_sig_allow_across_function_boundary"),
        ]

        for leading_field, bare_flag in bare_specs:
            with self.subTest(bare_flag=bare_flag):
                result = ida_analyze_util._normalize_generate_yaml_desired_fields(
                    [("Foo", [leading_field, bare_flag])],
                    debug=True,
                )
                self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_invalid_signature_boundary_flag_values(
        self,
    ) -> None:
        invalid_specs = [
            ("func_name", "func_sig_allow_across_function_boundary: false"),
            ("vfunc_sig", "vfunc_sig_allow_across_function_boundary: false"),
            ("offset_sig", "offset_sig_allow_across_function_boundary: false"),
        ]

        for leading_field, invalid_flag in invalid_specs:
            with self.subTest(invalid_flag=invalid_flag):
                result = ida_analyze_util._normalize_generate_yaml_desired_fields(
                    [("Foo", [leading_field, invalid_flag])],
                    debug=True,
                )
                self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_duplicate_signature_boundary_flags(
        self,
    ) -> None:
        duplicate_specs = [
            (
                "func_name",
                "func_sig_allow_across_function_boundary: true",
            ),
            (
                "vfunc_sig",
                "vfunc_sig_allow_across_function_boundary: true",
            ),
            (
                "offset_sig",
                "offset_sig_allow_across_function_boundary: true",
            ),
        ]

        for leading_field, allow_flag in duplicate_specs:
            with self.subTest(allow_flag=allow_flag):
                result = ida_analyze_util._normalize_generate_yaml_desired_fields(
                    [("Foo", [leading_field, allow_flag, allow_flag])],
                    debug=True,
                )
                self.assertIsNone(result)

    async def test_preprocess_common_skill_writes_func_and_vfunc_boundary_flags(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "Foo",
                    "func_sig": "AA BB",
                    "vfunc_sig": "48 89 5C 24 ? ? 57",
                    "vfunc_sig_max_match": 10,
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
                session="session",
                expected_outputs=["/tmp/Foo.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                func_names=["Foo"],
                generate_yaml_desired_fields=[
                    (
                        "Foo",
                        [
                            "func_name",
                            "func_sig",
                            "func_sig_allow_across_function_boundary: true",
                            "vfunc_sig",
                            "vfunc_sig_max_match:10",
                            "vfunc_sig_allow_across_function_boundary: true",
                        ],
                    )
                ],
                debug=True,
            )

        self.assertTrue(result)
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(
            [
                "func_name",
                "func_sig",
                "func_sig_allow_across_function_boundary",
                "vfunc_sig",
                "vfunc_sig_max_match",
                "vfunc_sig_allow_across_function_boundary",
            ],
            list(written_payload.keys()),
        )
        self.assertEqual(
            {
                "func_name": "Foo",
                "func_sig": "AA BB",
                "func_sig_allow_across_function_boundary": True,
                "vfunc_sig": "48 89 5C 24 ? ? 57",
                "vfunc_sig_max_match": 10,
                "vfunc_sig_allow_across_function_boundary": True,
            },
            written_payload,
        )

    async def test_preprocess_common_skill_writes_offset_sig_boundary_flag(
        self,
    ) -> None:
        struct_member_name = "CActor_m_iHealth"

        with patch.object(
            ida_analyze_util,
            "preprocess_struct_offset_sig_via_mcp",
            AsyncMock(
                return_value={
                    "struct_name": "CActor",
                    "member_name": "m_iHealth",
                    "offset": "0x10",
                    "size": 4,
                    "offset_sig": "49 8B 4E ??",
                    "offset_sig_disp": 0,
                }
            ),
        ), patch.object(
            ida_analyze_util,
            "write_struct_offset_yaml",
        ) as mock_write_struct_offset_yaml:
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=[f"/tmp/{struct_member_name}.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                struct_member_names=[struct_member_name],
                generate_yaml_desired_fields=[
                    (
                        struct_member_name,
                        [
                            "struct_name",
                            "member_name",
                            "offset",
                            "size",
                            "offset_sig",
                            "offset_sig_disp",
                            "offset_sig_allow_across_function_boundary: true",
                        ],
                    )
                ],
                debug=True,
            )

        self.assertTrue(result)
        mock_write_struct_offset_yaml.assert_called_once()
        written_payload = mock_write_struct_offset_yaml.call_args.args[1]
        self.assertEqual(
            [
                "struct_name",
                "member_name",
                "offset",
                "size",
                "offset_sig",
                "offset_sig_disp",
                "offset_sig_allow_across_function_boundary",
            ],
            list(written_payload.keys()),
        )
        self.assertEqual(
            {
                "struct_name": "CActor",
                "member_name": "m_iHealth",
                "offset": "0x10",
                "size": 4,
                "offset_sig": "49 8B 4E ??",
                "offset_sig_disp": 0,
                "offset_sig_allow_across_function_boundary": True,
            },
            written_payload,
        )

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

    async def test_preprocess_common_skill_writes_vfunc_sig_max_match_field(
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
                    "vfunc_sig": "48 89 5C 24 ? ? 57",
                    "vfunc_sig_max_match": 10,
                    "vtable_name": "Bar",
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
                session="session",
                expected_outputs=["/tmp/Foo.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                func_names=["Foo"],
                generate_yaml_desired_fields=[
                    (
                        "Foo",
                        [
                            "vfunc_sig_max_match:10",
                            "func_name",
                            "vfunc_sig",
                        ],
                    )
                ],
                debug=True,
            )

        self.assertTrue(result)
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(
            ["func_name", "vfunc_sig", "vfunc_sig_max_match"],
            list(written_payload.keys()),
        )
        self.assertEqual(
            {
                "func_name": "Foo",
                "vfunc_sig": "48 89 5C 24 ? ? 57",
                "vfunc_sig_max_match": 10,
            },
            written_payload,
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


class TestIdaStringEnumerationSupport(unittest.TestCase):
    def test_resolve_ida_string_min_length_config_skips_setup_when_unset_or_blank(
        self,
    ) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(
                ida_analyze_util._resolve_ida_string_min_length_config()
            )

        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": ""},
            clear=True,
        ):
            self.assertIsNone(
                ida_analyze_util._resolve_ida_string_min_length_config()
            )

        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "   "},
            clear=True,
        ):
            self.assertIsNone(
                ida_analyze_util._resolve_ida_string_min_length_config()
            )

    def test_resolve_ida_string_min_length_config_handles_invalid_zero_and_valid_value(
        self,
    ) -> None:
        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "invalid"},
            clear=True,
        ):
            self.assertEqual(
                4,
                ida_analyze_util._resolve_ida_string_min_length_config(),
            )

        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "0"},
            clear=True,
        ):
            self.assertEqual(
                4,
                ida_analyze_util._resolve_ida_string_min_length_config(),
            )

        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "6"},
            clear=True,
        ):
            self.assertEqual(
                6,
                ida_analyze_util._resolve_ida_string_min_length_config(),
            )

    def test_build_ida_strings_enumerator_py_lines_skips_setup_by_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            py_lines = ida_analyze_util._build_ida_strings_enumerator_py_lines()

        self.assertEqual(
            ["strings = idautils.Strings(default_setup=False)"],
            py_lines,
        )

    def test_build_ida_strings_enumerator_py_lines_skips_setup_for_blank_env(
        self,
    ) -> None:
        with patch.dict(
            os.environ,
            {ida_analyze_util.IDA_STRING_MIN_LENGTH_ENV_VAR: " "},
            clear=True,
        ):
            py_lines = ida_analyze_util._build_ida_strings_enumerator_py_lines()

        self.assertEqual(
            ["strings = idautils.Strings(default_setup=False)"],
            py_lines,
        )

    def test_build_ida_strings_enumerator_py_lines_uses_netnode_guard_for_env_min_length(
        self,
    ) -> None:
        with patch.dict(
            os.environ,
            {ida_analyze_util.IDA_STRING_MIN_LENGTH_ENV_VAR: "8"},
            clear=True,
        ):
            py_lines = ida_analyze_util._build_ida_strings_enumerator_py_lines()

        code = "\n".join(py_lines)
        self.assertIn("import ida_netnode, json", code)
        self.assertIn("strings = idautils.Strings(default_setup=False)", code)
        self.assertIn(
            "CS2VIBE_STRING_SETUP_STATE_NODE = '$CS2VIBE_STRING_SETUP_STATE'",
            code,
        )
        self.assertIn(
            "expected_state = {'version': 1, 'minlen': 8, 'strtypes': 'STRTYPE_C'}",
            code,
        )
        self.assertIn("globals().update(locals())", code)
        self.assertIn(
            "if _cs2vibe_read_string_setup_state() != expected_state:",
            code,
        )
        self.assertIn(
            "    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=8)",
            code,
        )
        self.assertIn(
            "    _cs2vibe_write_string_setup_state(expected_state)",
            code,
        )

    def test_build_ida_strings_enumerator_py_lines_exec_with_split_globals_and_locals(
        self,
    ) -> None:
        py_code = "\n".join(
            ida_analyze_util._build_ida_strings_enumerator_py_lines(min_length=6)
        )
        state_store = {"payload": None}
        strings_instances = []

        class FakeStrings:
            def __init__(self, default_setup=False) -> None:
                self.default_setup = default_setup
                self.setup_calls = []
                strings_instances.append(self)

            def setup(self, *, strtypes, minlen) -> None:
                self.setup_calls.append(
                    {
                        "strtypes": strtypes,
                        "minlen": minlen,
                    }
                )

            def __iter__(self):
                return iter(())

        class FakeNetnode:
            def valobj(self):
                return state_store["payload"]

            def set(self, payload) -> None:
                state_store["payload"] = payload

        def _make_node(name, _unused_zero, _unused_create):
            self.assertEqual(ida_analyze_util.IDA_STRING_SETUP_STATE_NODE, name)
            return FakeNetnode()

        fake_ida_netnode = types.ModuleType("ida_netnode")
        fake_ida_netnode.netnode = _make_node
        fake_idautils = types.SimpleNamespace(Strings=FakeStrings)
        fake_ida_nalt = types.SimpleNamespace(STRTYPE_C="STRTYPE_C")

        def _run_generated_code() -> None:
            exec_globals = {
                "__builtins__": __builtins__,
                "idautils": fake_idautils,
                "ida_nalt": fake_ida_nalt,
            }
            exec_locals = {}
            with patch.dict(sys.modules, {"ida_netnode": fake_ida_netnode}):
                exec(py_code, exec_globals, exec_locals)

        _run_generated_code()
        self.assertEqual(1, len(strings_instances))
        self.assertFalse(strings_instances[0].default_setup)
        self.assertEqual(
            [{"strtypes": ["STRTYPE_C"], "minlen": 6}],
            strings_instances[0].setup_calls,
        )
        self.assertEqual(
            {"version": 1, "minlen": 6, "strtypes": "STRTYPE_C"},
            json.loads(state_store["payload"]),
        )

        _run_generated_code()
        self.assertEqual(2, len(strings_instances))
        self.assertEqual([], strings_instances[1].setup_calls)

    def test_build_ida_strings_enumerator_py_lines_supports_explicit_none(self) -> None:
        with patch.dict(
            os.environ,
            {ida_analyze_util.IDA_STRING_MIN_LENGTH_ENV_VAR: "8"},
            clear=True,
        ):
            py_lines = ida_analyze_util._build_ida_strings_enumerator_py_lines(
                min_length=None,
            )

        self.assertEqual(
            ["strings = idautils.Strings(default_setup=False)"],
            py_lines,
        )

    def test_build_ida_strings_enumerator_py_lines_supports_custom_var_name(
        self,
    ) -> None:
        with patch.dict(os.environ, {}, clear=True):
            py_lines = ida_analyze_util._build_ida_strings_enumerator_py_lines(
                min_length=6,
                strings_var_name="ida_strings",
            )

        code = "\n".join(py_lines)
        self.assertIn("ida_strings = idautils.Strings(default_setup=False)", code)
        self.assertIn(
            "ida_strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)",
            code,
        )

    def test_build_ida_exact_string_index_py_lines_skips_setup_by_default(
        self,
    ) -> None:
        with patch.dict(os.environ, {}, clear=True):
            py_lines = ida_analyze_util._build_ida_exact_string_index_py_lines()

        self.assertEqual(
            [
                "exact_string_hits = {text: [] for text in target_strings if text}",
                "strings = idautils.Strings(default_setup=False)",
                "for item in strings:",
                "    try:",
                "        text = str(item)",
                "        ea = int(item.ea)",
                "    except Exception:",
                "        continue",
                "    if text in exact_string_hits:",
                "        exact_string_hits[text].append(ea)",
            ],
            py_lines,
        )

    def test_build_ida_exact_string_index_py_lines_reads_env_min_length(self) -> None:
        with patch.dict(
            os.environ,
            {ida_analyze_util.IDA_STRING_MIN_LENGTH_ENV_VAR: "8"},
            clear=True,
        ):
            py_lines = ida_analyze_util._build_ida_exact_string_index_py_lines()

        code = "\n".join(py_lines)
        self.assertIn(
            "exact_string_hits = {text: [] for text in target_strings if text}",
            code,
        )
        self.assertIn("strings = idautils.Strings(default_setup=False)", code)
        self.assertIn(
            "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=8)",
            code,
        )
        self.assertIn("for item in strings:", code)
        self.assertEqual(1, code.count("for item in strings:"))

    def test_build_ida_exact_string_index_py_lines_supports_custom_var_names(
        self,
    ) -> None:
        with patch.dict(os.environ, {}, clear=True):
            py_lines = ida_analyze_util._build_ida_exact_string_index_py_lines(
                target_texts_var_name="target_texts",
                result_var_name="result_map",
                min_length=6,
            )

        code = "\n".join(py_lines)
        self.assertIn("result_map = {text: [] for text in target_texts if text}", code)
        self.assertIn("strings = idautils.Strings(default_setup=False)", code)
        self.assertIn(
            "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)",
            code,
        )
        self.assertIn("for item in strings:", code)
        self.assertIn("    if text in result_map:", code)
        self.assertIn("        result_map[text].append(ea)", code)


class TestFuncXrefsSignatureSupport(unittest.IsolatedAsyncioTestCase):
    async def test_collect_xref_func_starts_for_string_uses_substring_by_default(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(["0x180001123"])

        with patch.object(
            ida_analyze_util,
            "_normalize_func_starts_for_code_addrs",
            AsyncMock(return_value={0x180001000}),
        ) as mock_normalize:
            result = await ida_analyze_util._collect_xref_func_starts_for_string(
                session=session,
                xref_string="_projectile",
                debug=True,
            )

        self.assertEqual({0x180001000}, result)
        session.call_tool.assert_awaited_once()
        mock_normalize.assert_awaited_once_with(
            session=session,
            code_addrs={0x180001123},
            debug=True,
        )
        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn("import ida_nalt, idautils, json", py_code)
        self.assertIn("strings = idautils.Strings(default_setup=False)", py_code)
        self.assertNotIn("strings.setup(", py_code)
        self.assertNotIn("ida_netnode", py_code)
        self.assertIn("for s in strings:", py_code)
        self.assertNotIn("for s in idautils.Strings():", py_code)
        self.assertIn('search_str = "_projectile"', py_code)
        self.assertIn("if search_str in current_str:", py_code)
        self.assertNotIn("if current_str == search_str:", py_code)

    async def test_collect_xref_func_starts_for_string_supports_fullmatch_prefix(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(["0x180001123"])

        with patch.object(
            ida_analyze_util,
            "_normalize_func_starts_for_code_addrs",
            AsyncMock(return_value={0x180001000}),
        ) as mock_normalize:
            result = await ida_analyze_util._collect_xref_func_starts_for_string(
                session=session,
                xref_string="FULLMATCH:_projectile",
                debug=True,
            )

        self.assertEqual({0x180001000}, result)
        session.call_tool.assert_awaited_once()
        mock_normalize.assert_awaited_once_with(
            session=session,
            code_addrs={0x180001123},
            debug=True,
        )
        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn('search_str = "_projectile"', py_code)
        self.assertIn("if current_str == search_str:", py_code)
        self.assertNotIn("if search_str in current_str:", py_code)
        self.assertNotIn("FULLMATCH:_projectile", py_code)

    async def test_collect_xref_func_starts_for_string_reads_env_min_length(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(["0x180001123"])

        with (
            patch.dict(
                os.environ,
                {ida_analyze_util.IDA_STRING_MIN_LENGTH_ENV_VAR: "6"},
                clear=True,
            ),
            patch.object(
                ida_analyze_util,
                "_normalize_func_starts_for_code_addrs",
                AsyncMock(return_value={0x180001000}),
            ) as mock_normalize,
        ):
            result = await ida_analyze_util._collect_xref_func_starts_for_string(
                session=session,
                xref_string="_projectile",
                debug=False,
            )

        self.assertEqual({0x180001000}, result)
        mock_normalize.assert_awaited_once_with(
            session=session,
            code_addrs={0x180001123},
            debug=False,
        )
        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn("import ida_netnode, json", py_code)
        self.assertIn("CS2VIBE_STRING_SETUP_STATE_NODE", py_code)
        self.assertIn(
            "expected_state = {'version': 1, 'minlen': 6, 'strtypes': 'STRTYPE_C'}",
            py_code,
        )
        self.assertIn(
            "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)",
            py_code,
        )
        self.assertIn("_cs2vibe_write_string_setup_state(expected_state)", py_code)

    async def test_collect_xref_func_starts_for_string_normalizes_raw_xref_from_addrs(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            ["0x180001123", "0x180001456", "invalid", "0x180001123"]
        )

        with patch.object(
            ida_analyze_util,
            "_normalize_func_starts_for_code_addrs",
            AsyncMock(return_value={0x180001000, 0x180002000}),
        ) as mock_normalize:
            result = await ida_analyze_util._collect_xref_func_starts_for_string(
                session=session,
                xref_string="_projectile",
                debug=True,
            )

        self.assertEqual({0x180001000, 0x180002000}, result)
        mock_normalize.assert_awaited_once_with(
            session=session,
            code_addrs={0x180001123, 0x180001456},
            debug=True,
        )
        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn("code_addrs = set()", py_code)
        self.assertIn("code_addrs.add(xref.frm)", py_code)
        self.assertNotIn("idaapi.get_func(xref.frm)", py_code)

    async def test_collect_xref_func_starts_for_ea_normalizes_raw_xref_from_addrs(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            ["0x180010123", "0x180010456", "bad-value", "0x180010123"]
        )

        with patch.object(
            ida_analyze_util,
            "_normalize_func_starts_for_code_addrs",
            AsyncMock(return_value={0x180010000}),
        ) as mock_normalize:
            result = await ida_analyze_util._collect_xref_func_starts_for_ea(
                session=session,
                target_ea="0x1800ABCDEF",
                debug=True,
            )

        self.assertEqual({0x180010000}, result)
        mock_normalize.assert_awaited_once_with(
            session=session,
            code_addrs={0x180010123, 0x180010456},
            debug=True,
        )
        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn("code_addrs = set()", py_code)
        self.assertIn("code_addrs.add(xref.frm)", py_code)
        self.assertNotIn("idaapi.get_func(xref.frm)", py_code)

    async def test_collect_xref_func_starts_for_signature_normalizes_match_addrs_directly(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _FakeCallToolResult(
            [{"matches": ["0x180020123", "0x180020456", "oops", "0x180020123"]}]
        )

        with patch.object(
            ida_analyze_util,
            "_normalize_func_starts_for_code_addrs",
            AsyncMock(return_value={0x180020000}),
        ) as mock_normalize:
            result = await ida_analyze_util._collect_xref_func_starts_for_signature(
                session=session,
                xref_signature="48 8B ?? ??",
                debug=True,
            )

        self.assertEqual({0x180020000}, result)
        session.call_tool.assert_awaited_once_with(
            name="find_bytes",
            arguments={"patterns": ["48 8B ?? ??"]},
        )
        mock_normalize.assert_awaited_once_with(
            session=session,
            code_addrs={0x180020123, 0x180020456},
            debug=True,
        )

    async def test_func_contains_signature_via_mcp_uses_ida_bytes_find_bytes(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload({"contains": True})

        result = await ida_analyze_util._func_contains_signature_via_mcp(
            session=session,
            func_va="0x180020000",
            signature="48 8B ?? ??",
            debug=True,
        )

        self.assertTrue(result)
        session.call_tool.assert_awaited_once()
        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn("import idaapi, ida_bytes, json", py_code)
        self.assertIn("ida_bytes.find_bytes(", py_code)
        self.assertIn("range_end=func.end_ea", py_code)
        self.assertNotIn("ida_search.find_binary", py_code)

    async def test_normalize_func_start_returns_existing_function(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {"status": "resolved", "func_start": "0x180001000"}
        )

        result = await ida_analyze_util._normalize_func_start_for_code_addr(
            session=session,
            code_addr=0x180001020,
            debug=True,
        )

        self.assertEqual(0x180001000, result)
        session.call_tool.assert_awaited_once()
        self.assertEqual("py_eval", session.call_tool.await_args.kwargs["name"])

    async def test_normalize_func_start_defines_unique_entry_candidate(self) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = [
            _py_eval_payload({"status": "needs_define", "entry": "0x180001000"}),
            _FakeCallToolResult({"ok": True}),
            _py_eval_payload({"status": "resolved", "func_start": "0x180001000"}),
        ]

        result = await ida_analyze_util._normalize_func_start_for_code_addr(
            session=session,
            code_addr=0x180001050,
            debug=True,
        )

        self.assertEqual(0x180001000, result)
        self.assertEqual(3, session.call_tool.await_count)
        define_call = session.call_tool.await_args_list[1]
        self.assertEqual("define_func", define_call.kwargs["name"])
        self.assertEqual(
            {"items": {"addr": "0x180001000"}},
            define_call.kwargs["arguments"],
        )

    async def test_normalize_func_start_returns_none_when_define_does_not_cover_code_addr(
        self,
    ) -> None:
        session = AsyncMock()

        with patch.object(
            ida_analyze_util,
            "_probe_func_start_or_entry_candidate",
            AsyncMock(return_value={"status": "needs_define", "entry": "0x180001000"}),
        ), patch.object(
            ida_analyze_util,
            "_read_covering_func_start_via_mcp",
            AsyncMock(return_value=None),
        ) as mock_read_covering:
            result = await ida_analyze_util._normalize_func_start_for_code_addr(
                session=session,
                code_addr=0x180001050,
                debug=True,
            )

        self.assertIsNone(result)
        session.call_tool.assert_awaited_once_with(
            name="define_func",
            arguments={"items": {"addr": "0x180001000"}},
        )
        mock_read_covering.assert_awaited_once_with(
            session=session,
            code_addr=0x180001050,
            debug=True,
        )

    async def test_normalize_func_start_skips_multiple_entry_candidates(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "status": "multiple_entries",
                "entries": ["0x180001000", "0x180001020"],
            }
        )

        result = await ida_analyze_util._normalize_func_start_for_code_addr(
            session=session,
            code_addr=0x180001050,
            debug=True,
        )

        self.assertIsNone(result)
        session.call_tool.assert_awaited_once()

    async def test_normalize_func_start_skips_existing_function_collision(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "status": "blocked_existing_function",
                "func_start": "0x180000F00",
            }
        )

        result = await ida_analyze_util._normalize_func_start_for_code_addr(
            session=session,
            code_addr=0x180001050,
            debug=True,
        )

        self.assertIsNone(result)
        session.call_tool.assert_awaited_once()

    async def test_probe_func_start_preserves_candidates_before_existing_function(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload({"status": "no_entry"})

        await ida_analyze_util._probe_func_start_or_entry_candidate(
            session=session,
            code_addr=0x180001050,
            debug=True,
        )

        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertRegex(
            py_code,
            r"if other_func:\n"
            r"\s+if candidates:\n"
            r"\s+break\n"
            r"\s+result_obj = \{\n"
            r"\s+'status': 'blocked_existing_function'",
        )

    async def test_normalize_func_start_probe_uses_conservative_filters(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload({"status": "no_entry"})

        await ida_analyze_util._normalize_func_start_for_code_addr(
            session=session,
            code_addr=0x180001050,
            debug=True,
        )

        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn("0x200", py_code)
        self.assertIn("'call'", py_code)
        self.assertIn("'jmp'", py_code)
        self.assertIn("'lea'", py_code)
        self.assertIn("ref_func = idaapi.get_func(xref.frm)", py_code)
        self.assertNotIn("result_obj = {'status': 'needs_define', 'entry': hex(code_addr)}", py_code)

    async def test_normalize_func_start_returns_none_for_invalid_py_eval_payloads(
        self,
    ) -> None:
        payloads = [
            _FakeCallToolResult(["not-a-dict"]),
            _FakeCallToolResult({"result": "not-json", "stdout": "", "stderr": ""}),
            _FakeCallToolResult({"result": json.dumps(["not-a-dict"]), "stdout": "", "stderr": ""}),
        ]

        for payload in payloads:
            with self.subTest(payload=payload.content[0].text):
                session = AsyncMock()
                session.call_tool.return_value = payload

                result = await ida_analyze_util._normalize_func_start_for_code_addr(
                    session=session,
                    code_addr=0x180001050,
                    debug=True,
                )

                self.assertIsNone(result)
                session.call_tool.assert_awaited_once()

    def test_parse_int_set_from_py_eval_returns_none_for_non_list_payload(self) -> None:
        result = ida_analyze_util._parse_int_set_from_py_eval(
            {
                "result": json.dumps({"func_start": "0x180001000"}),
                "stdout": "",
                "stderr": "",
            },
            debug=True,
        )

        self.assertIsNone(result)

    async def test_normalize_func_starts_for_code_addrs_deduplicates_and_filters_none(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_normalize_func_start_for_code_addr",
            AsyncMock(side_effect=[0x180001000, None, 0x180001000, 0x180002000]),
        ) as mock_normalize:
            result = await ida_analyze_util._normalize_func_starts_for_code_addrs(
                session="session",
                code_addrs=[0x180001030, 0x180001010, 0x180001020, 0x180001040],
                debug=True,
            )

        self.assertEqual({0x180001000, 0x180002000}, result)
        self.assertEqual(
            [
                call(session="session", code_addr=0x180001010, debug=True),
                call(session="session", code_addr=0x180001020, debug=True),
                call(session="session", code_addr=0x180001030, debug=True),
                call(session="session", code_addr=0x180001040, debug=True),
            ],
            mock_normalize.await_args_list,
        )

    async def test_filter_func_addrs_by_float_xrefs_keeps_xref_matches_and_excludes_hits(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "0x180100000": {
                    "constants": [
                        {
                            "inst_ea": "0x180100010",
                            "const_ea": "0x181000000",
                            "kind": "float",
                            "value": 64.0,
                        }
                    ],
                    "xref_hit": True,
                    "exclude_hit": False,
                },
                "0x180200000": {
                    "constants": [
                        {
                            "inst_ea": "0x180200010",
                            "const_ea": "0x181000004",
                            "kind": "float",
                            "value": 1.0,
                        }
                    ],
                    "xref_hit": False,
                    "exclude_hit": False,
                },
                "0x180300000": {
                    "constants": [
                        {
                            "inst_ea": "0x180300010",
                            "const_ea": "0x181000008",
                            "kind": "float",
                            "value": 0.5,
                        }
                    ],
                    "xref_hit": True,
                    "exclude_hit": True,
                },
            }
        )

        result = await ida_analyze_util._filter_func_addrs_by_float_xrefs_via_mcp(
            session=session,
            func_addrs={0x180100000, 0x180200000, 0x180300000},
            xref_floats=["64.0", "0.5"],
            exclude_floats=["0.5"],
            debug=True,
        )

        self.assertEqual({0x180100000}, result)
        session.call_tool.assert_awaited_once()
        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn('struct.unpack("<f"', py_code)
        self.assertIn('struct.unpack("<d"', py_code)
        self.assertIn('seg_name == ".rdata"', py_code)
        self.assertIn('seg_name.startswith(".rodata")', py_code)
        self.assertIn('"mulss"', py_code)
        self.assertIn('"mulsd"', py_code)
        self.assertIn('"vmulss"', py_code)
        self.assertIn('"vmulsd"', py_code)
        self.assertIn("globals().update(locals())", py_code)

    async def test_filter_func_addrs_by_float_xrefs_fails_closed_on_invalid_payload(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(["not-a-dict"])

        result = await ida_analyze_util._filter_func_addrs_by_float_xrefs_via_mcp(
            session=session,
            func_addrs={0x180100000},
            xref_floats=["64.0"],
            exclude_floats=[],
            debug=True,
        )

        self.assertIsNone(result)
        session.call_tool.assert_awaited_once()

    async def test_filter_func_addrs_by_float_xrefs_fails_closed_on_non_finite_values(
        self,
    ) -> None:
        cases = [
            (["nan"], []),
            (["64.0"], ["inf"]),
        ]
        for xref_floats, exclude_floats in cases:
            with self.subTest(xref_floats=xref_floats, exclude_floats=exclude_floats):
                session = AsyncMock()

                result = await ida_analyze_util._filter_func_addrs_by_float_xrefs_via_mcp(
                    session=session,
                    func_addrs={0x180100000},
                    xref_floats=xref_floats,
                    exclude_floats=exclude_floats,
                    debug=True,
                )

                self.assertIsNone(result)
                session.call_tool.assert_not_awaited()

    async def test_filter_func_addrs_by_float_xrefs_fails_closed_on_malformed_entry(
        self,
    ) -> None:
        payloads = [
            {
                "0x180100000": {
                    "constants": [],
                    "xref_hit": "false",
                    "exclude_hit": False,
                }
            },
            {
                "0x180100000": {
                    "constants": [],
                    "xref_hit": True,
                }
            },
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                session = AsyncMock()
                session.call_tool.return_value = _py_eval_payload(payload)

                result = await ida_analyze_util._filter_func_addrs_by_float_xrefs_via_mcp(
                    session=session,
                    func_addrs={0x180100000},
                    xref_floats=["64.0"],
                    exclude_floats=[],
                    debug=True,
                )

                self.assertIsNone(result)
                session.call_tool.assert_awaited_once()

    async def test_preprocess_func_xrefs_intersects_string_and_signature_sets(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180100000, 0x180200000}),
        ) as mock_collect_string, patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_signature",
            AsyncMock(return_value={0x180100000}),
        ) as mock_collect_signature, patch.object(
            ida_analyze_util,
            "_func_contains_signature_via_mcp",
            AsyncMock(side_effect=[False, True]),
        ) as mock_func_contains_signature, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=["Networking"],
                xref_gvs=[],
                xref_signatures=["C7 44 24 40 64 FF FF FF"],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertEqual(
            {
                "func_name": "LoggingChannel_Init",
                "func_va": "0x180200000",
                "func_rva": "0x200000",
                "func_size": "0x40",
                "func_sig": "48 89 5C 24 08",
            },
            result,
        )
        mock_collect_string.assert_awaited_once_with(
            session="session",
            xref_string="Networking",
            debug=True,
        )
        mock_collect_signature.assert_not_called()
        mock_func_contains_signature.assert_has_awaits(
            [
                call(
                    session="session",
                    func_va=0x180100000,
                    signature="C7 44 24 40 64 FF FF FF",
                    debug=True,
                ),
                call(
                    session="session",
                    func_va=0x180200000,
                    signature="C7 44 24 40 64 FF FF FF",
                    debug=True,
                ),
            ]
        )
        mock_gen_sig.assert_awaited_once()

    async def test_preprocess_func_xrefs_intersects_string_and_gv_sets(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180100000, 0x180200000}),
        ) as mock_collect_string, patch.object(
            ida_analyze_util,
            "_load_symbol_addr_from_current_yaml",
            return_value=0x18000F000,
        ) as mock_load_symbol, patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_ea",
            AsyncMock(return_value={0x180200000}),
        ) as mock_collect_ea, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=["Networking"],
                xref_gvs=["g_NetworkingState"],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertEqual("0x180200000", result["func_va"])
        mock_collect_string.assert_awaited_once_with(
            session="session",
            xref_string="Networking",
            debug=True,
        )
        mock_load_symbol.assert_called_once_with(
            "bin_dir",
            "windows",
            "g_NetworkingState",
            "gv_va",
            debug=True,
            debug_label="xref_gv",
        )
        mock_collect_ea.assert_awaited_once_with(
            session="session",
            target_ea=0x18000F000,
            debug=True,
        )
        mock_gen_sig.assert_awaited_once()

    async def test_preprocess_func_xrefs_accepts_literal_xref_gv_address(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_load_symbol_addr_from_current_yaml",
            return_value=0x18000F000,
        ) as mock_load_symbol, patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_ea",
            AsyncMock(return_value={0x180200000}),
        ) as mock_collect_ea, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=[],
                xref_gvs=["0x18000F000"],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                new_binary_dir=None,
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertEqual("0x180200000", result["func_va"])
        mock_load_symbol.assert_not_called()
        mock_collect_ea.assert_awaited_once_with(
            session="session",
            target_ea=0x18000F000,
            debug=True,
        )
        mock_gen_sig.assert_awaited_once()

    async def test_preprocess_func_xrefs_exclude_gvs_subtracts_candidate_set(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180100000, 0x180200000}),
        ) as mock_collect_string, patch.object(
            ida_analyze_util,
            "_load_symbol_addr_from_current_yaml",
            return_value=0x18000F100,
        ) as mock_load_symbol, patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_ea",
            AsyncMock(return_value={0x180100000}),
        ) as mock_collect_ea, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=["Networking"],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=["g_ExcludeNetworkingState"],
                exclude_signatures=[],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertEqual("0x180200000", result["func_va"])
        mock_collect_string.assert_awaited_once_with(
            session="session",
            xref_string="Networking",
            debug=True,
        )
        mock_load_symbol.assert_called_once_with(
            "bin_dir",
            "windows",
            "g_ExcludeNetworkingState",
            "gv_va",
            debug=True,
            debug_label="exclude_gv",
        )
        mock_collect_ea.assert_awaited_once_with(
            session="session",
            target_ea=0x18000F100,
            debug=True,
        )
        mock_gen_sig.assert_awaited_once()

    async def test_preprocess_func_xrefs_accepts_literal_exclude_gv_address(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180100000, 0x180200000}),
        ) as mock_collect_string, patch.object(
            ida_analyze_util,
            "_load_symbol_addr_from_current_yaml",
            return_value=0x18000F100,
        ) as mock_load_symbol, patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_ea",
            AsyncMock(return_value={0x180100000}),
        ) as mock_collect_ea, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=["Networking"],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=["0x18000F100"],
                exclude_signatures=[],
                new_binary_dir=None,
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertEqual("0x180200000", result["func_va"])
        mock_collect_string.assert_awaited_once_with(
            session="session",
            xref_string="Networking",
            debug=True,
        )
        mock_load_symbol.assert_not_called()
        mock_collect_ea.assert_awaited_once_with(
            session="session",
            target_ea=0x18000F100,
            debug=True,
        )
        mock_gen_sig.assert_awaited_once()

    async def test_preprocess_func_xrefs_exclude_signatures_only_checks_remaining_candidates(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180100000, 0x180200000}),
        ) as mock_collect_string, patch.object(
            ida_analyze_util,
            "_load_symbol_addr_from_current_yaml",
            return_value=0x180100000,
        ) as mock_load_symbol, patch.object(
            ida_analyze_util,
            "_func_contains_signature_via_mcp",
            AsyncMock(return_value=False),
        ) as mock_func_contains_signature, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=["Networking"],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=["LoggingChannel_Shutdown"],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=["DE AD BE EF"],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertEqual("0x180200000", result["func_va"])
        mock_collect_string.assert_awaited_once_with(
            session="session",
            xref_string="Networking",
            debug=True,
        )
        mock_load_symbol.assert_called_once_with(
            "bin_dir",
            "windows",
            "LoggingChannel_Shutdown",
            "func_va",
            debug=True,
            debug_label="exclude_func",
        )
        mock_func_contains_signature.assert_awaited_once_with(
            session="session",
            func_va=0x180200000,
            signature="DE AD BE EF",
            debug=True,
        )
        mock_gen_sig.assert_awaited_once()

    async def test_preprocess_func_xrefs_exclude_signatures_fails_closed_on_probe_failure(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180100000, 0x180200000}),
        ), patch.object(
            ida_analyze_util,
            "_load_symbol_addr_from_current_yaml",
            return_value=0x180100000,
        ), patch.object(
            ida_analyze_util,
            "_func_contains_signature_via_mcp",
            AsyncMock(return_value=None),
        ) as mock_func_contains_signature, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(return_value=None),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=["Networking"],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=["LoggingChannel_Shutdown"],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=["DE AD BE EF"],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertIsNone(result)
        mock_func_contains_signature.assert_awaited_once_with(
            session="session",
            func_va=0x180200000,
            signature="DE AD BE EF",
            debug=True,
        )
        mock_gen_sig.assert_not_called()

    async def test_preprocess_func_xrefs_applies_float_filters_after_excludes(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180100000, 0x180200000}),
        ) as mock_collect_string, patch.object(
            ida_analyze_util,
            "_load_symbol_addr_from_current_yaml",
            return_value=0x180100000,
        ) as mock_load_symbol, patch.object(
            ida_analyze_util,
            "_filter_func_addrs_by_float_xrefs_via_mcp",
            AsyncMock(return_value={0x180200000}),
        ) as mock_float_filter, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=["Networking"],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=["LoggingChannel_Shutdown"],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                xref_floats=["64.0"],
                exclude_floats=[],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertEqual("0x180200000", result["func_va"])
        mock_collect_string.assert_awaited_once_with(
            session="session",
            xref_string="Networking",
            debug=True,
        )
        mock_load_symbol.assert_called_once_with(
            "bin_dir",
            "windows",
            "LoggingChannel_Shutdown",
            "func_va",
            debug=True,
            debug_label="exclude_func",
        )
        mock_float_filter.assert_awaited_once_with(
            session="session",
            func_addrs={0x180200000},
            xref_floats=["64.0"],
            exclude_floats=[],
            debug=True,
        )
        mock_gen_sig.assert_awaited_once()

    async def test_preprocess_func_xrefs_fails_closed_on_float_filter_failure(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180100000, 0x180200000}),
        ), patch.object(
            ida_analyze_util,
            "_filter_func_addrs_by_float_xrefs_via_mcp",
            AsyncMock(return_value=None),
        ) as mock_float_filter, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(return_value=None),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=["Networking"],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                xref_floats=["64.0"],
                exclude_floats=[],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertIsNone(result)
        mock_float_filter.assert_awaited_once()
        mock_gen_sig.assert_not_called()

    async def test_preprocess_func_xrefs_forwards_boundary_flag_to_generator(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_string",
            AsyncMock(return_value={0x180200000}),
        ), patch.object(
            ida_analyze_util,
            "_func_contains_signature_via_mcp",
            AsyncMock(return_value=True),
        ) as mock_func_contains_signature, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=["Networking"],
                xref_gvs=[],
                xref_signatures=["C7 44 24 40 64 FF FF FF"],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                allow_func_sig_across_function_boundary=True,
                debug=False,
            )

        self.assertEqual("48 89 5C 24 08", result["func_sig"])
        mock_func_contains_signature.assert_awaited_once_with(
            session="session",
            func_va=0x180200000,
            signature="C7 44 24 40 64 FF FF FF",
            debug=False,
        )
        mock_gen_sig.assert_awaited_once()
        self.assertTrue(
            mock_gen_sig.await_args.kwargs["allow_across_function_boundary"]
        )

    async def test_preprocess_func_xrefs_uses_vtable_entry_when_dep_func_has_no_callers(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_load_symbol_addr_from_current_yaml",
            return_value=0x180200000,
        ) as mock_load_symbol, patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_ea",
            AsyncMock(return_value=set()),
        ) as mock_collect_ea, patch.object(
            ida_analyze_util,
            "_read_yaml_file",
            return_value={
                "vtable_entries": {
                    0: "0x180200000",
                    1: "0x180300000",
                }
            },
        ) as mock_read_yaml, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="CLoopModeGame_LoopInit",
                xref_strings=[],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=["CLoopModeGame_LoopInitInternal"],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                new_binary_dir="bin_dir",
                platform="linux",
                image_base=0x180000000,
                vtable_class="CLoopModeGame",
                debug=True,
            )

        self.assertEqual("CLoopModeGame_LoopInit", result["func_name"])
        self.assertEqual("0x180200000", result["func_va"])
        mock_collect_ea.assert_awaited_once_with(
            session="session",
            target_ea=0x180200000,
            debug=True,
        )
        mock_read_yaml.assert_called_once_with(
            str(Path("bin_dir") / "CLoopModeGame_vtable.linux.yaml")
        )
        self.assertEqual(0x180200000, mock_gen_sig.await_args.kwargs["func_va"])
        self.assertFalse(
            mock_gen_sig.await_args.kwargs["allow_across_function_boundary"]
        )
        mock_load_symbol.assert_called_once()

    async def test_preprocess_func_xrefs_fails_when_signature_set_is_empty(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_collect_xref_func_starts_for_signature",
            AsyncMock(return_value=set()),
        ) as mock_collect_signature, patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(return_value=None),
        ) as mock_gen_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="LoggingChannel_Init",
                xref_strings=[],
                xref_gvs=[],
                xref_signatures=["C7 44 24 40 64 FF FF FF"],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertIsNone(result)
        mock_collect_signature.assert_awaited_once_with(
            session="session",
            xref_signature="C7 44 24 40 64 FF FF FF",
            debug=True,
        )
        mock_gen_sig.assert_not_called()

    async def test_preprocess_common_skill_forwards_dict_func_xrefs_fields(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(return_value=None),
        ), patch.object(
            ida_analyze_util,
            "preprocess_func_xrefs_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "LoggingChannel_Init",
                    "func_va": "0x180200000",
                    "func_rva": "0x200000",
                    "func_size": "0x40",
                    "func_sig": "48 89 5C 24 08",
                }
            ),
        ) as mock_func_xrefs, patch.object(
            ida_analyze_util,
            "write_func_yaml",
        ) as mock_write_func_yaml, patch.object(
            ida_analyze_util,
            "_rename_func_in_ida",
            AsyncMock(return_value=None),
        ):
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=["/tmp/LoggingChannel_Init.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                func_names=["LoggingChannel_Init"],
                func_xrefs=[
                    {
                        "func_name": "LoggingChannel_Init",
                        "xref_strings": ["Networking"],
                        "xref_gvs": ["g_NetworkingState"],
                        "xref_signatures": ["C7 44 24 40 64 FF FF FF"],
                        "xref_funcs": ["LoggingChannel_Shutdown"],
                        "xref_floats": ["64.0", "0.5"],
                        "exclude_funcs": ["LoggingChannel_Rebuild"],
                        "exclude_strings": ["FULLMATCH:Networking"],
                        "exclude_gvs": ["g_ExcludeNetworkingState"],
                        "exclude_signatures": ["DE AD BE EF"],
                        "exclude_floats": ["128.0"],
                    }
                ],
                generate_yaml_desired_fields=[
                    (
                        "LoggingChannel_Init",
                        [
                            "func_name",
                            "func_va",
                            "func_rva",
                            "func_size",
                            "func_sig",
                        ],
                    )
                ],
                debug=True,
            )

        self.assertTrue(result)
        mock_func_xrefs.assert_awaited_once()
        self.assertEqual(
            ["g_NetworkingState"],
            mock_func_xrefs.call_args.kwargs["xref_gvs"],
        )
        self.assertEqual(
            ["C7 44 24 40 64 FF FF FF"],
            mock_func_xrefs.call_args.kwargs["xref_signatures"],
        )
        self.assertEqual(
            ["LoggingChannel_Shutdown"],
            mock_func_xrefs.call_args.kwargs["xref_funcs"],
        )
        self.assertEqual(
            ["64.0", "0.5"],
            mock_func_xrefs.call_args.kwargs["xref_floats"],
        )
        self.assertEqual(
            ["LoggingChannel_Rebuild"],
            mock_func_xrefs.call_args.kwargs["exclude_funcs"],
        )
        self.assertEqual(
            ["FULLMATCH:Networking"],
            mock_func_xrefs.call_args.kwargs["exclude_strings"],
        )
        self.assertEqual(
            ["g_ExcludeNetworkingState"],
            mock_func_xrefs.call_args.kwargs["exclude_gvs"],
        )
        self.assertEqual(
            ["DE AD BE EF"],
            mock_func_xrefs.call_args.kwargs["exclude_signatures"],
        )
        self.assertEqual(
            ["128.0"],
            mock_func_xrefs.call_args.kwargs["exclude_floats"],
        )
        mock_write_func_yaml.assert_called_once()

    async def test_preprocess_common_skill_rejects_tuple_func_xrefs(
        self,
    ) -> None:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/LoggingChannel_Init.windows.yaml"],
            old_yaml_map={},
            new_binary_dir="/tmp",
            platform="windows",
            image_base=0x180000000,
            func_names=["LoggingChannel_Init"],
            func_xrefs=[
                (
                    "LoggingChannel_Init",
                    ["Networking"],
                    [],
                    [],
                    [],
                    [],
                )
            ],
            generate_yaml_desired_fields=[
                (
                    "LoggingChannel_Init",
                    ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
                )
            ],
            debug=True,
        )

        self.assertFalse(result)

    async def test_preprocess_common_skill_rejects_unknown_func_xrefs_key(
        self,
    ) -> None:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/LoggingChannel_Init.windows.yaml"],
            old_yaml_map={},
            new_binary_dir="/tmp",
            platform="windows",
            image_base=0x180000000,
            func_names=["LoggingChannel_Init"],
            func_xrefs=[
                {
                    "func_name": "LoggingChannel_Init",
                    "xref_strings": ["Networking"],
                    "xref_gvs": [],
                    "xref_signatures": [],
                    "xref_funcs": [],
                    "exclude_funcs": [],
                    "exclude_strings": [],
                    "exclude_gvs": [],
                    "exclude_signatures": [],
                    "unexpected": [],
                }
            ],
            generate_yaml_desired_fields=[
                (
                    "LoggingChannel_Init",
                    ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
                )
            ],
            debug=True,
        )

        self.assertFalse(result)

    async def test_preprocess_common_skill_rejects_empty_positive_xref_sources(
        self,
    ) -> None:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/LoggingChannel_Init.windows.yaml"],
            old_yaml_map={},
            new_binary_dir="/tmp",
            platform="windows",
            image_base=0x180000000,
            func_names=["LoggingChannel_Init"],
            func_xrefs=[
                {
                    "func_name": "LoggingChannel_Init",
                    "xref_strings": [],
                    "xref_gvs": [],
                    "xref_signatures": [],
                    "xref_funcs": [],
                    "exclude_funcs": [],
                    "exclude_strings": [],
                    "exclude_gvs": [],
                    "exclude_signatures": [],
                }
            ],
            generate_yaml_desired_fields=[
                (
                    "LoggingChannel_Init",
                    ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
                )
            ],
            debug=True,
        )

        self.assertFalse(result)

    async def test_preprocess_common_skill_rejects_invalid_float_xref_values(
        self,
    ) -> None:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/LoggingChannel_Init.windows.yaml"],
            old_yaml_map={},
            new_binary_dir="/tmp",
            platform="windows",
            image_base=0x180000000,
            func_names=["LoggingChannel_Init"],
            func_xrefs=[
                {
                    "func_name": "LoggingChannel_Init",
                    "xref_strings": ["Networking"],
                    "xref_gvs": [],
                    "xref_signatures": [],
                    "xref_funcs": [],
                    "xref_floats": ["not-a-float"],
                    "exclude_funcs": [],
                    "exclude_strings": [],
                    "exclude_gvs": [],
                    "exclude_signatures": [],
                    "exclude_floats": [],
                }
            ],
            generate_yaml_desired_fields=[
                (
                    "LoggingChannel_Init",
                    ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
                )
            ],
            debug=True,
        )
        self.assertFalse(result)

    async def test_preprocess_common_skill_rejects_nan_xref_floats(self) -> None:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/LoggingChannel_Init.windows.yaml"],
            old_yaml_map={},
            new_binary_dir="/tmp",
            platform="windows",
            image_base=0x180000000,
            func_names=["LoggingChannel_Init"],
            func_xrefs=[
                {
                    "func_name": "LoggingChannel_Init",
                    "xref_strings": ["Networking"],
                    "xref_gvs": [],
                    "xref_signatures": [],
                    "xref_funcs": [],
                    "xref_floats": ["nan"],
                    "exclude_funcs": [],
                    "exclude_strings": [],
                    "exclude_gvs": [],
                    "exclude_signatures": [],
                    "exclude_floats": [],
                }
            ],
            generate_yaml_desired_fields=[
                (
                    "LoggingChannel_Init",
                    ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
                )
            ],
            debug=True,
        )
        self.assertFalse(result)

    async def test_preprocess_common_skill_rejects_inf_xref_floats(self) -> None:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/LoggingChannel_Init.windows.yaml"],
            old_yaml_map={},
            new_binary_dir="/tmp",
            platform="windows",
            image_base=0x180000000,
            func_names=["LoggingChannel_Init"],
            func_xrefs=[
                {
                    "func_name": "LoggingChannel_Init",
                    "xref_strings": ["Networking"],
                    "xref_gvs": [],
                    "xref_signatures": [],
                    "xref_funcs": [],
                    "xref_floats": ["inf"],
                    "exclude_funcs": [],
                    "exclude_strings": [],
                    "exclude_gvs": [],
                    "exclude_signatures": [],
                    "exclude_floats": [],
                }
            ],
            generate_yaml_desired_fields=[
                (
                    "LoggingChannel_Init",
                    ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
                )
            ],
            debug=True,
        )
        self.assertFalse(result)

    async def test_preprocess_common_skill_rejects_negative_inf_exclude_floats(
        self,
    ) -> None:
        result = await ida_analyze_util.preprocess_common_skill(
            session="session",
            expected_outputs=["/tmp/LoggingChannel_Init.windows.yaml"],
            old_yaml_map={},
            new_binary_dir="/tmp",
            platform="windows",
            image_base=0x180000000,
            func_names=["LoggingChannel_Init"],
            func_xrefs=[
                {
                    "func_name": "LoggingChannel_Init",
                    "xref_strings": ["Networking"],
                    "xref_gvs": [],
                    "xref_signatures": [],
                    "xref_funcs": [],
                    "xref_floats": [],
                    "exclude_funcs": [],
                    "exclude_strings": [],
                    "exclude_gvs": [],
                    "exclude_signatures": [],
                    "exclude_floats": ["-inf"],
                }
            ],
            generate_yaml_desired_fields=[
                (
                    "LoggingChannel_Init",
                    ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
                )
            ],
            debug=True,
        )
        self.assertFalse(result)

    def test_can_probe_future_func_fast_path_ignores_literal_gv_dependencies(
        self,
    ) -> None:
        result = ida_analyze_util._can_probe_future_func_fast_path(
            func_name="LoggingChannel_Init",
            func_xrefs_map={
                "LoggingChannel_Init": {
                    "xref_strings": [],
                    "xref_gvs": ["0x18000F000"],
                    "xref_signatures": [],
                    "xref_funcs": [],
                    "exclude_funcs": [],
                    "exclude_strings": [],
                    "exclude_gvs": ["0x18000F100"],
                    "exclude_signatures": [],
                }
            },
            new_binary_dir=None,
            platform="windows",
            debug=True,
        )

        self.assertTrue(result)


class TestFunctionDetailExportPyEvalBuilder(unittest.IsolatedAsyncioTestCase):
    def test_build_function_detail_export_py_eval_contains_chunk_comment_and_fallback_logic(
        self,
    ) -> None:
        py_code = ida_analyze_util.build_function_detail_export_py_eval(0x180123450)
        first_chunk_fallback = py_code.find("if not chunk_ranges:")
        tail_iterator_fallback = py_code.find("ida_funcs.func_tail_iterator_t(func)")
        tail_iterator_no_arg_fallback = py_code.find("ida_funcs.func_tail_iterator_t()")
        tail_iterator_set_ea = py_code.find("tail_iterator.set_ea(func.start_ea)")
        final_single_range_guard = py_code.rfind("if not chunk_ranges:")
        final_single_range_fallback = py_code.rfind(
            "chunk_ranges = [(int(func.start_ea), int(func.end_ea))]"
        )

        self.assertIn("for start_ea, end_ea in idautils.Chunks(func.start_ea):", py_code)
        self.assertIn("initial_chunk_ranges = []", py_code)
        self.assertIn(
            "_append_chunk_range(initial_chunk_ranges, start_ea, end_ea)",
            py_code,
        )
        self.assertIn("chunk_ranges = initial_chunk_ranges", py_code)
        self.assertIn("except Exception:\n        pass", py_code)
        self.assertNotEqual(-1, first_chunk_fallback)
        self.assertNotEqual(-1, tail_iterator_fallback)
        self.assertNotEqual(-1, tail_iterator_no_arg_fallback)
        self.assertNotEqual(-1, tail_iterator_set_ea)
        self.assertNotEqual(-1, final_single_range_guard)
        self.assertNotEqual(-1, final_single_range_fallback)
        self.assertLess(first_chunk_fallback, tail_iterator_fallback)
        self.assertLess(tail_iterator_fallback, tail_iterator_no_arg_fallback)
        self.assertLess(tail_iterator_no_arg_fallback, tail_iterator_set_ea)
        self.assertLess(tail_iterator_set_ea, final_single_range_guard)
        self.assertLess(final_single_range_guard, final_single_range_fallback)
        self.assertLess(tail_iterator_fallback, final_single_range_fallback)
        self.assertIn("pending_eas = [int(func.start_ea)]", py_code)
        self.assertIn("mnem == 'jmp'", py_code)
        self.assertIn("mnem.startswith('j')", py_code)
        self.assertIn("idc.get_cmt(ea, repeatable)", py_code)
        self.assertIn("get_extra_cmt = getattr(idc, 'get_extra_cmt', None)", py_code)
        self.assertIn(
            "fallback_eas = sorted(set(int(ea) for ea in _iter_chunk_code_heads(chunk_ranges)))",
            py_code,
        )
        self.assertIn("def _render_disasm_lines(eas):", py_code)
        self.assertNotIn("for ea in idautils.FuncItems(func.start_ea):", py_code)

    def test_build_function_detail_export_py_eval_runs_with_ida_mcp_split_scope(
        self,
    ) -> None:
        fake_func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1003)
        ida_bytes = types.ModuleType("ida_bytes")
        ida_funcs = types.ModuleType("ida_funcs")
        ida_lines = types.ModuleType("ida_lines")
        ida_segment = types.ModuleType("ida_segment")
        idautils = types.ModuleType("idautils")
        idc = types.ModuleType("idc")

        ida_bytes.get_flags = lambda ea: 1
        ida_bytes.is_code = lambda flags: True
        ida_funcs.get_func = lambda ea: fake_func
        ida_funcs.get_func_name = lambda ea: "FakeFunc"
        ida_lines.tag_remove = lambda text: text
        ida_segment.getseg = lambda ea: object()
        ida_segment.get_segm_name = lambda seg: ".text"
        idautils.Chunks = lambda start_ea: iter([(0x1000, 0x1003)])
        idautils.CodeRefsFrom = lambda ea, flow: []
        idc.BADADDR = -1
        idc.generate_disasm_line = lambda ea, flags: "retn" if ea == 0x1002 else "nop"
        idc.get_cmt = (
            lambda ea, repeatable: "entry comment" if ea == 0x1000 and repeatable == 0 else None
        )
        idc.get_extra_cmt = lambda ea, index: None
        idc.next_head = lambda ea, end_ea: ea + 1 if ea + 1 < end_ea else idc.BADADDR
        idc.print_insn_mnem = lambda ea: "ret" if ea == 0x1002 else "nop"

        fake_modules = {
            "ida_bytes": ida_bytes,
            "ida_funcs": ida_funcs,
            "ida_lines": ida_lines,
            "ida_segment": ida_segment,
            "idautils": idautils,
            "idc": idc,
        }
        py_code = ida_analyze_util.build_function_detail_export_py_eval(0x1000)
        exec_globals: dict[str, object] = {}
        exec_locals: dict[str, object] = {}

        with patch.dict(sys.modules, fake_modules):
            exec(py_code, exec_globals, exec_locals)

        payload = json.loads(str(exec_locals["result"]))
        self.assertEqual("FakeFunc", payload["func_name"])
        self.assertIn(".text:0000000000001000                 ; entry comment", payload["disasm_code"])
        self.assertIn(".text:0000000000001002                 retn", payload["disasm_code"])

    def test_build_function_detail_export_file_py_eval_writes_json_and_returns_ack(
        self,
    ) -> None:
        py_code = ida_analyze_util.build_function_detail_export_file_py_eval(
            0x180123450,
            output_path="/tmp/function-detail.json",
        )

        self.assertIn("payload_text = result", py_code)
        self.assertIn("output_path = '/tmp/function-detail.json'", py_code)
        self.assertIn("'bytes_written'", py_code)
        self.assertIn("format_name = 'json'", py_code)

    async def test_export_function_detail_via_mcp_uses_shared_py_eval_builder(self) -> None:
        session = AsyncMock()
        captured_output_path: dict[str, Path] = {}

        def _fake_builder(func_va_int: int, *, output_path: str | Path) -> str:
            captured_output_path["path"] = Path(output_path)
            self.assertEqual(0x180123450, func_va_int)
            return "PY-CODE"

        async def _fake_call_tool(**kwargs):
            output_path = captured_output_path["path"]
            payload_text = json.dumps(
                {
                    "func_name": "sub_180123450",
                    "func_va": "0x180123450",
                    "disasm_code": "text:180123450 push rbp",
                    "procedure": "",
                }
            )
            output_path.write_text(payload_text, encoding="utf-8")
            return _py_eval_payload(
                {
                    "ok": True,
                    "output_path": str(output_path),
                    "bytes_written": len(payload_text.encode("utf-8")),
                    "format": "json",
                }
            )

        session.call_tool.side_effect = _fake_call_tool

        with patch.object(
            ida_analyze_util,
            "build_function_detail_export_file_py_eval",
            side_effect=_fake_builder,
        ) as mock_builder:
            payload = await ida_analyze_util._export_function_detail_via_mcp(
                session,
                "CNetworkMessages_FindNetworkGroup",
                "0x180123450",
                debug=False,
            )

        mock_builder.assert_called_once()
        session.call_tool.assert_awaited_once_with(
            name="py_eval",
            arguments={"code": "PY-CODE"},
        )
        self.assertEqual(
            {
                "func_name": "CNetworkMessages_FindNetworkGroup",
                "func_va": "0x180123450",
                "disasm_code": "text:180123450 push rbp",
                "procedure": "",
            },
            payload,
        )

    async def test_export_function_detail_via_mcp_normalizes_none_procedure_to_empty_string(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "func_name": "sub_180123450",
                "func_va": "0x180123450",
                "disasm_code": "text:180123450 push rbp",
                "procedure": None,
            }
        )

        payload = await ida_analyze_util._export_function_detail_via_mcp(
            session,
            "CNetworkMessages_FindNetworkGroup",
            "0x180123450",
            debug=False,
        )

        self.assertIsNotNone(payload)
        self.assertEqual("", payload["procedure"])

    async def test_export_function_detail_via_mcp_returns_none_when_py_eval_raises(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.side_effect = RuntimeError("boom")

        payload = await ida_analyze_util._export_function_detail_via_mcp(
            session,
            "CNetworkMessages_FindNetworkGroup",
            "0x180123450",
            debug=False,
        )

        self.assertIsNone(payload)

    async def test_export_function_detail_via_mcp_returns_none_without_calling_py_eval_when_input_func_va_is_invalid(
        self,
    ) -> None:
        session = AsyncMock()

        payload = await ida_analyze_util._export_function_detail_via_mcp(
            session,
            "CNetworkMessages_FindNetworkGroup",
            "bad",
            debug=False,
        )

        self.assertIsNone(payload)
        session.call_tool.assert_not_called()

    async def test_export_function_detail_via_mcp_returns_none_when_disasm_code_missing_or_empty(
        self,
    ) -> None:
        for detail_payload in (
            {
                "func_name": "sub_180123450",
                "func_va": "0x180123450",
                "procedure": "",
            },
            {
                "func_name": "sub_180123450",
                "func_va": "0x180123450",
                "disasm_code": "   ",
                "procedure": "",
            },
        ):
            with self.subTest(detail_payload=detail_payload):
                session = AsyncMock()
                session.call_tool.return_value = _py_eval_payload(detail_payload)

                payload = await ida_analyze_util._export_function_detail_via_mcp(
                    session,
                    "CNetworkMessages_FindNetworkGroup",
                    "0x180123450",
                    debug=False,
                )

                self.assertIsNone(payload)

    async def test_export_function_detail_via_mcp_returns_none_when_func_va_is_invalid(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "func_name": "sub_180123450",
                "func_va": "not-an-address",
                "disasm_code": "text:180123450 push rbp",
                "procedure": "",
            }
        )

        payload = await ida_analyze_util._export_function_detail_via_mcp(
            session,
            "CNetworkMessages_FindNetworkGroup",
            "0x180123450",
            debug=False,
        )

        self.assertIsNone(payload)

    async def test_export_function_detail_via_mcp_returns_none_when_procedure_is_not_string(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "func_name": "sub_180123450",
                "func_va": "0x180123450",
                "disasm_code": "text:180123450 push rbp",
                "procedure": 123,
            }
        )

        payload = await ida_analyze_util._export_function_detail_via_mcp(
            session,
            "CNetworkMessages_FindNetworkGroup",
            "0x180123450",
            debug=False,
        )

        self.assertIsNone(payload)


class TestLlmDecompileSupport(unittest.IsolatedAsyncioTestCase):
    def test_parse_llm_decompile_response_normalizes_found_funcptr(self) -> None:
        response_text = """
```yaml
found_funcptr:
  - insn_va: 0x180666600
    insn_disasm: " lea     rdx, sub_15BC910 "
    funcptr_name: " CLoopModeGame_OnClientPollNetworking "
  - insn_va: 0x180666601
```
""".strip()

        parsed = ida_analyze_util.parse_llm_decompile_response(response_text)

        self.assertEqual(
            [
                {
                    "insn_va": "0x180666600",
                    "insn_disasm": "lea     rdx, sub_15BC910",
                    "funcptr_name": "CLoopModeGame_OnClientPollNetworking",
                }
            ],
            parsed["found_funcptr"],
        )
        self.assertEqual([], parsed["found_call"])
        self.assertEqual([], parsed["found_vcall"])

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
    size: 8
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
                "found_funcptr": [],
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
                        "size": "8",
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
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            },
            parsed,
        )
        mock_call_llm_text.assert_called_once()
        self.assertEqual("gpt-4.1-mini", mock_call_llm_text.call_args.kwargs["model"])
        self.assertNotIn("temperature", mock_call_llm_text.call_args.kwargs)

    async def test_call_llm_decompile_forwards_explicit_temperature(
        self,
    ) -> None:
        response_text = """
```yaml
found_vcall: []
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
                temperature=0.35,
            )

        self.assertEqual(
            {
                "found_vcall": [],
                "found_call": [],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            },
            parsed,
        )
        mock_call_llm_text.assert_called_once()
        self.assertEqual(0.35, mock_call_llm_text.call_args.kwargs["temperature"])

    async def test_call_llm_decompile_forwards_effort_and_codex_transport(
        self,
    ) -> None:
        response_text = """
```yaml
found_vcall: []
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
                client=None,
                model="gpt-5.4",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
                api_key="test-api-key",
                base_url="https://example.invalid/v1",
                fake_as="codex",
                effort="high",
            )

        self.assertEqual(
            {
                "found_vcall": [],
                "found_call": [],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            },
            parsed,
        )
        mock_call_llm_text.assert_called_once()
        self.assertEqual("high", mock_call_llm_text.call_args.kwargs["effort"])
        self.assertEqual("codex", mock_call_llm_text.call_args.kwargs["fake_as"])
        self.assertEqual(
            "test-api-key",
            mock_call_llm_text.call_args.kwargs["api_key"],
        )
        self.assertEqual(
            "https://example.invalid/v1",
            mock_call_llm_text.call_args.kwargs["base_url"],
        )

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
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            },
            parsed,
        )

    async def test_call_llm_decompile_retries_transient_transport_error_then_parses_yaml(
        self,
    ) -> None:
        response_text = """
```yaml
found_vcall:
  - insn_va: 0x180777700
    insn_disasm: "call    [rax+68h]"
    vfunc_offset: 0x68
    func_name: "ILoopMode_OnLoopActivate"
found_call: []
found_gv: []
found_struct_offset: []
```
""".strip()

        with patch.object(
            ida_analyze_util,
            "call_llm_text",
            side_effect=[
                RuntimeError("*** transport received error: retry your request"),
                response_text,
            ],
            create=True,
        ) as mock_call_llm_text:
            parsed = await ida_analyze_util.call_llm_decompile(
                client=object(),
                model="gpt-5.4",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
                max_retries=2,
                retry_initial_delay=0,
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
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            },
            parsed,
        )
        self.assertEqual(2, mock_call_llm_text.call_count)

    async def test_call_llm_decompile_does_not_retry_non_transient_error(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "call_llm_text",
            side_effect=RuntimeError("invalid api key"),
            create=True,
        ) as mock_call_llm_text:
            parsed = await ida_analyze_util.call_llm_decompile(
                client=object(),
                model="gpt-5.4",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
                max_retries=3,
                retry_initial_delay=0,
            )

        self.assertEqual(ida_analyze_util._empty_llm_decompile_result(), parsed)
        mock_call_llm_text.assert_called_once()

    async def test_call_llm_decompile_returns_empty_after_retry_exhaustion(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "call_llm_text",
            side_effect=RuntimeError("HTTP 503 service unavailable"),
            create=True,
        ) as mock_call_llm_text:
            parsed = await ida_analyze_util.call_llm_decompile(
                client=object(),
                model="gpt-5.4",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
                max_retries=3,
                retry_initial_delay=0,
            )

        self.assertEqual(ida_analyze_util._empty_llm_decompile_result(), parsed)
        self.assertEqual(3, mock_call_llm_text.call_count)

    async def test_call_llm_decompile_max_retries_one_disables_retry(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "call_llm_text",
            side_effect=RuntimeError("HTTP 429 too many requests"),
            create=True,
        ) as mock_call_llm_text:
            parsed = await ida_analyze_util.call_llm_decompile(
                client=object(),
                model="gpt-5.4",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
                max_retries=1,
                retry_initial_delay=0,
            )

        self.assertEqual(ida_analyze_util._empty_llm_decompile_result(), parsed)
        mock_call_llm_text.assert_called_once()

    def test_is_transient_llm_error_accepts_status_code_attributes(self) -> None:
        class FakeError(Exception):
            status_code = 429

        self.assertTrue(ida_analyze_util._is_transient_llm_error(FakeError()))

    def test_is_transient_llm_error_accepts_response_status_code(self) -> None:
        class FakeResponse:
            status_code = 502

        class FakeError(Exception):
            response = FakeResponse()

        self.assertTrue(ida_analyze_util._is_transient_llm_error(FakeError()))

    def test_is_transient_llm_error_rejects_client_configuration_error(self) -> None:
        self.assertFalse(
            ida_analyze_util._is_transient_llm_error(RuntimeError("invalid api key"))
        )

    def test_build_llm_decompile_specs_map_groups_duplicate_symbol_names(
        self,
    ) -> None:
        specs_map = ida_analyze_util._build_llm_decompile_specs_map(
            [
                (
                    "ILoopMode_OnLoopActivate",
                    "prompt/call_llm_decompile.md",
                    "references/reference_a.yaml",
                ),
                (
                    "CNetworkMessages_FindNetworkGroup",
                    "prompt/call_llm_decompile.md",
                    "references/reference_b.yaml",
                ),
                (
                    "ILoopMode_OnLoopActivate",
                    "prompt/call_llm_decompile.md",
                    "references/reference_c.yaml",
                ),
            ],
            debug=True,
        )

        self.assertEqual(
            {
                "ILoopMode_OnLoopActivate": [
                    {
                        "prompt_path": "prompt/call_llm_decompile.md",
                        "reference_yaml_path": "references/reference_a.yaml",
                    },
                    {
                        "prompt_path": "prompt/call_llm_decompile.md",
                        "reference_yaml_path": "references/reference_c.yaml",
                    },
                ],
                "CNetworkMessages_FindNetworkGroup": [
                    {
                        "prompt_path": "prompt/call_llm_decompile.md",
                        "reference_yaml_path": "references/reference_b.yaml",
                    }
                ],
            },
            specs_map,
        )

    def test_build_llm_decompile_specs_map_rejects_mixed_prompt_paths(
        self,
    ) -> None:
        specs_map = ida_analyze_util._build_llm_decompile_specs_map(
            [
                (
                    "ILoopMode_OnLoopActivate",
                    "prompt/call_llm_decompile.md",
                    "references/reference_a.yaml",
                ),
                (
                    "ILoopMode_OnLoopActivate",
                    "prompt/other_llm_decompile.md",
                    "references/reference_b.yaml",
                ),
            ],
            debug=True,
        )

        self.assertIsNone(specs_map)

    async def test_prepare_llm_decompile_request_collects_multiple_references(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "references").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "symbols={symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference_a.yaml",
                {
                    "func_name": "CNetworkGameClient_RecordEntityBandwidth",
                    "disasm_code": "call    sub_180111100",
                    "procedure": "return FindNetworkGroup(this);",
                },
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference_b.yaml",
                {
                    "func_name": "CNetworkMessages_FindMessage",
                    "disasm_code": "call    sub_180222200",
                    "procedure": "return FindMessage(this);",
                },
            )

            with patch.object(
                ida_analyze_util,
                "_get_preprocessor_scripts_dir",
                return_value=preprocessor_dir,
            ), patch.object(
                ida_analyze_util,
                "create_openai_client",
                side_effect=AssertionError("should not be called in codex mode"),
                create=True,
            ):
                request = ida_analyze_util._prepare_llm_decompile_request(
                    "ILoopMode_OnLoopActivate",
                    {
                        "ILoopMode_OnLoopActivate": [
                            {
                                "prompt_path": "prompt/call_llm_decompile.md",
                                "reference_yaml_path": "references/reference_a.yaml",
                            },
                            {
                                "prompt_path": "prompt/call_llm_decompile.md",
                                "reference_yaml_path": "references/reference_b.yaml",
                            },
                        ]
                    },
                    {
                        "model": "gpt-5.4",
                        "api_key": "test-api-key",
                        "fake_as": "codex",
                    },
                    platform="windows",
                    debug=True,
                )

        reference_yaml_paths = [
            os.fspath(
                preprocessor_dir / "references" / "reference_a.yaml",
            ),
            os.fspath(
                preprocessor_dir / "references" / "reference_b.yaml",
            ),
        ]
        self.assertIsNotNone(request)
        self.assertEqual(reference_yaml_paths, request["reference_yaml_paths"])
        self.assertEqual(
            [
                "CNetworkGameClient_RecordEntityBandwidth",
                "CNetworkMessages_FindMessage",
            ],
            request["target_func_names"],
        )
        self.assertEqual(
            [
                {
                    "func_name": "CNetworkGameClient_RecordEntityBandwidth",
                    "disasm_code": "call    sub_180111100",
                    "procedure": "return FindNetworkGroup(this);",
                },
                {
                    "func_name": "CNetworkMessages_FindMessage",
                    "disasm_code": "call    sub_180222200",
                    "procedure": "return FindMessage(this);",
                },
            ],
            request["reference_items"],
        )
        self.assertEqual(reference_yaml_paths[0], request["reference_yaml_path"])
        self.assertEqual(
            "CNetworkGameClient_RecordEntityBandwidth",
            request["target_func_name"],
        )
        self.assertEqual(
            "call    sub_180111100",
            request["disasm_for_reference"],
        )
        self.assertEqual(
            "return FindNetworkGroup(this);",
            request["procedure_for_reference"],
        )
        self.assertEqual(
            (
                "gpt-5.4",
                request["prompt_path"],
                tuple(reference_yaml_paths),
                None,
            ),
            ida_analyze_util._build_llm_decompile_request_cache_key(request),
        )
        self.assertEqual(
            (
                "gpt-4.1-mini",
                "/tmp/prompt.md",
                ("/tmp/reference.yaml",),
                0.25,
            ),
            ida_analyze_util._build_llm_decompile_request_cache_key(
                {
                    "model": "gpt-4.1-mini",
                    "prompt_path": "/tmp/prompt.md",
                    "reference_yaml_path": "/tmp/reference.yaml",
                    "temperature": 0.25,
                }
            ),
        )

    async def test_prepare_llm_decompile_request_preserves_retry_config(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "references" / "server").mkdir(
                parents=True,
                exist_ok=True,
            )
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{reference_blocks}\n---\n{target_blocks}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "server" / "Reference.windows.yaml",
                {
                    "func_name": "ReferenceFunc",
                    "disasm_code": "call qword ptr [rax+68h]",
                    "procedure": "ref();",
                },
            )

            with patch.object(
                ida_analyze_util,
                "_get_preprocessor_scripts_dir",
                return_value=preprocessor_dir,
            ):
                request = ida_analyze_util._prepare_llm_decompile_request(
                    "TargetFunc",
                    {
                        "TargetFunc": [
                            {
                                "prompt_path": "prompt/call_llm_decompile.md",
                                "reference_yaml_path": (
                                    "references/server/Reference.{platform}.yaml"
                                ),
                            }
                        ]
                    },
                    {
                        "model": "gpt-5.4",
                        "fake_as": "codex",
                        "max_retries": 4,
                        "retry_initial_delay": 0.5,
                        "retry_backoff_factor": 1.5,
                        "retry_max_delay": 3,
                    },
                    platform="windows",
                )

        self.assertEqual(4, request["max_retries"])
        self.assertEqual(0.5, request["retry_initial_delay"])
        self.assertEqual(1.5, request["retry_backoff_factor"])
        self.assertEqual(3, request["retry_max_delay"])

    async def test_prepare_llm_decompile_request_skips_client_factory_for_codex(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "references").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "symbols={symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": "CNetworkGameClient_RecordEntityBandwidth",
                    "disasm_code": "call    [rax+68h]",
                    "procedure": "(*v1->lpVtbl->OnLoopActivate)(v1);",
                },
            )

            with patch.object(
                ida_analyze_util,
                "_get_preprocessor_scripts_dir",
                return_value=preprocessor_dir,
            ), patch.object(
                ida_analyze_util,
                "create_openai_client",
                side_effect=AssertionError("should not be called in codex mode"),
                create=True,
            ):
                request = ida_analyze_util._prepare_llm_decompile_request(
                    "ILoopMode_OnLoopActivate",
                    {
                        "ILoopMode_OnLoopActivate": {
                            "prompt_path": "prompt/call_llm_decompile.md",
                            "reference_yaml_path": "references/reference.yaml",
                        }
                    },
                    {
                        "model": "gpt-5.4",
                        "api_key": "test-api-key",
                        "base_url": "https://example.invalid/v1",
                        "fake_as": "codex",
                        "effort": "high",
                    },
                    platform="windows",
                    debug=True,
                )

        self.assertIsNotNone(request)
        self.assertIsNone(request["client"])
        self.assertEqual("codex", request["fake_as"])
        self.assertEqual("high", request["effort"])
        self.assertEqual("test-api-key", request["api_key"])
        self.assertEqual("https://example.invalid/v1", request["base_url"])

    async def test_load_llm_decompile_target_detail_prefers_current_yaml_func_va(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "server"
            _write_yaml(
                module_dir / "BotAdd_CommandHandler.windows.yaml",
                {
                    "func_name": "BotAdd_CommandHandler",
                    "func_va": "0x1802DA7B0",
                },
            )
            expected_payload = {
                "func_name": "BotAdd_CommandHandler",
                "func_va": "0x1802da7b0",
                "disasm_code": "call    CCSBotManager_AddBot",
                "procedure": "void __fastcall BotAdd_CommandHandler()",
            }
            session = AsyncMock()

            with patch.object(
                ida_analyze_util,
                "_export_function_detail_via_mcp",
                AsyncMock(return_value=expected_payload),
            ) as mock_export, patch.object(
                ida_analyze_util,
                "_find_function_addr_by_names_via_mcp",
                AsyncMock(return_value="0x180000000"),
            ) as mock_find:
                result = await ida_analyze_util._load_llm_decompile_target_detail_via_mcp(
                    session=session,
                    target_func_name="BotAdd_CommandHandler",
                    new_binary_dir=str(module_dir),
                    platform="windows",
                    debug=True,
                )

        self.assertEqual(expected_payload, result)
        mock_export.assert_awaited_once_with(
            session,
            "BotAdd_CommandHandler",
            "0x1802da7b0",
            debug=True,
        )
        mock_find.assert_not_awaited()

    async def test_load_llm_decompile_target_detail_falls_back_to_name_lookup_when_current_yaml_missing_func_va(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "server"
            _write_yaml(
                module_dir / "BotAdd_CommandHandler.windows.yaml",
                {
                    "func_name": "BotAdd_CommandHandler",
                },
            )
            expected_payload = {
                "func_name": "BotAdd_CommandHandler",
                "func_va": "0x1802da7b0",
                "disasm_code": "call    CCSBotManager_AddBot",
                "procedure": "void __fastcall BotAdd_CommandHandler()",
            }
            session = AsyncMock()

            with patch.object(
                ida_analyze_util,
                "_find_function_addr_by_names_via_mcp",
                AsyncMock(return_value="0x1802da7b0"),
            ) as mock_find, patch.object(
                ida_analyze_util,
                "_export_function_detail_via_mcp",
                AsyncMock(return_value=expected_payload),
            ) as mock_export:
                result = await ida_analyze_util._load_llm_decompile_target_detail_via_mcp(
                    session=session,
                    target_func_name="BotAdd_CommandHandler",
                    new_binary_dir=str(module_dir),
                    platform="windows",
                    debug=True,
                )

        self.assertEqual(expected_payload, result)
        mock_find.assert_awaited_once()
        mock_export.assert_awaited_once_with(
            session,
            "BotAdd_CommandHandler",
            "0x1802da7b0",
            debug=True,
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

    async def test_preprocess_struct_offset_sig_via_mcp_emits_default_zero_disp(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "CGameResourceService_m_pEntitySystem.old.yaml"
            new_path = Path(temp_dir) / "CGameResourceService_m_pEntitySystem.windows.yaml"
            _write_yaml(
                old_path,
                {
                    "struct_name": "CGameResourceService",
                    "member_name": "m_pEntitySystem",
                    "offset": "0x50",
                    "size": 8,
                    "offset_sig": "49 8B 4E ??",
                },
            )

            session = AsyncMock()

            def _fake_call_tool(*, name: str, arguments: dict[str, object]):
                if name == "find_bytes":
                    self.assertEqual(
                        {"patterns": ["49 8B 4E ??"], "limit": 2},
                        arguments,
                    )
                    return _FakeCallToolResult(
                        [
                            {
                                "matches": ["0x1801BA12A"],
                                "n": 1,
                            }
                        ]
                    )
                if name == "py_eval":
                    code = arguments["code"]
                    self.assertIn("inst_addr = sig_addr + 0", code)
                    return _py_eval_payload(
                        {
                            "offset": 0x58,
                            "sig_va": "0x1801BA12A",
                            "inst_va": "0x1801BA12A",
                            "offset_size": 1,
                        }
                    )
                raise AssertionError(f"unexpected MCP tool: {name}")

            session.call_tool.side_effect = _fake_call_tool

            result = await ida_analyze_util.preprocess_struct_offset_sig_via_mcp(
                session=session,
                new_path=str(new_path),
                old_path=str(old_path),
                image_base=0x180000000,
                new_binary_dir=temp_dir,
                platform="windows",
                debug=True,
            )

        self.assertEqual(
            {
                "struct_name": "CGameResourceService",
                "member_name": "m_pEntitySystem",
                "offset": "0x58",
                "offset_sig": "49 8B 4E ??",
                "offset_sig_disp": 0,
                "size": 8,
            },
            result,
        )

    async def test_preprocess_gen_struct_offset_sig_via_mcp_generates_current_version_sig(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("DecodeInstruction", code)
                self.assertIn("ida_bytes.get_bytes", code)
                self.assertIn("allow_across_boundary = False", code)
                self.assertIn(
                    "limit_end = min(func.end_ea, target_inst + max_sig_bytes)",
                    code,
                )
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
            size=8,
            min_sig_bytes=4,
            debug=False,
        )

        self.assertEqual(
            {
                "struct_name": "CGameResourceService",
                "member_name": "m_pEntitySystem",
                "offset": "0x58",
                "size": 8,
                "offset_sig": "49 8B 4E ??",
                "offset_sig_disp": 0,
            },
            result,
        )

    async def test_preprocess_gen_struct_offset_sig_via_mcp_guards_cross_boundary_decode(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = True", code)
                self.assertIn("PAD_BYTES = {0xCC, 0x90}", code)
                self.assertIn("SEGPERM_EXEC", code)
                self.assertIn("def _is_same_exec_segment", code)
                self.assertIn("def _consume_padding", code)
                self.assertIn(
                    "cursor >= func.end_ea or not ida_bytes.is_code(flags) "
                    "or not ida_bytes.is_head(flags)",
                    code,
                )
                self.assertIn(
                    "if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):\n"
                    "            return cursor, padding, True",
                    code,
                )
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
            size=8,
            min_sig_bytes=4,
            allow_across_function_boundary=True,
            debug=False,
        )

        self.assertEqual(
            {
                "struct_name": "CGameResourceService",
                "member_name": "m_pEntitySystem",
                "offset": "0x58",
                "size": 8,
                "offset_sig": "49 8B 4E ??",
                "offset_sig_disp": 0,
            },
            result,
        )

    async def test_preprocess_gen_struct_offset_sig_via_mcp_guards_internal_gap_decode(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = True", code)
                self.assertIn("def _consume_padding", code)
                self.assertIn(
                    "cursor >= func.end_ea or not ida_bytes.is_code(flags) "
                    "or not ida_bytes.is_head(flags)",
                    code,
                )
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
            size=8,
            min_sig_bytes=4,
            allow_across_function_boundary=True,
            debug=False,
        )

        self.assertEqual(
            {
                "struct_name": "CGameResourceService",
                "member_name": "m_pEntitySystem",
                "offset": "0x58",
                "size": 8,
                "offset_sig": "49 8B 4E ??",
                "offset_sig_disp": 0,
            },
            result,
        )

    async def test_preprocess_gen_gv_sig_via_mcp_syncs_py_eval_locals_into_globals(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                self.assertIn("def _resolve_disp_off", arguments["code"])
                self.assertIn("def _collect_sig_stream", arguments["code"])
                self.assertIn("def _try_add", arguments["code"])
                self.assertIn("globals().update(locals())", arguments["code"])
                return _py_eval_payload(
                    [
                        {
                            "gv_inst_va": "0x1801BA12A",
                            "gv_inst_length": 6,
                            "gv_inst_disp": 2,
                            "insts": [
                                {
                                    "ea": "0x1801BA12A",
                                    "size": 6,
                                    "bytes": "8b0d78563412",
                                    "wild": [2, 3, 4, 5],
                                },
                                {
                                    "ea": "0x1801BA130",
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
                    ["8B 0D ?? ?? ?? ??"],
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

        result = await ida_analyze_util.preprocess_gen_gv_sig_via_mcp(
            session=session,
            gv_va="0x180123456",
            image_base=0x180000000,
            gv_access_inst_va="0x1801BA12A",
            min_sig_bytes=6,
            debug=False,
        )

        self.assertEqual(
            {
                "gv_va": "0x180123456",
                "gv_rva": "0x123456",
                "gv_sig": "8B 0D ?? ?? ?? ??",
                "gv_sig_va": "0x1801ba12a",
                "gv_inst_offset": 0,
                "gv_inst_length": 6,
                "gv_inst_disp": 2,
            },
            result,
        )

    async def test_preprocess_gen_gv_sig_via_mcp_guards_cross_boundary_decode(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = True", code)
                self.assertIn("PAD_BYTES = {0xCC, 0x90}", code)
                self.assertIn("SEGPERM_EXEC", code)
                self.assertIn("def _is_same_exec_segment", code)
                self.assertIn("def _consume_padding", code)
                self.assertIn("def _try_decode_padding_nop", code)
                self.assertIn("if mnem == 'nop':", code)
                self.assertIn(
                    "cursor >= f.end_ea or not ida_bytes.is_code(flags) "
                    "or not ida_bytes.is_head(flags)",
                    code,
                )
                self.assertIn(
                    "if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):",
                    code,
                )
                return _py_eval_payload(
                    [
                        {
                            "gv_inst_va": "0x1801BA12A",
                            "gv_inst_length": 6,
                            "gv_inst_disp": 2,
                            "insts": [
                                {
                                    "ea": "0x1801BA12A",
                                    "size": 6,
                                    "bytes": "8b0d78563412",
                                    "wild": [2, 3, 4, 5],
                                },
                                {
                                    "ea": "0x1801BA130",
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
                    ["8B 0D ?? ?? ?? ??"],
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

        result = await ida_analyze_util.preprocess_gen_gv_sig_via_mcp(
            session=session,
            gv_va="0x180123456",
            image_base=0x180000000,
            gv_access_inst_va="0x1801BA12A",
            min_sig_bytes=6,
            allow_across_function_boundary=True,
            debug=False,
        )

        self.assertEqual(
            {
                "gv_va": "0x180123456",
                "gv_rva": "0x123456",
                "gv_sig": "8B 0D ?? ?? ?? ??",
                "gv_sig_va": "0x1801ba12a",
                "gv_inst_offset": 0,
                "gv_inst_length": 6,
                "gv_inst_disp": 2,
            },
            result,
        )

    async def test_preprocess_gen_gv_sig_via_mcp_guards_internal_gap_decode(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = True", code)
                self.assertIn("def _consume_padding", code)
                self.assertIn("def _try_decode_padding_nop", code)
                self.assertIn("if mnem == 'nop':", code)
                self.assertIn(
                    "cursor >= f.end_ea or not ida_bytes.is_code(flags) "
                    "or not ida_bytes.is_head(flags)",
                    code,
                )
                return _py_eval_payload(
                    [
                        {
                            "gv_inst_va": "0x1801BA12A",
                            "gv_inst_length": 6,
                            "gv_inst_disp": 2,
                            "insts": [
                                {
                                    "ea": "0x1801BA12A",
                                    "size": 6,
                                    "bytes": "8b0d78563412",
                                    "wild": [2, 3, 4, 5],
                                },
                                {
                                    "ea": "0x1801BA130",
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
                    ["8B 0D ?? ?? ?? ??"],
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

        result = await ida_analyze_util.preprocess_gen_gv_sig_via_mcp(
            session=session,
            gv_va="0x180123456",
            image_base=0x180000000,
            gv_access_inst_va="0x1801BA12A",
            min_sig_bytes=6,
            allow_across_function_boundary=True,
            debug=False,
        )

        self.assertEqual(
            {
                "gv_va": "0x180123456",
                "gv_rva": "0x123456",
                "gv_sig": "8B 0D ?? ?? ?? ??",
                "gv_sig_va": "0x1801ba12a",
                "gv_inst_offset": 0,
                "gv_inst_length": 6,
                "gv_inst_disp": 2,
            },
            result,
        )

    async def test_preprocess_gen_func_sig_via_mcp_defaults_to_function_boundary(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = False", code)
                self.assertIn(
                    "limit_end = min(f.end_ea, target_ea + max_sig_bytes)",
                    code,
                )
                return _py_eval_payload(
                    {
                        "func_va": "0x180123450",
                        "func_size": "0x40",
                        "insts": [
                            {
                                "ea": "0x180123450",
                                "size": 7,
                                "bytes": "488b0d78563412",
                                "wild": [3, 4, 5, 6],
                            }
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(
                    ["48 8B 0D ?? ?? ?? ??"],
                    arguments["patterns"],
                )
                return _FakeCallToolResult(
                    [
                        {
                            "matches": ["0x180123450"],
                            "n": 1,
                        }
                    ]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_func_sig_via_mcp(
            session=session,
            func_va="0x180123450",
            image_base=0x180000000,
            min_sig_bytes=6,
            debug=False,
        )

        self.assertEqual(
            {
                "func_va": "0x180123450",
                "func_rva": "0x123450",
                "func_size": "0x40",
                "func_sig": "48 8B 0D ?? ?? ?? ??",
            },
            result,
        )

    async def test_preprocess_gen_func_sig_via_mcp_guards_cross_boundary_decode(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = True", code)
                self.assertIn("PAD_BYTES = {0xCC, 0x90}", code)
                self.assertIn("SEGPERM_EXEC", code)
                self.assertIn("def _is_same_exec_segment", code)
                self.assertIn("def _consume_padding", code)
                self.assertIn("def _try_decode_padding_nop", code)
                self.assertIn("if mnem == 'nop':", code)
                self.assertIn(
                    "cursor >= f.end_ea or not ida_bytes.is_code(flags) "
                    "or not ida_bytes.is_head(flags)",
                    code,
                )
                self.assertIn(
                    "if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):\n"
                    "            return cursor, padding, True",
                    code,
                )
                return _py_eval_payload(
                    {
                        "func_va": "0x180123450",
                        "func_size": "0x40",
                        "insts": [
                            {
                                "ea": "0x180123450",
                                "size": 7,
                                "bytes": "488b0d78563412",
                                "wild": [3, 4, 5, 6],
                            }
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(
                    ["48 8B 0D ?? ?? ?? ??"],
                    arguments["patterns"],
                )
                return _FakeCallToolResult(
                    [
                        {
                            "matches": ["0x180123450"],
                            "n": 1,
                        }
                    ]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_func_sig_via_mcp(
            session=session,
            func_va="0x180123450",
            image_base=0x180000000,
            min_sig_bytes=6,
            allow_across_function_boundary=True,
            debug=False,
        )

        self.assertEqual(
            {
                "func_va": "0x180123450",
                "func_rva": "0x123450",
                "func_size": "0x40",
                "func_sig": "48 8B 0D ?? ?? ?? ??",
            },
            result,
        )

    async def test_preprocess_gen_func_sig_via_mcp_guards_internal_gap_decode(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = True", code)
                self.assertIn("def _consume_padding", code)
                self.assertIn("def _try_decode_padding_nop", code)
                self.assertIn("if mnem == 'nop':", code)
                self.assertIn(
                    "cursor >= f.end_ea or not ida_bytes.is_code(flags) "
                    "or not ida_bytes.is_head(flags)",
                    code,
                )
                return _py_eval_payload(
                    {
                        "func_va": "0x180123450",
                        "func_size": "0x40",
                        "insts": [
                            {
                                "ea": "0x180123450",
                                "size": 7,
                                "bytes": "488b0d78563412",
                                "wild": [3, 4, 5, 6],
                            }
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(
                    ["48 8B 0D ?? ?? ?? ??"],
                    arguments["patterns"],
                )
                return _FakeCallToolResult(
                    [
                        {
                            "matches": ["0x180123450"],
                            "n": 1,
                        }
                    ]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_func_sig_via_mcp(
            session=session,
            func_va="0x180123450",
            image_base=0x180000000,
            min_sig_bytes=6,
            allow_across_function_boundary=True,
            debug=False,
        )

        self.assertEqual(
            {
                "func_va": "0x180123450",
                "func_rva": "0x123450",
                "func_size": "0x40",
                "func_sig": "48 8B 0D ?? ?? ?? ??",
            },
            result,
        )

    def test_build_signature_boundary_py_eval_helpers_allows_zero_padding_code_head(
        self,
    ) -> None:
        helper_code = ida_analyze_util._build_signature_boundary_py_eval_helpers()

        self.assertIn("import idc\n", helper_code)
        self.assertIn("def _try_decode_padding_nop", helper_code)
        self.assertIn(
            "get_canon_mnem = getattr(insn, 'get_canon_mnem', None)",
            helper_code,
        )
        self.assertIn(
            "mnem = (idc.print_insn_mnem(cursor) or '').lower()",
            helper_code,
        )
        self.assertIn(
            "if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):\n"
            "            return cursor, padding, True",
            helper_code,
        )
        self.assertNotIn(
            "if pad_buf and ida_bytes.is_code(flags) and ida_bytes.is_head(flags):",
            helper_code,
        )
        self.assertLess(
            helper_code.index(
                "if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):\n"
                "            return cursor, padding, True"
            ),
            helper_code.index("b = ida_bytes.get_byte(cursor)"),
        )

    def test_build_signature_boundary_py_eval_helpers_stops_padding_at_code_head(
        self,
    ) -> None:
        helper_code = ida_analyze_util._build_signature_boundary_py_eval_helpers()

        self.assertIn(
            "nop_inst = _try_decode_padding_nop(cursor, limit_end)\n"
            "        if nop_inst:\n"
            "            padding.append(nop_inst)\n"
            "            cursor += nop_inst['size']\n"
            "            continue\n"
            "        b = ida_bytes.get_byte(cursor)\n"
            "        if b == idaapi.BADADDR or b not in PAD_BYTES:\n"
            "            return cursor, padding, False",
            helper_code,
        )
        self.assertIn(
            "while cursor < limit_end and _is_same_exec_segment(cursor, seg_start_ea):\n"
            "            flags = ida_bytes.get_full_flags(cursor)\n"
            "            if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):\n"
            "                break\n"
            "            nop_inst = _try_decode_padding_nop(cursor, limit_end)\n"
            "            if nop_inst:\n"
            "                break\n"
            "            b = ida_bytes.get_byte(cursor)\n"
            "            if b == idaapi.BADADDR or b not in PAD_BYTES:\n"
            "                return cursor, padding, False\n"
            "            pad_buf.append(b)\n"
            "            cursor += 1",
            helper_code,
        )

    def test_build_signature_boundary_py_eval_helpers_recognizes_multibyte_nop_padding(
        self,
    ) -> None:
        helper_code = ida_analyze_util._build_signature_boundary_py_eval_helpers()

        self.assertIn(
            "def _try_decode_padding_nop(cursor, limit_end):\n"
            "    insn = idautils.DecodeInstruction(cursor)\n"
            "    if not insn or insn.size <= 0 or cursor + insn.size > limit_end:\n"
            "        return None\n"
            "    get_canon_mnem = getattr(insn, 'get_canon_mnem', None)\n"
            "    mnem = ''\n"
            "    if callable(get_canon_mnem):\n"
            "        try:\n"
            "            mnem = (get_canon_mnem() or '').lower()\n"
            "        except Exception:\n"
            "            mnem = ''\n"
            "    if not mnem:\n"
            "        mnem = (idc.print_insn_mnem(cursor) or '').lower()\n"
            "    if mnem == 'nop':\n"
            "        raw = ida_bytes.get_bytes(cursor, insn.size)\n"
            "        if raw and len(raw) == insn.size:\n"
            "            return {'ea': hex(cursor), 'size': insn.size, 'bytes': raw.hex(), 'wild': []}\n"
            "    return None",
            helper_code,
        )

    def test_build_signature_boundary_py_eval_helpers_syncs_split_exec_scope(
        self,
    ) -> None:
        helper_code = ida_analyze_util._build_signature_boundary_py_eval_helpers()
        original_idc = sys.modules.get("idc")
        sys.modules["idc"] = types.SimpleNamespace(
            print_insn_mnem=lambda _cursor: "",
        )

        try:
            fake_segment = types.SimpleNamespace(start_ea=0x1000, perm=4)
            exec_globals = {
                "idaapi": types.SimpleNamespace(
                    BADADDR=-1,
                    SEGPERM_EXEC=4,
                    getseg=lambda _ea: fake_segment,
                ),
                "ida_bytes": types.SimpleNamespace(
                    get_full_flags=lambda _ea: 1,
                    get_byte=lambda _ea: 0xCC,
                    get_bytes=lambda _ea, size: b"\x90" * size,
                    is_code=lambda _flags: True,
                    is_head=lambda _flags: True,
                ),
                "idautils": types.SimpleNamespace(
                    DecodeInstruction=lambda _cursor: None,
                ),
            }
            exec_locals = {}

            exec(helper_code, exec_globals, exec_locals)
            result = exec_locals["_consume_padding"](0x1000, 0x1010, 0x1000)
        finally:
            if original_idc is None:
                sys.modules.pop("idc", None)
            else:
                sys.modules["idc"] = original_idc

        self.assertEqual((0x1000, [], True), result)

    async def test_preprocess_gen_vfunc_sig_via_mcp_generates_current_version_sig(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("target_vfunc_offset = 120", code)
                self.assertIn("target_inst = 6442757059", code)
                self.assertIn("globals().update(locals())", code)
                self.assertIn("allow_across_boundary = False", code)
                self.assertIn(
                    "limit_end = min(f.end_ea, target_inst + max_sig_bytes)",
                    code,
                )
                return _py_eval_payload(
                    {
                        "vfunc_sig_va": "0x18004abc3",
                        "vfunc_inst_length": 6,
                        "vfunc_disp_offset": 2,
                        "vfunc_disp_size": 4,
                        "insts": [
                            {
                                "ea": "0x18004abc3",
                                "size": 6,
                                "bytes": "ff9078000000",
                                "wild": [],
                            },
                            {
                                "ea": "0x18004abc9",
                                "size": 3,
                                "bytes": "4885c0",
                                "wild": [],
                            },
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(
                    ["FF 90 78 00 00 00"],
                    arguments["patterns"],
                )
                return _FakeCallToolResult(
                    [
                        {
                            "matches": ["0x18004abc3"],
                            "n": 1,
                        }
                    ]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_vfunc_sig_via_mcp(
            session=session,
            inst_va="0x18004ABC3",
            vfunc_offset="0x78",
            debug=False,
        )

        self.assertEqual(
            {
                "vfunc_sig": "FF 90 78 00 00 00",
                "vfunc_sig_va": "0x18004abc3",
                "vfunc_sig_disp": 0,
                "vfunc_inst_length": 6,
                "vfunc_disp_offset": 2,
                "vfunc_disp_size": 4,
                "vfunc_offset": "0x78",
                "vfunc_sig_max_match": 1,
            },
            result,
        )

    async def test_preprocess_gen_vfunc_sig_via_mcp_accepts_implicit_zero_slot(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn(
                    "import idaapi, ida_bytes, idautils, ida_ua, idc, json",
                    code,
                )
                self.assertIn("def _has_implicit_zero_vfunc_slot", code)
                self.assertIn("target_vfunc_offset == 0", code)
                self.assertIn("disp_off, disp_size = 0, 0", code)
                return _py_eval_payload(
                    {
                        "vfunc_sig_va": "0x18004abc3",
                        "vfunc_inst_length": 2,
                        "vfunc_disp_offset": 0,
                        "vfunc_disp_size": 0,
                        "insts": [
                            {
                                "ea": "0x18004abc3",
                                "size": 2,
                                "bytes": "ff10",
                                "wild": [],
                            },
                            {
                                "ea": "0x18004abc5",
                                "size": 3,
                                "bytes": "488bd8",
                                "wild": [],
                            },
                            {
                                "ea": "0x18004abc8",
                                "size": 3,
                                "bytes": "4885db",
                                "wild": [],
                            },
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(
                    ["FF 10 48 8B D8 48 85 DB"],
                    arguments["patterns"],
                )
                return _FakeCallToolResult(
                    [
                        {
                            "matches": ["0x18004abc3"],
                            "n": 1,
                        }
                    ]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_vfunc_sig_via_mcp(
            session=session,
            inst_va="0x18004ABC3",
            vfunc_offset="0x0",
            debug=False,
        )

        self.assertEqual(
            {
                "vfunc_sig": "FF 10 48 8B D8 48 85 DB",
                "vfunc_sig_va": "0x18004abc3",
                "vfunc_sig_disp": 0,
                "vfunc_inst_length": 2,
                "vfunc_disp_offset": 0,
                "vfunc_disp_size": 0,
                "vfunc_offset": "0x0",
                "vfunc_sig_max_match": 1,
            },
            result,
        )

    async def test_preprocess_gen_vfunc_sig_via_mcp_accepts_match_count_within_limit(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                return _py_eval_payload(
                    {
                        "vfunc_sig_va": "0x18004abc3",
                        "vfunc_inst_length": 6,
                        "vfunc_disp_offset": 2,
                        "vfunc_disp_size": 4,
                        "insts": [
                            {
                                "ea": "0x18004abc3",
                                "size": 6,
                                "bytes": "ff9078000000",
                                "wild": [],
                            },
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(["FF 90 78 00 00 00"], arguments["patterns"])
                self.assertEqual(11, arguments["limit"])
                return _FakeCallToolResult(
                    [
                        {
                            "matches": ["0x18004abc3", "0x18010abc3"],
                            "n": 2,
                        }
                    ]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_vfunc_sig_via_mcp(
            session=session,
            inst_va="0x18004ABC3",
            vfunc_offset="0x78",
            max_match_count=10,
            debug=False,
        )

        self.assertEqual("FF 90 78 00 00 00", result["vfunc_sig"])
        self.assertEqual(10, result["vfunc_sig_max_match"])

    async def test_preprocess_gen_vfunc_sig_via_mcp_rejects_match_count_over_limit(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                return _py_eval_payload(
                    {
                        "vfunc_sig_va": "0x18004abc3",
                        "vfunc_inst_length": 6,
                        "vfunc_disp_offset": 2,
                        "vfunc_disp_size": 4,
                        "insts": [
                            {
                                "ea": "0x18004abc3",
                                "size": 6,
                                "bytes": "ff9078000000",
                                "wild": [],
                            },
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(["FF 90 78 00 00 00"], arguments["patterns"])
                self.assertEqual(11, arguments["limit"])
                return _FakeCallToolResult(
                    [
                        {
                            "matches": ["0x18004abc3"],
                            "n": 11,
                        }
                    ]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_vfunc_sig_via_mcp(
            session=session,
            inst_va="0x18004ABC3",
            vfunc_offset="0x78",
            max_match_count=10,
            debug=False,
        )

        self.assertIsNone(result)

    async def test_preprocess_gen_vfunc_sig_via_mcp_rejects_match_set_without_target_inst(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                return _py_eval_payload(
                    {
                        "vfunc_sig_va": "0x18004abc3",
                        "vfunc_inst_length": 6,
                        "vfunc_disp_offset": 2,
                        "vfunc_disp_size": 4,
                        "insts": [
                            {
                                "ea": "0x18004abc3",
                                "size": 6,
                                "bytes": "ff9078000000",
                                "wild": [],
                            },
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(["FF 90 78 00 00 00"], arguments["patterns"])
                self.assertEqual(11, arguments["limit"])
                return _FakeCallToolResult(
                    [
                        {
                            "matches": ["0x18010abc3", "0x18020abc3"],
                            "n": 2,
                        }
                    ]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_vfunc_sig_via_mcp(
            session=session,
            inst_va="0x18004ABC3",
            vfunc_offset="0x78",
            max_match_count=10,
            debug=False,
        )

        self.assertIsNone(result)

    async def test_preprocess_gen_struct_offset_sig_via_mcp_logs_missing_py_eval_candidates(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload([])

        with patch("builtins.print") as mock_print:
            result = await ida_analyze_util.preprocess_gen_struct_offset_sig_via_mcp(
                session=session,
                struct_name="CGameResourceService",
                member_name="m_pEntitySystem",
                offset="0x58",
                offset_inst_va="0x1801BA12A",
                image_base=0x180000000,
                size=8,
                min_sig_bytes=4,
                debug=True,
            )

        self.assertIsNone(result)
        printed = "\n".join(
            str(args[0]) for args, _ in mock_print.call_args_list if args
        )
        self.assertIn(
            "no candidate instruction stream from py_eval",
            printed,
        )
        self.assertIn("CGameResourceService.m_pEntitySystem", printed)
        self.assertIn("0x1801ba12a", printed)

    async def test_preprocess_gen_struct_offset_sig_via_mcp_logs_py_eval_payload_shape(
        self,
    ) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _FakeCallToolResult(
            {
                "result": json.dumps({"unexpected": "mapping"}),
                "stdout": "",
                "stderr": "Traceback: simulated IDA warning",
            }
        )

        with patch("builtins.print") as mock_print:
            result = await ida_analyze_util.preprocess_gen_struct_offset_sig_via_mcp(
                session=session,
                struct_name="CGameResourceService",
                member_name="m_pEntitySystem",
                offset="0x58",
                offset_inst_va="0x1801BA12A",
                image_base=0x180000000,
                size=8,
                min_sig_bytes=4,
                debug=True,
            )

        self.assertIsNone(result)
        printed = "\n".join(
            str(args[0]) for args, _ in mock_print.call_args_list if args
        )
        self.assertIn("struct offset py_eval stderr", printed)
        self.assertIn("Traceback: simulated IDA warning", printed)
        self.assertIn("struct offset py_eval result shape", printed)
        self.assertIn("candidate_infos_type=dict", printed)
        self.assertIn("candidate_count=<not-list>", printed)

    async def test_preprocess_gen_struct_offset_sig_via_mcp_logs_find_bytes_rejections(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
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
                pattern = arguments["patterns"][0]
                if pattern == "49 8B 4E ??":
                    return _FakeCallToolResult(
                        [
                            {
                                "matches": [],
                                "n": 0,
                            }
                        ]
                    )
                if pattern == "49 8B 4E ?? 48 85 C9":
                    return _FakeCallToolResult(
                        [
                            {
                                "matches": ["0x1801BA12A", "0x1801BA200"],
                                "n": 2,
                            }
                        ]
                    )
                raise AssertionError(f"unexpected pattern: {pattern}")
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        with patch("builtins.print") as mock_print:
            result = await ida_analyze_util.preprocess_gen_struct_offset_sig_via_mcp(
                session=session,
                struct_name="CGameResourceService",
                member_name="m_pEntitySystem",
                offset="0x58",
                offset_inst_va="0x1801BA12A",
                image_base=0x180000000,
                size=8,
                min_sig_bytes=4,
                debug=True,
            )

        self.assertIsNone(result)
        printed = "\n".join(
            str(args[0]) for args, _ in mock_print.call_args_list if args
        )
        self.assertIn("candidate rejected with zero find_bytes matches", printed)
        self.assertIn("candidate rejected with 2 find_bytes matches", printed)
        self.assertIn("sig=49 8B 4E ??", printed)
        self.assertIn("sig=49 8B 4E ?? 48 85 C9", printed)
        self.assertIn("hits=<none>", printed)
        self.assertIn("0x1801ba12a", printed)
        self.assertIn("0x1801ba200", printed)

    async def test_preprocess_common_skill_logs_struct_member_name_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "server"
            target_output = module_dir / "CBaseAnimGraph_m_skeletonInstance.windows.yaml"
            old_path = module_dir / "old" / "CBaseAnimGraph_m_skeletonInstance.windows.yaml"
            _write_yaml(
                old_path,
                {
                    "struct_name": "CBaseAnimGraph",
                    "member_name": "m_skeletonInstance",
                    "offset": "0x278",
                    "size": 8,
                },
            )

            session = AsyncMock()
            llm_request = {
                "client": None,
                "model": "gpt-5.4",
                "prompt_path": "/tmp/prompt.md",
                "reference_yaml_path": "/tmp/reference.yaml",
                "prompt_template": "ignored",
                "target_func_name": "CBaseAnimGraph_GetAnimationController",
                "disasm_for_reference": "",
                "procedure_for_reference": "",
            }

            with patch.object(
                ida_analyze_util,
                "preprocess_struct_offset_sig_via_mcp",
                AsyncMock(return_value=None),
            ), patch.object(
                ida_analyze_util,
                "_prepare_llm_decompile_request",
                return_value=llm_request,
            ), patch.object(
                ida_analyze_util,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(
                    return_value=[
                        {
                            "disasm_code": "mov rcx, [rcx+278h]",
                            "procedure": "return this->m_skeletonInstance;",
                        }
                    ]
                ),
            ), patch.object(
                ida_analyze_util,
                "call_llm_decompile",
                AsyncMock(
                    return_value={
                        "found_vcall": [],
                        "found_call": [],
                        "found_funcptr": [],
                        "found_gv": [],
                        "found_struct_offset": [
                            {
                                "insn_va": "0x180A76B04",
                                "insn_disasm": "mov rcx, [rcx+278h]",
                                "offset": "0x278",
                                "struct_name": "CSomeOtherStruct",
                                "member_name": "m_wrongField",
                                "size": "8",
                            }
                        ],
                    }
                ),
            ), patch("builtins.print") as mock_print:
                result = await ida_analyze_util.preprocess_common_skill(
                    session=session,
                    expected_outputs=[str(target_output)],
                    old_yaml_map={str(target_output): str(old_path)},
                    new_binary_dir=str(module_dir),
                    platform="windows",
                    image_base=0x180000000,
                    struct_member_names=["CBaseAnimGraph_m_skeletonInstance"],
                    llm_decompile_specs=[
                        (
                            "CBaseAnimGraph_m_skeletonInstance",
                            "prompt/call_llm_decompile.md",
                            "references/server/CBaseAnimGraph_GetAnimationController.windows.yaml",
                        )
                    ],
                    llm_config={"model": "gpt-5.4"},
                    generate_yaml_desired_fields=[
                        (
                            "CBaseAnimGraph_m_skeletonInstance",
                            [
                                "struct_name",
                                "member_name",
                                "offset",
                                "size",
                                "offset_sig",
                                "offset_sig_disp",
                            ],
                        )
                    ],
                    debug=True,
                )

        self.assertFalse(result)
        printed = "\n".join(
            str(args[0]) for args, _ in mock_print.call_args_list if args
        )
        self.assertIn(
            "struct-member name mismatch for CBaseAnimGraph_m_skeletonInstance",
            printed,
        )
        self.assertIn(
            "expected CBaseAnimGraph.m_skeletonInstance",
            printed,
        )
        self.assertIn(
            "got CSomeOtherStruct.m_wrongField",
            printed,
        )

    async def test_preprocess_gen_vfunc_sig_via_mcp_guards_cross_boundary_decode(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = True", code)
                self.assertIn("PAD_BYTES = {0xCC, 0x90}", code)
                self.assertIn("SEGPERM_EXEC", code)
                self.assertIn("def _is_same_exec_segment", code)
                self.assertIn("def _consume_padding", code)
                self.assertIn("def _try_decode_padding_nop", code)
                self.assertIn("if mnem == 'nop':", code)
                self.assertIn(
                    "cursor >= f.end_ea or not ida_bytes.is_code(flags) "
                    "or not ida_bytes.is_head(flags)",
                    code,
                )
                self.assertIn(
                    "if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):\n"
                    "            return cursor, padding, True",
                    code,
                )
                return _py_eval_payload(
                    {
                        "vfunc_sig_va": "0x18004abc3",
                        "vfunc_inst_length": 6,
                        "vfunc_disp_offset": 2,
                        "vfunc_disp_size": 4,
                        "insts": [
                            {
                                "ea": "0x18004abc3",
                                "size": 6,
                                "bytes": "ff9078000000",
                                "wild": [],
                            },
                            {
                                "ea": "0x18004abc9",
                                "size": 3,
                                "bytes": "4885c0",
                                "wild": [],
                            },
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(
                    ["FF 90 78 00 00 00"],
                    arguments["patterns"],
                )
                return _FakeCallToolResult(
                    [
                        {
                            "matches": ["0x18004abc3"],
                            "n": 1,
                        }
                    ]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_vfunc_sig_via_mcp(
            session=session,
            inst_va="0x18004ABC3",
            vfunc_offset="0x78",
            allow_across_function_boundary=True,
            debug=False,
        )

        self.assertEqual(
            {
                "vfunc_sig": "FF 90 78 00 00 00",
                "vfunc_sig_va": "0x18004abc3",
                "vfunc_sig_disp": 0,
                "vfunc_inst_length": 6,
                "vfunc_disp_offset": 2,
                "vfunc_disp_size": 4,
                "vfunc_offset": "0x78",
                "vfunc_sig_max_match": 1,
            },
            result,
        )

    async def test_preprocess_gen_vfunc_sig_via_mcp_guards_internal_gap_decode(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = True", code)
                self.assertIn("def _consume_padding", code)
                self.assertIn("def _try_decode_padding_nop", code)
                self.assertIn("if mnem == 'nop':", code)
                self.assertIn(
                    "cursor >= f.end_ea or not ida_bytes.is_code(flags) "
                    "or not ida_bytes.is_head(flags)",
                    code,
                )
                return _py_eval_payload(
                    {
                        "vfunc_sig_va": "0x18004abc3",
                        "vfunc_inst_length": 6,
                        "vfunc_disp_offset": 2,
                        "vfunc_disp_size": 4,
                        "insts": [
                            {
                                "ea": "0x18004abc3",
                                "size": 6,
                                "bytes": "ff9078000000",
                                "wild": [],
                            },
                            {
                                "ea": "0x18004abc9",
                                "size": 3,
                                "bytes": "4885c0",
                                "wild": [],
                            },
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(
                    ["FF 90 78 00 00 00"],
                    arguments["patterns"],
                )
                return _FakeCallToolResult(
                    [
                        {
                            "matches": ["0x18004abc3"],
                            "n": 1,
                        }
                    ]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_vfunc_sig_via_mcp(
            session=session,
            inst_va="0x18004ABC3",
            vfunc_offset="0x78",
            allow_across_function_boundary=True,
            debug=False,
        )

        self.assertEqual(
            {
                "vfunc_sig": "FF 90 78 00 00 00",
                "vfunc_sig_va": "0x18004abc3",
                "vfunc_sig_disp": 0,
                "vfunc_inst_length": 6,
                "vfunc_disp_offset": 2,
                "vfunc_disp_size": 4,
                "vfunc_offset": "0x78",
                "vfunc_sig_max_match": 1,
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
            expected_detail_export_code = _function_detail_export_py_eval(
                target_detail_payload["func_va"]
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
                if code == expected_detail_export_code:
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
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
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
                        "max_retries": 4,
                        "retry_initial_delay": 0,
                        "retry_backoff_factor": 1.5,
                        "retry_max_delay": 2,
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
        self.assertEqual(
            [func_name],
            mock_call_llm_decompile.call_args.kwargs["symbol_name_list"],
        )
        self.assertEqual(4, mock_call_llm_decompile.call_args.kwargs["max_retries"])
        self.assertEqual(
            0,
            mock_call_llm_decompile.call_args.kwargs["retry_initial_delay"],
        )
        self.assertEqual(
            1.5,
            mock_call_llm_decompile.call_args.kwargs["retry_backoff_factor"],
        )
        self.assertEqual(
            2,
            mock_call_llm_decompile.call_args.kwargs["retry_max_delay"],
        )
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(func_name, written_payload["func_name"])
        self.assertEqual("0x68", written_payload["vfunc_offset"])
        self.assertEqual(13, written_payload["vfunc_index"])

    async def test_preprocess_common_skill_batches_same_llm_request_for_multiple_unresolved_targets(
        self,
    ) -> None:
        func_names = [
            "CNetworkMessages_FindNetworkGroup",
            "CNetworkMessages_FindMessage",
        ]
        output_paths = [f"/tmp/{func_name}.windows.yaml" for func_name in func_names]
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
                    "func_name": func_names[0],
                },
                {
                    "insn_va": "0x180777710",
                    "insn_disasm": "call    sub_180222210",
                    "func_name": func_names[1],
                },
            ],
            "found_gv": [],
            "found_struct_offset": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )
            fake_client = object()

            async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
                return {
                    "func_name": kwargs["func_name"],
                    "func_va": str(kwargs["direct_func_va"]).strip().lower(),
                }

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
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(side_effect=["0x180123450", "0x180223450"]),
            ), patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
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
                    session="session",
                    expected_outputs=output_paths,
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=func_names,
                    generate_yaml_desired_fields=[
                        (func_names[0], ["func_name", "func_va"]),
                        (func_names[1], ["func_name", "func_va"]),
                    ],
                    llm_decompile_specs=[
                        (
                            func_names[0],
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                        (
                            func_names[1],
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_call_llm_decompile.assert_awaited_once()
        self.assertEqual(
            func_names,
            mock_call_llm_decompile.call_args.kwargs["symbol_name_list"],
        )
        self.assertEqual(2, mock_write_func_yaml.call_count)

    async def test_preprocess_common_skill_llm_batch_excludes_fast_path_targets(
        self,
    ) -> None:
        unresolved_func_name = "CNetworkMessages_FindNetworkGroup"
        fast_path_func_name = "CNetworkMessages_FindMessage"
        func_names = [unresolved_func_name, fast_path_func_name]
        output_paths = [f"/tmp/{func_name}.windows.yaml" for func_name in func_names]
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
                    "func_name": unresolved_func_name,
                }
            ],
            "found_gv": [],
            "found_struct_offset": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )

            async def _fake_preprocess_func_sig_via_mcp(*, func_name, **_kwargs):
                if func_name == fast_path_func_name:
                    return {
                        "func_name": fast_path_func_name,
                        "func_va": "0x180333333",
                    }
                return None

            async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
                return {
                    "func_name": kwargs["func_name"],
                    "func_va": str(kwargs["direct_func_va"]).strip().lower(),
                }

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
                AsyncMock(side_effect=_fake_preprocess_func_sig_via_mcp),
            ), patch.object(
                ida_analyze_util,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(return_value="0x180123450"),
            ), patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
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
                    session="session",
                    expected_outputs=output_paths,
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=func_names,
                    generate_yaml_desired_fields=[
                        (unresolved_func_name, ["func_name", "func_va"]),
                        (fast_path_func_name, ["func_name", "func_va"]),
                    ],
                    llm_decompile_specs=[
                        (
                            unresolved_func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                        (
                            fast_path_func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_call_llm_decompile.assert_awaited_once()
        self.assertEqual(
            [unresolved_func_name],
            mock_call_llm_decompile.call_args.kwargs["symbol_name_list"],
        )
        self.assertEqual(2, mock_write_func_yaml.call_count)

    async def test_preprocess_common_skill_llm_batch_includes_unresolved_gv_targets(
        self,
    ) -> None:
        func_name = "CNetChan_ParseNetMessageShowFilter"
        gv_name = "g_pLoggingChannel"
        output_paths = [
            f"/tmp/{func_name}.windows.yaml",
            f"/tmp/{gv_name}.windows.yaml",
        ]
        target_detail_payload = {
            "func_name": "CNetChan_ParseMessagesDemoInternal",
            "func_va": "0x180555500",
            "disasm_code": "call    CNetChan_ParseNetMessageShowFilter\nmov     ecx, cs:g_pLoggingChannel",
            "procedure": "CNetChan_ParseNetMessageShowFilter(...); LoggingSystem_Log(g_pLoggingChannel, ...);",
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
            "found_gv": [
                {
                    "insn_va": "0x180777710",
                    "insn_disasm": "mov     ecx, cs:g_pLoggingChannel",
                    "gv_name": gv_name,
                }
            ],
            "found_struct_offset": [],
        }

        async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
            return {
                "func_name": kwargs["func_name"],
                "func_va": str(kwargs["direct_func_va"]).strip().lower(),
            }

        async def _fake_preprocess_direct_gv_sig_via_mcp(**kwargs):
            return {
                "gv_name": kwargs["gv_name"],
                "gv_va": str(kwargs["direct_gv_va"]).strip().lower(),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )

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
                "preprocess_gv_sig_via_mcp",
                AsyncMock(return_value=None),
            ), patch.object(
                ida_analyze_util,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(return_value="0x180123450"),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_gv_target_via_mcp",
                AsyncMock(return_value="0x180223450"),
                create=True,
            ), patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
            ), patch.object(
                ida_analyze_util,
                "_preprocess_direct_gv_sig_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_direct_gv_sig_via_mcp),
                create=True,
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
                "write_gv_yaml",
            ) as mock_write_gv_yaml, patch.object(
                ida_analyze_util,
                "_rename_func_in_ida",
                AsyncMock(return_value=None),
            ), patch.object(
                ida_analyze_util,
                "_rename_gv_in_ida",
                AsyncMock(return_value=None),
            ):
                result = await ida_analyze_util.preprocess_common_skill(
                    session="session",
                    expected_outputs=output_paths,
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    gv_names=[gv_name],
                    generate_yaml_desired_fields=[
                        (func_name, ["func_name", "func_va"]),
                        (gv_name, ["gv_name", "gv_va"]),
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                        (
                            gv_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_call_llm_decompile.assert_awaited_once()
        self.assertEqual(
            [func_name, gv_name],
            mock_call_llm_decompile.call_args.kwargs["symbol_name_list"],
        )
        mock_write_func_yaml.assert_called_once()
        mock_write_gv_yaml.assert_called_once()

    async def test_preprocess_common_skill_llm_batch_includes_unresolved_struct_targets(
        self,
    ) -> None:
        func_name = "CGameResourceService_BuildResourceManifest"
        struct_member_name = "CGameResourceService_m_pEntitySystem"
        output_paths = [
            f"/tmp/{func_name}.windows.yaml",
            f"/tmp/{struct_member_name}.windows.yaml",
        ]
        old_struct_yaml_path = Path(tempfile.gettempdir()) / f"{struct_member_name}.old.yaml"
        target_detail_payload = {
            "func_name": "CGameResourceService_BuildResourceManifest",
            "func_va": "0x180555500",
            "disasm_code": (
                "call    sub_180222200\n"
                "mov     rcx, [r14+58h]"
            ),
            "procedure": (
                "CGameResourceService_BuildResourceManifest(...);\n"
                "return this->m_pEntitySystem;"
            ),
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
            "found_struct_offset": [
                {
                    "insn_va": "0x180777710",
                    "insn_disasm": "mov     rcx, [r14+58h]",
                    "offset": "0x58",
                    "size": "8",
                    "struct_name": "CGameResourceService",
                    "member_name": "m_pEntitySystem",
                }
            ],
        }

        async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
            return {
                "func_name": kwargs["func_name"],
                "func_va": str(kwargs["direct_func_va"]).strip().lower(),
            }

        try:
            _write_yaml(
                old_struct_yaml_path,
                {
                    "struct_name": "CGameResourceService",
                    "member_name": "m_pEntitySystem",
                    "offset": "0x50",
                    "size": 8,
                    "offset_sig": "49 8B 4E 50",
                },
            )

            with tempfile.TemporaryDirectory() as temp_dir:
                preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
                (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
                (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                    "{symbol_name_list}",
                    encoding="utf-8",
                )
                _write_yaml(
                    preprocessor_dir / "references" / "reference.yaml",
                    {
                        "func_name": target_detail_payload["func_name"],
                        "disasm_code": target_detail_payload["disasm_code"],
                        "procedure": target_detail_payload["procedure"],
                    },
                )

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
                    "preprocess_struct_offset_sig_via_mcp",
                    AsyncMock(return_value=None),
                ), patch.object(
                    ida_analyze_util,
                    "_load_llm_decompile_target_details_via_mcp",
                    AsyncMock(return_value=[target_detail_payload]),
                ), patch.object(
                    ida_analyze_util,
                    "_resolve_direct_call_target_via_mcp",
                    AsyncMock(return_value="0x180123450"),
                ), patch.object(
                    ida_analyze_util,
                    "_preprocess_direct_func_sig_via_mcp",
                    AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
                ), patch.object(
                    ida_analyze_util,
                    "_preprocess_direct_struct_offset_sig_via_mcp",
                    AsyncMock(
                        return_value={
                            "struct_name": "CGameResourceService",
                            "member_name": "m_pEntitySystem",
                            "offset": "0x58",
                            "size": 8,
                            "offset_sig": "49 8B 4E ??",
                            "offset_sig_disp": 0,
                        }
                    ),
                    create=True,
                ) as mock_preprocess_direct_struct_offset_sig, patch.object(
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
                    "write_struct_offset_yaml",
                ) as mock_write_struct_offset_yaml, patch.object(
                    ida_analyze_util,
                    "_rename_func_in_ida",
                    AsyncMock(return_value=None),
                ):
                    result = await ida_analyze_util.preprocess_common_skill(
                        session="session",
                        expected_outputs=output_paths,
                        old_yaml_map={
                            output_paths[1]: str(old_struct_yaml_path),
                        },
                        new_binary_dir="/tmp",
                        platform="windows",
                        image_base=0x180000000,
                        func_names=[func_name],
                        struct_member_names=[struct_member_name],
                        generate_yaml_desired_fields=[
                            (func_name, ["func_name", "func_va"]),
                            (
                                struct_member_name,
                                [
                                    "struct_name",
                                    "member_name",
                                    "offset",
                                    "size",
                                    "offset_sig",
                                    "offset_sig_disp",
                                ],
                            ),
                        ],
                        llm_decompile_specs=[
                            (
                                func_name,
                                "prompt/call_llm_decompile.md",
                                "references/reference.yaml",
                            ),
                            (
                                struct_member_name,
                                "prompt/call_llm_decompile.md",
                                "references/reference.yaml",
                            ),
                        ],
                        llm_config={
                            "model": "gpt-4.1-mini",
                            "api_key": "test-api-key",
                        },
                        debug=True,
                    )
        finally:
            if old_struct_yaml_path.exists():
                old_struct_yaml_path.unlink()

        self.assertTrue(result)
        mock_call_llm_decompile.assert_awaited_once()
        self.assertEqual(
            [func_name, struct_member_name],
            mock_call_llm_decompile.call_args.kwargs["symbol_name_list"],
        )
        mock_preprocess_direct_struct_offset_sig.assert_awaited_once_with(
            session="session",
            new_path=output_paths[1],
            image_base=0x180000000,
            struct_member_name=struct_member_name,
            struct_name="CGameResourceService",
            member_name="m_pEntitySystem",
            offset="0x58",
            offset_inst_va="0x180777710",
            size="8",
            old_path=str(old_struct_yaml_path),
            allow_across_function_boundary=False,
            debug=True,
        )
        mock_write_func_yaml.assert_called_once()
        mock_write_struct_offset_yaml.assert_called_once()
        written_payload = mock_write_struct_offset_yaml.call_args.args[1]
        self.assertEqual("CGameResourceService", written_payload["struct_name"])
        self.assertEqual("m_pEntitySystem", written_payload["member_name"])
        self.assertEqual("0x58", written_payload["offset"])
        self.assertEqual(8, written_payload["size"])
        self.assertEqual(0, written_payload["offset_sig_disp"])

    async def test_preprocess_common_skill_forwards_struct_offset_boundary_flag_and_writes_it(
        self,
    ) -> None:
        func_name = "CNetworkMessages_FindNetworkGroup"
        struct_member_name = "CGameResourceService_m_pEntitySystem"
        output_paths = [
            f"/tmp/{func_name}.windows.yaml",
            f"/tmp/{struct_member_name}.windows.yaml",
        ]
        old_struct_yaml_path = Path(tempfile.gettempdir()) / (
            f"{struct_member_name}.{id(self)}.windows.yaml"
        )
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
            "found_struct_offset": [
                {
                    "insn_va": "0x180777710",
                    "insn_disasm": "mov     rcx, [r14+58h]",
                    "offset": "0x58",
                    "size": "8",
                    "struct_name": "CGameResourceService",
                    "member_name": "m_pEntitySystem",
                }
            ],
        }

        async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
            return {
                "func_name": kwargs["func_name"],
                "func_va": str(kwargs["direct_func_va"]).strip().lower(),
            }

        try:
            _write_yaml(
                old_struct_yaml_path,
                {
                    "struct_name": "CGameResourceService",
                    "member_name": "m_pEntitySystem",
                    "offset": "0x50",
                    "size": 8,
                    "offset_sig": "49 8B 4E 50",
                },
            )

            with tempfile.TemporaryDirectory() as temp_dir:
                preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
                (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
                (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                    "{symbol_name_list}",
                    encoding="utf-8",
                )
                _write_yaml(
                    preprocessor_dir / "references" / "reference.yaml",
                    {
                        "func_name": target_detail_payload["func_name"],
                        "disasm_code": target_detail_payload["disasm_code"],
                        "procedure": target_detail_payload["procedure"],
                    },
                )

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
                    "preprocess_struct_offset_sig_via_mcp",
                    AsyncMock(return_value=None),
                ), patch.object(
                    ida_analyze_util,
                    "_load_llm_decompile_target_details_via_mcp",
                    AsyncMock(return_value=[target_detail_payload]),
                ), patch.object(
                    ida_analyze_util,
                    "_resolve_direct_call_target_via_mcp",
                    AsyncMock(return_value="0x180123450"),
                ), patch.object(
                    ida_analyze_util,
                    "_preprocess_direct_func_sig_via_mcp",
                    AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
                ), patch.object(
                    ida_analyze_util,
                    "_preprocess_direct_struct_offset_sig_via_mcp",
                    AsyncMock(
                        return_value={
                            "struct_name": "CGameResourceService",
                            "member_name": "m_pEntitySystem",
                            "offset": "0x58",
                            "size": 8,
                            "offset_sig": "49 8B 4E ??",
                            "offset_sig_disp": 0,
                        }
                    ),
                    create=True,
                ) as mock_preprocess_direct_struct_offset_sig, patch.object(
                    ida_analyze_util,
                    "call_llm_decompile",
                    create=True,
                    new_callable=AsyncMock,
                    return_value=normalized_payload,
                ), patch.object(
                    ida_analyze_util,
                    "write_func_yaml",
                ), patch.object(
                    ida_analyze_util,
                    "write_struct_offset_yaml",
                ) as mock_write_struct_offset_yaml, patch.object(
                    ida_analyze_util,
                    "_rename_func_in_ida",
                    AsyncMock(return_value=None),
                ):
                    result = await ida_analyze_util.preprocess_common_skill(
                        session="session",
                        expected_outputs=output_paths,
                        old_yaml_map={
                            output_paths[1]: str(old_struct_yaml_path),
                        },
                        new_binary_dir="/tmp",
                        platform="windows",
                        image_base=0x180000000,
                        func_names=[func_name],
                        struct_member_names=[struct_member_name],
                        generate_yaml_desired_fields=[
                            (func_name, ["func_name", "func_va"]),
                            (
                                struct_member_name,
                                [
                                    "struct_name",
                                    "member_name",
                                    "offset",
                                    "size",
                                    "offset_sig",
                                    "offset_sig_disp",
                                    "offset_sig_allow_across_function_boundary: true",
                                ],
                            ),
                        ],
                        llm_decompile_specs=[
                            (
                                func_name,
                                "prompt/call_llm_decompile.md",
                                "references/reference.yaml",
                            ),
                            (
                                struct_member_name,
                                "prompt/call_llm_decompile.md",
                                "references/reference.yaml",
                            ),
                        ],
                        llm_config={
                            "model": "gpt-4.1-mini",
                            "api_key": "test-api-key",
                        },
                        debug=True,
                    )
        finally:
            if old_struct_yaml_path.exists():
                old_struct_yaml_path.unlink()

        self.assertTrue(result)
        mock_preprocess_direct_struct_offset_sig.assert_awaited_once_with(
            session="session",
            new_path=output_paths[1],
            image_base=0x180000000,
            struct_member_name=struct_member_name,
            struct_name="CGameResourceService",
            member_name="m_pEntitySystem",
            offset="0x58",
            offset_inst_va="0x180777710",
            size="8",
            old_path=str(old_struct_yaml_path),
            allow_across_function_boundary=True,
            debug=True,
        )
        mock_write_struct_offset_yaml.assert_called_once()
        written_payload = mock_write_struct_offset_yaml.call_args.args[1]
        self.assertEqual(
            [
                "struct_name",
                "member_name",
                "offset",
                "size",
                "offset_sig",
                "offset_sig_disp",
                "offset_sig_allow_across_function_boundary",
            ],
            list(written_payload.keys()),
        )
        self.assertTrue(
            written_payload["offset_sig_allow_across_function_boundary"]
        )

    async def test_preprocess_common_skill_llm_batch_uses_xref_resolved_symbol_to_shrink_request(
        self,
    ) -> None:
        first_func_name = "CNetworkMessages_FindNetworkGroup"
        second_func_name = "CNetworkMessages_FindMessage"
        func_names = [first_func_name, second_func_name]
        target_detail_payload = {
            "func_name": "CNetworkGameClient_RecordEntityBandwidth",
            "func_va": "0x180555500",
            "disasm_code": "call    sub_180222200",
            "procedure": "return CNetworkMessages::FindNetworkGroup(this, group);",
        }
        llm_payload = {
            "found_vcall": [],
            "found_call": [
                {
                    "insn_va": "0x180777700",
                    "insn_disasm": "call    sub_180222200",
                    "func_name": first_func_name,
                }
            ],
            "found_gv": [],
            "found_struct_offset": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            new_binary_dir = Path(temp_dir) / "current"
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            first_output = new_binary_dir / f"{first_func_name}.windows.yaml"
            second_output = new_binary_dir / f"{second_func_name}.windows.yaml"
            output_paths = [str(first_output), str(second_output)]
            dependent_yaml_path = new_binary_dir / f"{first_func_name}.windows.yaml"

            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )

            async def _fake_preprocess_func_xrefs_via_mcp(*, func_name, **_kwargs):
                if func_name != second_func_name:
                    return None
                if dependent_yaml_path.is_file():
                    return {
                        "func_name": second_func_name,
                        "func_va": "0x180333333",
                    }
                return None

            async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
                return {
                    "func_name": kwargs["func_name"],
                    "func_va": str(kwargs["direct_func_va"]).strip().lower(),
                }

            def _fake_write_func_yaml(path, data):
                output_path = Path(path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(
                    yaml.safe_dump(data, sort_keys=False),
                    encoding="utf-8",
                )

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
                "preprocess_func_xrefs_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_func_xrefs_via_mcp),
            ), patch.object(
                ida_analyze_util,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(return_value="0x180123450"),
            ), patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
            ), patch.object(
                ida_analyze_util,
                "call_llm_decompile",
                create=True,
                new_callable=AsyncMock,
                return_value=llm_payload,
            ) as mock_call_llm_decompile, patch.object(
                ida_analyze_util,
                "write_func_yaml",
                side_effect=_fake_write_func_yaml,
            ) as mock_write_func_yaml, patch.object(
                ida_analyze_util,
                "_rename_func_in_ida",
                AsyncMock(return_value=None),
            ):
                result = await ida_analyze_util.preprocess_common_skill(
                    session="session",
                    expected_outputs=output_paths,
                    old_yaml_map={},
                    new_binary_dir=str(new_binary_dir),
                    platform="windows",
                    image_base=0x180000000,
                    func_names=func_names,
                    func_xrefs=[
                        {
                            "func_name": second_func_name,
                            "xref_strings": ["dummy-string"],
                            "xref_gvs": [],
                            "xref_signatures": [],
                            "xref_funcs": [first_func_name],
                            "exclude_funcs": [],
                            "exclude_strings": [],
                            "exclude_gvs": [],
                            "exclude_signatures": [],
                        },
                    ],
                    generate_yaml_desired_fields=[
                        (first_func_name, ["func_name", "func_va"]),
                        (second_func_name, ["func_name", "func_va"]),
                    ],
                    llm_decompile_specs=[
                        (
                            first_func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                        (
                            second_func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_call_llm_decompile.assert_awaited_once()
        self.assertEqual(
            [first_func_name],
            mock_call_llm_decompile.call_args.kwargs["symbol_name_list"],
        )
        self.assertEqual(2, mock_write_func_yaml.call_count)

    async def test_preprocess_common_skill_llm_batch_issues_second_request_for_symbol_not_covered_in_first_batch(
        self,
    ) -> None:
        first_func_name = "CNetworkMessages_FindNetworkGroup"
        second_func_name = "CNetworkMessages_FindMessage"
        func_names = [first_func_name, second_func_name]
        target_detail_payload = {
            "func_name": "CNetworkGameClient_RecordEntityBandwidth",
            "func_va": "0x180555500",
            "disasm_code": "call    sub_180222200",
            "procedure": "return CNetworkMessages::FindNetworkGroup(this, group);",
        }
        first_llm_payload = {
            "found_vcall": [],
            "found_call": [
                {
                    "insn_va": "0x180777700",
                    "insn_disasm": "call    sub_180222200",
                    "func_name": first_func_name,
                }
            ],
            "found_gv": [],
            "found_struct_offset": [],
        }
        second_llm_payload = {
            "found_vcall": [],
            "found_call": [
                {
                    "insn_va": "0x180777710",
                    "insn_disasm": "call    sub_180222210",
                    "func_name": second_func_name,
                }
            ],
            "found_gv": [],
            "found_struct_offset": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            new_binary_dir = Path(temp_dir) / "current"
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            first_output = new_binary_dir / f"{first_func_name}.windows.yaml"
            second_output = new_binary_dir / f"{second_func_name}.windows.yaml"
            output_paths = [str(first_output), str(second_output)]
            dependent_yaml_path = new_binary_dir / f"{first_func_name}.windows.yaml"

            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )

            async def _fake_preprocess_func_xrefs_via_mcp(*, func_name, **_kwargs):
                if func_name != second_func_name:
                    return None
                if dependent_yaml_path.is_file():
                    return None
                return None

            async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
                return {
                    "func_name": kwargs["func_name"],
                    "func_va": str(kwargs["direct_func_va"]).strip().lower(),
                }

            def _fake_write_func_yaml(path, data):
                output_path = Path(path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(
                    yaml.safe_dump(data, sort_keys=False),
                    encoding="utf-8",
                )

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
                "preprocess_func_xrefs_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_func_xrefs_via_mcp),
            ), patch.object(
                ida_analyze_util,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(side_effect=["0x180123450", "0x180223450"]),
            ), patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
            ), patch.object(
                ida_analyze_util,
                "call_llm_decompile",
                create=True,
                new_callable=AsyncMock,
                side_effect=[first_llm_payload, second_llm_payload],
            ) as mock_call_llm_decompile, patch.object(
                ida_analyze_util,
                "write_func_yaml",
                side_effect=_fake_write_func_yaml,
            ) as mock_write_func_yaml, patch.object(
                ida_analyze_util,
                "_rename_func_in_ida",
                AsyncMock(return_value=None),
            ):
                result = await ida_analyze_util.preprocess_common_skill(
                    session="session",
                    expected_outputs=output_paths,
                    old_yaml_map={},
                    new_binary_dir=str(new_binary_dir),
                    platform="windows",
                    image_base=0x180000000,
                    func_names=func_names,
                    func_xrefs=[
                        {
                            "func_name": second_func_name,
                            "xref_strings": ["dummy-string"],
                            "xref_gvs": [],
                            "xref_signatures": [],
                            "xref_funcs": [first_func_name],
                            "exclude_funcs": [],
                            "exclude_strings": [],
                            "exclude_gvs": [],
                            "exclude_signatures": [],
                        },
                    ],
                    generate_yaml_desired_fields=[
                        (first_func_name, ["func_name", "func_va"]),
                        (second_func_name, ["func_name", "func_va"]),
                    ],
                    llm_decompile_specs=[
                        (
                            first_func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                        (
                            second_func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        self.assertEqual(2, mock_call_llm_decompile.await_count)
        self.assertEqual(
            [first_func_name],
            mock_call_llm_decompile.await_args_list[0].kwargs["symbol_name_list"],
        )
        self.assertEqual(
            [second_func_name],
            mock_call_llm_decompile.await_args_list[1].kwargs["symbol_name_list"],
        )
        self.assertEqual(2, mock_write_func_yaml.call_count)

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

    async def test_preprocess_common_skill_uses_mainloop_target_when_deactivateloop_target_missing(
        self,
    ) -> None:
        func_name = "ILoopMode_OnLoopActivate"
        output_path = f"/tmp/{func_name}.windows.yaml"
        target_detail_payload = {
            "func_name": "CEngineServiceMgr__MainLoop",
            "func_va": "0x180555500",
            "disasm_code": "call    sub_180222200",
            "procedure": "return CEngineServiceMgr__MainLoop(this);",
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

        async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
            return {
                "func_name": kwargs["func_name"],
                "func_va": str(kwargs["direct_func_va"]).strip().lower(),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "references").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{reference_blocks}\n---\n{target_blocks}\n---\n{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "deactivate.yaml",
                {
                    "func_name": "CEngineServiceMgr_DeactivateLoop",
                    "disasm_code": "call    sub_180111100",
                    "procedure": "return CEngineServiceMgr_DeactivateLoop(this);",
                },
            )
            _write_yaml(
                preprocessor_dir / "references" / "mainloop.yaml",
                {
                    "func_name": "CEngineServiceMgr__MainLoop",
                    "disasm_code": "call    sub_180222200",
                    "procedure": "return CEngineServiceMgr__MainLoop(this);",
                },
            )

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
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
                create=True,
            ) as mock_load_target_details, patch.object(
                ida_analyze_util,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(return_value="0x180123450"),
            ), patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
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
                    session="session",
                    expected_outputs=[output_path],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    generate_yaml_desired_fields=[
                        (func_name, ["func_name", "func_va"]),
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/deactivate.yaml",
                        ),
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/mainloop.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_load_target_details.assert_awaited_once_with(
            "session",
            [
                "CEngineServiceMgr_DeactivateLoop",
                "CEngineServiceMgr__MainLoop",
            ],
            new_binary_dir="/tmp",
            platform="windows",
            debug=True,
        )
        mock_call_llm_decompile.assert_awaited_once()
        self.assertIn(
            "Reference Function: CEngineServiceMgr_DeactivateLoop",
            mock_call_llm_decompile.call_args.kwargs["reference_blocks"],
        )
        self.assertIn(
            "Reference Function: CEngineServiceMgr__MainLoop",
            mock_call_llm_decompile.call_args.kwargs["reference_blocks"],
        )
        self.assertIn(
            "Target Function: CEngineServiceMgr__MainLoop",
            mock_call_llm_decompile.call_args.kwargs["target_blocks"],
        )
        self.assertNotIn(
            "Target Function: CEngineServiceMgr_DeactivateLoop",
            mock_call_llm_decompile.call_args.kwargs["target_blocks"],
        )
        mock_write_func_yaml.assert_called_once()

    async def test_preprocess_common_skill_fails_when_all_llm_targets_are_missing(
        self,
    ) -> None:
        func_name = "ILoopMode_OnLoopActivate"
        output_path = f"/tmp/{func_name}.windows.yaml"

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "references").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{reference_blocks}\n---\n{target_blocks}\n---\n{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "deactivate.yaml",
                {
                    "func_name": "CEngineServiceMgr_DeactivateLoop",
                    "disasm_code": "call    sub_180111100",
                    "procedure": "return CEngineServiceMgr_DeactivateLoop(this);",
                },
            )
            _write_yaml(
                preprocessor_dir / "references" / "mainloop.yaml",
                {
                    "func_name": "CEngineServiceMgr__MainLoop",
                    "disasm_code": "call    sub_180222200",
                    "procedure": "return CEngineServiceMgr__MainLoop(this);",
                },
            )

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
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[]),
                create=True,
            ) as mock_load_target_details, patch.object(
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
                    generate_yaml_desired_fields=[
                        (func_name, ["func_name", "func_va"]),
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/deactivate.yaml",
                        ),
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/mainloop.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertFalse(result)
        mock_load_target_details.assert_awaited_once()
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
            expected_detail_export_code = _function_detail_export_py_eval(
                target_detail_payload["func_va"]
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
                if code == expected_detail_export_code:
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

    async def test_preprocess_common_skill_uses_found_funcptr_to_generate_func_yaml(
        self,
    ) -> None:
        func_name = "CLoopModeGame_OnClientPollNetworking"
        output_paths = [f"/tmp/{func_name}.windows.yaml"]
        target_detail_payload = {
            "func_name": "CLoopModeGame_RegisterEventMapInternal",
            "func_va": "0x180555500",
            "disasm_code": "lea     rdx, sub_15BC910",
            "procedure": "v40 = sub_15BC910;",
        }
        normalized_payload = {
            "found_vcall": [],
            "found_call": [],
            "found_funcptr": [
                {
                    "insn_va": "0x180666600",
                    "insn_disasm": "lea     rdx, sub_15BC910",
                    "funcptr_name": func_name,
                }
            ],
            "found_gv": [],
            "found_struct_offset": [],
        }

        async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
            return {
                "func_name": kwargs["func_name"],
                "func_va": str(kwargs["direct_func_va"]).strip().lower(),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )

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
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_funcptr_target_via_mcp",
                AsyncMock(return_value="0x180123450"),
                create=True,
            ) as mock_resolve_direct_funcptr_target, patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
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
                    session="session",
                    expected_outputs=output_paths,
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    generate_yaml_desired_fields=[
                        (func_name, ["func_name", "func_va"]),
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_resolve_direct_funcptr_target.assert_awaited_once_with(
            "session",
            "0x180666600",
            debug=True,
        )
        self.assertEqual("0x180123450", mock_write_func_yaml.call_args.args[1]["func_va"])

    async def test_preprocess_common_skill_prefers_found_call_over_found_funcptr(
        self,
    ) -> None:
        func_name = "CLoopModeGame_OnClientPollNetworking"
        output_path = f"/tmp/{func_name}.windows.yaml"
        target_detail_payload = {
            "func_name": "CLoopModeGame_RegisterEventMapInternal",
            "func_va": "0x180555500",
            "disasm_code": "call    sub_180111111\nlea     rdx, sub_15BC910",
            "procedure": "sub_180111111(); v40 = sub_15BC910;",
        }
        normalized_payload = {
            "found_vcall": [],
            "found_call": [
                {
                    "insn_va": "0x180777700",
                    "insn_disasm": "call    sub_180111111",
                    "func_name": func_name,
                }
            ],
            "found_funcptr": [
                {
                    "insn_va": "0x180666600",
                    "insn_disasm": "lea     rdx, sub_15BC910",
                    "funcptr_name": func_name,
                }
            ],
            "found_gv": [],
            "found_struct_offset": [],
        }

        async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
            return {
                "func_name": kwargs["func_name"],
                "func_va": str(kwargs["direct_func_va"]).strip().lower(),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )

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
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(return_value="0x180111111"),
                create=True,
            ) as mock_resolve_direct_call_target, patch.object(
                ida_analyze_util,
                "_resolve_direct_funcptr_target_via_mcp",
                AsyncMock(return_value="0x180222222"),
                create=True,
            ) as mock_resolve_direct_funcptr_target, patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
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
                    session="session",
                    expected_outputs=[output_path],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    generate_yaml_desired_fields=[
                        (func_name, ["func_name", "func_va"]),
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_resolve_direct_call_target.assert_awaited_once_with(
            "session",
            "0x180777700",
            debug=True,
        )
        mock_resolve_direct_funcptr_target.assert_not_awaited()
        mock_write_func_yaml.assert_called_once()
        self.assertEqual("0x180111111", mock_write_func_yaml.call_args.args[1]["func_va"])

    async def test_preprocess_common_skill_skips_found_funcptr_when_resolver_is_non_unique(
        self,
    ) -> None:
        func_name = "CLoopModeGame_OnClientPollNetworking"
        output_path = f"/tmp/{func_name}.windows.yaml"
        target_detail_payload = {
            "func_name": "CLoopModeGame_RegisterEventMapInternal",
            "func_va": "0x180555500",
            "disasm_code": "lea     rdx, sub_15BC910",
            "procedure": "v40 = sub_15BC910;",
        }
        normalized_payload = {
            "found_vcall": [],
            "found_call": [],
            "found_funcptr": [
                {
                    "insn_va": "0x180666600",
                    "insn_disasm": "lea     rdx, sub_15BC910",
                    "funcptr_name": func_name,
                }
            ],
            "found_gv": [],
            "found_struct_offset": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )

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
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_funcptr_target_via_mcp",
                AsyncMock(return_value=None),
                create=True,
            ) as mock_resolve_direct_funcptr_target, patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(),
            ) as mock_preprocess_direct_func_sig_via_mcp, patch.object(
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
                    session="session",
                    expected_outputs=[output_path],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    generate_yaml_desired_fields=[
                        (func_name, ["func_name", "func_va"]),
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertFalse(result)
        mock_resolve_direct_funcptr_target.assert_awaited_once_with(
            "session",
            "0x180666600",
            debug=True,
        )
        mock_preprocess_direct_func_sig_via_mcp.assert_not_awaited()
        mock_write_func_yaml.assert_not_called()

    async def test_preprocess_common_skill_skips_found_funcptr_when_vfunc_sig_required(
        self,
    ) -> None:
        func_name = "CBaseEntity_GetHammerUniqueId"
        output_path = f"/tmp/{func_name}.windows.yaml"
        target_detail_payload = {
            "func_name": "CBaseEntity_Spawn",
            "func_va": "0x180555500",
            "disasm_code": "lea     rdx, sub_15BC910\ncall    qword ptr [rax+370h]",
            "procedure": "v40 = sub_15BC910; return this->vfptr[110](this);",
        }
        normalized_payload = {
            "found_vcall": [
                {
                    "insn_va": "0x18016742cf",
                    "insn_disasm": "call    qword ptr [rax+370h]",
                    "vfunc_offset": "0x370",
                    "func_name": func_name,
                }
            ],
            "found_call": [],
            "found_funcptr": [
                {
                    "insn_va": "0x180666600",
                    "insn_disasm": "lea     rdx, sub_15BC910",
                    "funcptr_name": func_name,
                }
            ],
            "found_gv": [],
            "found_struct_offset": [],
        }

        async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
            if kwargs.get("direct_vcall_inst_va"):
                return {
                    "func_name": kwargs["func_name"],
                    "func_va": "0x1809b8db0",
                    "vfunc_sig": "FF 90 70 03 00 00",
                    "vfunc_sig_max_match": 10,
                    "vfunc_offset": "0x370",
                    "vfunc_index": 110,
                }
            if kwargs.get("direct_func_va"):
                return {
                    "func_name": kwargs["func_name"],
                    "func_va": str(kwargs["direct_func_va"]).strip().lower(),
                }
            return None

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )

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
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_funcptr_target_via_mcp",
                AsyncMock(return_value="0x180123450"),
                create=True,
            ) as mock_resolve_direct_funcptr_target, patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
            ) as mock_preprocess_direct_func_sig_via_mcp, patch.object(
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
                    session="session",
                    expected_outputs=[output_path],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    func_vtable_relations=[(func_name, "CBaseEntity")],
                    generate_yaml_desired_fields=[
                        (
                            func_name,
                            [
                                "func_name",
                                "func_va",
                                "vfunc_sig",
                                "vfunc_sig_max_match:10",
                                "vtable_name",
                                "vfunc_offset",
                                "vfunc_index",
                            ],
                        )
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_resolve_direct_funcptr_target.assert_not_awaited()
        mock_preprocess_direct_func_sig_via_mcp.assert_awaited_once()
        preprocess_kwargs = mock_preprocess_direct_func_sig_via_mcp.await_args.kwargs
        self.assertEqual("0x18016742cf", preprocess_kwargs["direct_vcall_inst_va"])
        self.assertEqual("0x370", preprocess_kwargs["direct_vfunc_offset"])
        self.assertNotIn("direct_func_va", preprocess_kwargs)
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(func_name, written_payload["func_name"])
        self.assertEqual("FF 90 70 03 00 00", written_payload["vfunc_sig"])
        self.assertEqual(10, written_payload["vfunc_sig_max_match"])
        self.assertEqual("CBaseEntity", written_payload["vtable_name"])

    async def test_preprocess_common_skill_skips_found_call_when_vfunc_sig_required(
        self,
    ) -> None:
        func_name = "CBaseEntity_GetHammerUniqueId"
        output_path = f"/tmp/{func_name}.windows.yaml"
        target_detail_payload = {
            "func_name": "CBaseEntity_Spawn",
            "func_va": "0x180555500",
            "disasm_code": "call    sub_180111111\ncall    qword ptr [rax+370h]",
            "procedure": "sub_180111111(); return this->vfptr[110](this);",
        }
        normalized_payload = {
            "found_vcall": [
                {
                    "insn_va": "0x18016742cf",
                    "insn_disasm": "call    qword ptr [rax+370h]",
                    "vfunc_offset": "0x370",
                    "func_name": func_name,
                }
            ],
            "found_call": [
                {
                    "insn_va": "0x180777700",
                    "insn_disasm": "call    sub_180111111",
                    "func_name": func_name,
                }
            ],
            "found_funcptr": [],
            "found_gv": [],
            "found_struct_offset": [],
        }

        async def _fake_preprocess_direct_func_sig_via_mcp(**kwargs):
            if kwargs.get("direct_vcall_inst_va"):
                return {
                    "func_name": kwargs["func_name"],
                    "func_va": "0x1809b8db0",
                    "vfunc_sig": "FF 90 70 03 00 00",
                    "vfunc_sig_max_match": 10,
                    "vfunc_offset": "0x370",
                    "vfunc_index": 110,
                }
            if kwargs.get("direct_func_va"):
                return {
                    "func_name": kwargs["func_name"],
                    "func_va": str(kwargs["direct_func_va"]).strip().lower(),
                }
            return None

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )

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
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(return_value="0x180111111"),
                create=True,
            ) as mock_resolve_direct_call_target, patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(side_effect=_fake_preprocess_direct_func_sig_via_mcp),
            ) as mock_preprocess_direct_func_sig_via_mcp, patch.object(
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
                    session="session",
                    expected_outputs=[output_path],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    func_vtable_relations=[(func_name, "CBaseEntity")],
                    generate_yaml_desired_fields=[
                        (
                            func_name,
                            [
                                "func_name",
                                "func_va",
                                "vfunc_sig",
                                "vfunc_sig_max_match:10",
                                "vtable_name",
                                "vfunc_offset",
                                "vfunc_index",
                            ],
                        )
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        ),
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_resolve_direct_call_target.assert_not_awaited()
        mock_preprocess_direct_func_sig_via_mcp.assert_awaited_once()
        preprocess_kwargs = mock_preprocess_direct_func_sig_via_mcp.await_args.kwargs
        self.assertEqual("0x18016742cf", preprocess_kwargs["direct_vcall_inst_va"])
        self.assertEqual("0x370", preprocess_kwargs["direct_vfunc_offset"])
        self.assertNotIn("direct_func_va", preprocess_kwargs)
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(func_name, written_payload["func_name"])
        self.assertEqual("FF 90 70 03 00 00", written_payload["vfunc_sig"])
        self.assertEqual(10, written_payload["vfunc_sig_max_match"])
        self.assertEqual("CBaseEntity", written_payload["vtable_name"])

    async def test_preprocess_common_skill_generates_vfunc_sig_from_vcall_even_when_vtable_available(
        self,
    ) -> None:
        func_name = "CBaseEntity_GetHammerUniqueId"
        output_path = f"/tmp/{func_name}.windows.yaml"
        target_detail_payload = {
            "func_name": "CBaseEntity_Spawn",
            "func_va": "0x180555500",
            "disasm_code": "call    qword ptr [rax+370h]",
            "procedure": "return this->vfptr[110](this);",
        }
        normalized_payload = {
            "found_vcall": [
                {
                    "insn_va": "0x18016742cf",
                    "insn_disasm": "call    qword ptr [rax+370h]",
                    "vfunc_offset": "0x370",
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
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )

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
                AsyncMock(
                    return_value={
                        "vtable_class": "CBaseEntity",
                        "vtable_symbol": "_ZTV11CBaseEntity + 0x10",
                        "vtable_va": "0x18021862e0",
                        "vtable_rva": "0x21862e0",
                        "vtable_size": "0x778",
                        "vtable_numvfunc": 239,
                        "vtable_entries": {110: "0x1809b8db0"},
                    }
                ),
            ), patch.object(
                ida_analyze_util,
                "_get_func_basic_info_via_mcp",
                AsyncMock(
                    return_value={
                        "func_va": "0x1809b8db0",
                        "func_rva": "0x9b8db0",
                        "func_size": "0x3",
                    }
                ),
            ), patch.object(
                ida_analyze_util,
                "preprocess_gen_vfunc_sig_via_mcp",
                AsyncMock(
                    return_value={
                        "vfunc_sig": "FF 90 70 03 00 00",
                        "vfunc_sig_max_match": 10,
                    }
                ),
            ) as mock_preprocess_gen_vfunc_sig, patch.object(
                ida_analyze_util,
                "preprocess_gen_func_sig_via_mcp",
                AsyncMock(return_value=None),
            ) as mock_preprocess_gen_func_sig, patch.object(
                ida_analyze_util,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
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
                    func_vtable_relations=[(func_name, "CBaseEntity")],
                    generate_yaml_desired_fields=[
                        (
                            func_name,
                            [
                                "func_name",
                                "vfunc_sig",
                                "vfunc_sig_max_match:10",
                                "vtable_name",
                                "vfunc_offset",
                                "vfunc_index",
                            ],
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
        mock_preprocess_gen_vfunc_sig.assert_awaited_once_with(
            session=session,
            inst_va="0x18016742cf",
            vfunc_offset="0x370",
            max_match_count=10,
            debug=True,
        )
        mock_preprocess_gen_func_sig.assert_not_awaited()
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(func_name, written_payload["func_name"])
        self.assertEqual("FF 90 70 03 00 00", written_payload["vfunc_sig"])
        self.assertEqual(10, written_payload["vfunc_sig_max_match"])
        self.assertEqual("CBaseEntity", written_payload["vtable_name"])
        self.assertEqual("0x370", written_payload["vfunc_offset"])
        self.assertEqual(110, written_payload["vfunc_index"])
        self.assertNotIn("func_sig", written_payload)

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
            expected_detail_export_code = _function_detail_export_py_eval(
                target_detail_payload["func_va"]
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
                if code == expected_detail_export_code:
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
                "preprocess_gen_vfunc_sig_via_mcp",
                create=True,
                new_callable=AsyncMock,
                return_value={"vfunc_sig": "FF 90 78 00 00 00 48 8B C8"},
            ) as mock_preprocess_gen_vfunc_sig, patch.object(
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
                            [
                                "func_name",
                                "vfunc_sig",
                                "vfunc_sig_max_match:10",
                                "vtable_name",
                                "vfunc_offset",
                                "vfunc_index",
                            ],
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
        mock_preprocess_gen_vfunc_sig.assert_awaited_once_with(
            session=session,
            inst_va="0x18004abc3",
            vfunc_offset="0x78",
            max_match_count=10,
            debug=True,
        )
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(func_name, written_payload["func_name"])
        self.assertEqual("FF 90 78 00 00 00 48 8B C8", written_payload["vfunc_sig"])
        self.assertEqual(10, written_payload["vfunc_sig_max_match"])
        self.assertEqual("CNetworkMessages", written_payload["vtable_name"])
        self.assertEqual("0x78", written_payload["vfunc_offset"])
        self.assertEqual(15, written_payload["vfunc_index"])
        self.assertNotIn("func_va", written_payload)

    async def test_preprocess_common_skill_fails_when_slot_only_vfunc_sig_generation_fails(
        self,
    ) -> None:
        func_name = "INetworkMessages_SetNetworkSerializationContextData"
        output_path = f"/tmp/{func_name}.linux.yaml"
        target_detail_payload = {
            "func_name": "CEntitySystem_Init",
            "func_va": "0x1D85700",
            "disasm_code": "call    qword ptr [rax+0A8h]",
            "procedure": "return this->vfptr[21](this, ctx);",
        }
        normalized_payload = {
            "found_vcall": [
                {
                    "insn_va": "0x1D859BF",
                    "insn_disasm": "call    qword ptr [rax+0A8h]",
                    "vfunc_offset": "0xA8",
                    "func_name": func_name,
                },
                {
                    "insn_va": "0x1D85A10",
                    "insn_disasm": "call    qword ptr [rax+0A8h]",
                    "vfunc_offset": "0xA8",
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
                    "disasm_code": "call    qword ptr [rax+0A8h]",
                    "procedure": target_detail_payload["procedure"],
                },
            )
            expected_detail_export_code = _function_detail_export_py_eval(
                target_detail_payload["func_va"]
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
                if code == expected_detail_export_code:
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
                "preprocess_gen_vfunc_sig_via_mcp",
                create=True,
                new_callable=AsyncMock,
                return_value=None,
            ) as mock_preprocess_gen_vfunc_sig, patch.object(
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
                    platform="linux",
                    image_base=0,
                    func_names=[func_name],
                    func_vtable_relations=[(func_name, "INetworkMessages")],
                    generate_yaml_desired_fields=[
                        (
                            func_name,
                            [
                                "func_name",
                                "vfunc_sig",
                                "vtable_name",
                                "vfunc_offset",
                                "vfunc_index",
                            ],
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

        self.assertFalse(result)
        self.assertEqual(2, mock_preprocess_gen_vfunc_sig.await_count)
        mock_preprocess_gen_vfunc_sig.assert_has_awaits(
            [
                call(
                    session=session,
                    inst_va="0x1d859bf",
                    vfunc_offset="0xa8",
                    max_match_count=1,
                    debug=True,
                ),
                call(
                    session=session,
                    inst_va="0x1d85a10",
                    vfunc_offset="0xa8",
                    max_match_count=1,
                    debug=True,
                ),
            ]
        )
        mock_write_func_yaml.assert_not_called()

    async def test_preprocess_direct_func_sig_via_mcp_forwards_boundary_flag_to_generator(
        self,
    ) -> None:
        session = AsyncMock()

        with patch.object(
            ida_analyze_util,
            "_get_func_basic_info_via_mcp",
            AsyncMock(return_value={"func_size": "0x40"}),
        ), patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(return_value={"func_sig": "AA BB"}),
        ) as mock_gen_sig:
            result = await ida_analyze_util._preprocess_direct_func_sig_via_mcp(
                session=session,
                new_path="/tmp/Foo.windows.yaml",
                image_base=0x180000000,
                platform="windows",
                func_name="Foo",
                direct_func_va="0x180123450",
                require_func_sig=True,
                allow_func_sig_across_function_boundary=True,
                debug=False,
            )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("AA BB", result["func_sig"])
        mock_gen_sig.assert_awaited_once()
        self.assertTrue(
            mock_gen_sig.await_args.kwargs["allow_across_function_boundary"]
        )

    async def test_preprocess_direct_func_sig_forwards_vfunc_boundary_flag(
        self,
    ) -> None:
        session = AsyncMock()

        with patch.object(
            ida_analyze_util,
            "_get_func_basic_info_via_mcp",
            AsyncMock(return_value={"func_size": "0x40"}),
        ), patch.object(
            ida_analyze_util,
            "preprocess_gen_vfunc_sig_via_mcp",
            AsyncMock(
                return_value={
                    "vfunc_sig": "FF 90 78 00 00 00",
                    "vfunc_sig_max_match": 10,
                }
            ),
        ) as mock_gen_vfunc_sig:
            result = await ida_analyze_util._preprocess_direct_func_sig_via_mcp(
                session=session,
                new_path="/tmp/Foo.windows.yaml",
                image_base=0x180000000,
                platform="windows",
                func_name="Foo",
                direct_func_va="0x180123450",
                direct_vcall_inst_va="0x18016742cf",
                direct_vfunc_offset="0x78",
                require_vfunc_sig=True,
                allow_vfunc_sig_across_function_boundary=True,
                vfunc_sig_max_match=10,
                debug=False,
            )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("FF 90 78 00 00 00", result["vfunc_sig"])
        mock_gen_vfunc_sig.assert_awaited_once()
        self.assertTrue(
            mock_gen_vfunc_sig.await_args.kwargs["allow_across_function_boundary"]
        )

    async def test_preprocess_direct_struct_offset_forwards_boundary_flag(
        self,
    ) -> None:
        session = AsyncMock()

        with patch.object(
            ida_analyze_util,
            "preprocess_gen_struct_offset_sig_via_mcp",
            AsyncMock(
                return_value={
                    "struct_name": "CGameResourceService",
                    "member_name": "m_pEntitySystem",
                    "offset": "0x58",
                    "size": 8,
                    "offset_sig": "49 8B 4E ??",
                    "offset_sig_disp": 0,
                }
            ),
        ) as mock_gen_sig:
            result = await ida_analyze_util._preprocess_direct_struct_offset_sig_via_mcp(
                session=session,
                new_path="/tmp/CGameResourceService_m_pEntitySystem.windows.yaml",
                image_base=0x180000000,
                struct_member_name="CGameResourceService_m_pEntitySystem",
                struct_name="CGameResourceService",
                member_name="m_pEntitySystem",
                offset="0x58",
                offset_inst_va="0x180123450",
                size=8,
                allow_across_function_boundary=True,
                debug=False,
            )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("49 8B 4E ??", result["offset_sig"])
        mock_gen_sig.assert_awaited_once()
        self.assertTrue(
            mock_gen_sig.await_args.kwargs["allow_across_function_boundary"]
        )

    async def test_slot_only_vfunc_payload_forwards_boundary_flag(
        self,
    ) -> None:
        session = AsyncMock()
        llm_result = {
            "found_vcall": [
                {
                    "insn_va": "0x18004ABC3",
                    "insn_disasm": "call    qword ptr [rax+78h]",
                    "vfunc_offset": "0x78",
                    "func_name": "Foo",
                },
                {
                    "insn_va": "0x18004AC0A",
                    "insn_disasm": "call    qword ptr [rax+78h]",
                    "vfunc_offset": "0x78",
                    "func_name": "Foo",
                },
            ],
            "found_call": [],
            "found_gv": [],
            "found_struct_offset": [],
        }

        with patch.object(
            ida_analyze_util,
            "preprocess_gen_vfunc_sig_via_mcp",
            AsyncMock(
                return_value={
                    "vfunc_sig": "FF 90 78 00 00 00 48 8B C8",
                    "vfunc_sig_max_match": 10,
                }
            ),
        ) as mock_gen_vfunc_sig:
            result = await ida_analyze_util._build_enriched_slot_only_vfunc_payload_via_mcp(
                session=session,
                func_name="Foo",
                llm_result=llm_result,
                vtable_name="CNetworkMessages",
                vfunc_sig_max_match=10,
                require_vfunc_sig=True,
                allow_vfunc_sig_across_function_boundary=True,
                debug=False,
            )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("FF 90 78 00 00 00 48 8B C8", result["vfunc_sig"])
        mock_gen_vfunc_sig.assert_awaited_once()
        self.assertTrue(
            mock_gen_vfunc_sig.await_args.kwargs["allow_across_function_boundary"]
        )

    async def test_preprocess_common_skill_forwards_func_sig_boundary_flag_to_direct_helper(
        self,
    ) -> None:
        func_name = "Foo"
        output_path = f"/tmp/{func_name}.windows.yaml"
        target_detail_payload = {
            "func_name": "Bar",
            "func_va": "0x180555500",
            "disasm_code": "call    sub_180123450",
            "procedure": "return sub_180123450();",
        }
        normalized_payload = {
            "found_call": [
                {
                    "insn_va": "0x18016742cf",
                    "insn_disasm": "call    sub_180123450",
                    "func_name": func_name,
                }
            ],
            "found_vcall": [],
            "found_funcptr": [],
            "found_gv": [],
            "found_struct_offset": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {
                    "func_name": target_detail_payload["func_name"],
                    "disasm_code": target_detail_payload["disasm_code"],
                    "procedure": target_detail_payload["procedure"],
                },
            )

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
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[target_detail_payload]),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(return_value="0x180123450"),
                create=True,
            ), patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(
                    return_value={
                        "func_name": func_name,
                        "func_va": "0x180123450",
                        "func_sig": "AA BB",
                    }
                ),
            ) as mock_preprocess_direct_func_sig, patch.object(
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
                    session="session",
                    expected_outputs=[output_path],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    generate_yaml_desired_fields=[
                        (
                            func_name,
                            [
                                "func_name",
                                "func_sig",
                                "func_sig_allow_across_function_boundary: true",
                            ],
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
        mock_preprocess_direct_func_sig.assert_awaited_once()
        self.assertTrue(
            mock_preprocess_direct_func_sig.await_args.kwargs[
                "allow_func_sig_across_function_boundary"
            ]
        )
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(
            {
                "func_name": "Foo",
                "func_sig": "AA BB",
                "func_sig_allow_across_function_boundary": True,
            },
            written_payload,
        )

    async def test_preprocess_common_skill_forwards_vfunc_boundary_flag_and_writes_it(
        self,
    ) -> None:
        func_name = "Foo"
        output_path = f"/tmp/{func_name}.windows.yaml"
        target_detail_payload = {
            "func_name": "Bar",
            "func_va": "0x180555500",
            "disasm_code": "call    qword ptr [rax+78h]",
            "procedure": "return this->vfptr[15](this);",
        }
        normalized_payload = {
            "found_vcall": [
                {
                    "insn_va": "0x18004ABC3",
                    "insn_disasm": "call    qword ptr [rax+78h]",
                    "vfunc_offset": "0x78",
                    "func_name": func_name,
                }
            ],
            "found_call": [],
            "found_funcptr": [],
            "found_gv": [],
            "found_struct_offset": [],
        }

        helper_cases = (
            (
                "direct_vcall",
                "_preprocess_direct_func_sig_via_mcp",
                {
                    "func_name": func_name,
                    "vfunc_sig": "FF 90 78 00 00 00",
                    "vfunc_sig_max_match": 10,
                    "vtable_name": "CNetworkMessages",
                    "vfunc_offset": "0x78",
                    "vfunc_index": 15,
                },
            ),
            (
                "slot_only",
                "_build_enriched_slot_only_vfunc_payload_via_mcp",
                {
                    "func_name": func_name,
                    "vfunc_sig": "FF 90 78 00 00 00",
                    "vfunc_sig_max_match": 10,
                    "vtable_name": "CNetworkMessages",
                    "vfunc_offset": "0x78",
                    "vfunc_index": 15,
                },
            ),
        )

        for case_name, expected_helper_name, helper_payload in helper_cases:
            with self.subTest(case=case_name):
                with tempfile.TemporaryDirectory() as temp_dir:
                    preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
                    (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
                    (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                        "{symbol_name_list}",
                        encoding="utf-8",
                    )
                    _write_yaml(
                        preprocessor_dir / "references" / "reference.yaml",
                        {
                            "func_name": target_detail_payload["func_name"],
                            "disasm_code": target_detail_payload["disasm_code"],
                            "procedure": target_detail_payload["procedure"],
                        },
                    )

                    direct_helper_return = (
                        helper_payload if expected_helper_name == "_preprocess_direct_func_sig_via_mcp" else None
                    )
                    slot_only_return = (
                        helper_payload if expected_helper_name == "_build_enriched_slot_only_vfunc_payload_via_mcp" else None
                    )

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
                        "_load_llm_decompile_target_details_via_mcp",
                        AsyncMock(return_value=[target_detail_payload]),
                    ), patch.object(
                        ida_analyze_util,
                        "_preprocess_direct_func_sig_via_mcp",
                        AsyncMock(return_value=direct_helper_return),
                    ) as mock_preprocess_direct_func_sig, patch.object(
                        ida_analyze_util,
                        "_build_enriched_slot_only_vfunc_payload_via_mcp",
                        AsyncMock(return_value=slot_only_return),
                    ) as mock_slot_only_helper, patch.object(
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
                            session="session",
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
                                    [
                                        "func_name",
                                        "vfunc_sig",
                                        "vfunc_sig_max_match:10",
                                        "vfunc_sig_allow_across_function_boundary: true",
                                        "vtable_name",
                                        "vfunc_offset",
                                        "vfunc_index",
                                    ],
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
                if expected_helper_name == "_preprocess_direct_func_sig_via_mcp":
                    mock_preprocess_direct_func_sig.assert_awaited_once()
                    self.assertTrue(
                        mock_preprocess_direct_func_sig.await_args.kwargs[
                            "allow_vfunc_sig_across_function_boundary"
                        ]
                    )
                    mock_slot_only_helper.assert_not_awaited()
                else:
                    mock_preprocess_direct_func_sig.assert_awaited_once()
                    self.assertTrue(
                        mock_preprocess_direct_func_sig.await_args.kwargs[
                            "allow_vfunc_sig_across_function_boundary"
                        ]
                    )
                    mock_slot_only_helper.assert_awaited_once()
                    self.assertTrue(
                        mock_slot_only_helper.await_args.kwargs[
                            "allow_vfunc_sig_across_function_boundary"
                        ]
                    )
                mock_write_func_yaml.assert_called_once()
                written_payload = mock_write_func_yaml.call_args.args[1]
                self.assertEqual(
                    True,
                    written_payload["vfunc_sig_allow_across_function_boundary"],
                )

    async def test_preprocess_common_skill_forwards_func_sig_boundary_flag_in_inherit_vfuncs(
        self,
    ) -> None:
        func_name = "CDerived_Touch"
        output_path = f"/tmp/{func_name}.windows.yaml"

        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(return_value=None),
        ) as mock_preprocess_func_sig, patch.object(
            ida_analyze_util,
            "preprocess_index_based_vfunc_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": func_name,
                    "func_va": "0x180123450",
                    "func_rva": "0x123450",
                    "func_size": "0x40",
                    "func_sig": "AA BB",
                    "vtable_name": "CDerived",
                    "vfunc_offset": "0x118",
                    "vfunc_index": 35,
                }
            ),
        ) as mock_preprocess_index_vfunc, patch.object(
            ida_analyze_util,
            "write_func_yaml",
        ) as mock_write_func_yaml, patch.object(
            ida_analyze_util,
            "_rename_func_in_ida",
            AsyncMock(return_value=None),
        ):
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=[output_path],
                old_yaml_map={output_path: "/tmp/old.yaml"},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                inherit_vfuncs=[
                    (func_name, "CDerived", "CBaseEntity_Touch", True),
                ],
                generate_yaml_desired_fields=[
                    (
                        func_name,
                        [
                            "func_name",
                            "func_sig",
                            "func_sig_allow_across_function_boundary: true",
                            "vtable_name",
                            "vfunc_offset",
                            "vfunc_index",
                        ],
                    )
                ],
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess_func_sig.assert_awaited_once()
        self.assertTrue(
            mock_preprocess_func_sig.await_args.kwargs[
                "allow_func_sig_across_function_boundary"
            ]
        )
        mock_preprocess_index_vfunc.assert_awaited_once()
        self.assertTrue(
            mock_preprocess_index_vfunc.await_args.kwargs[
                "allow_func_sig_across_function_boundary"
            ]
        )
        mock_write_func_yaml.assert_called_once()
        written_payload = mock_write_func_yaml.call_args.args[1]
        self.assertEqual(True, written_payload["func_sig_allow_across_function_boundary"])


class TestPreprocessFuncSigViaMcpVfuncSigMaxMatch(unittest.IsolatedAsyncioTestCase):
    async def _preprocess_with_vfunc_sig_max_match(self, max_match_count):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "INetworkMessages_GetLoggingChannel.windows.yaml"
            new_path = Path(temp_dir) / "INetworkMessages_GetLoggingChannel.new.windows.yaml"

            _write_yaml(
                old_path,
                {
                    "func_name": "INetworkMessages_GetLoggingChannel",
                    "vfunc_sig": "FF 90 20 01 00 00",
                    "vfunc_sig_max_match": max_match_count,
                    "vtable_name": "INetworkMessages",
                    "vfunc_offset": "0x120",
                    "vfunc_index": 36,
                    "func_va": "0x180111111",
                },
            )
            _write_yaml(
                Path(temp_dir) / "INetworkMessages_vtable.windows.yaml",
                {
                    "vtable_entries": {
                        36: "0x180222222",
                    }
                },
            )

            session = AsyncMock()

            async def _fake_call_tool(*, name: str, arguments: dict[str, object]):
                if name == "find_bytes":
                    return _FakeCallToolResult(
                        [
                            {
                                "matches": ["0x180012340"],
                                "n": 1,
                            }
                        ]
                    )
                if name == "py_eval":
                    return _py_eval_payload(
                        {
                            "func_va": "0x180222222",
                            "func_size": "0x40",
                        }
                    )
                raise AssertionError(f"unexpected MCP tool: {name}")

            session.call_tool.side_effect = _fake_call_tool

            result = await ida_analyze_util.preprocess_func_sig_via_mcp(
                session=session,
                new_path=str(new_path),
                old_path=str(old_path),
                image_base=0x180000000,
                new_binary_dir=temp_dir,
                platform="windows",
                debug=True,
            )

        return result, session

    async def test_preprocess_func_sig_via_mcp_allows_vfunc_sig_match_count_within_limit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "INetworkMessages_GetLoggingChannel.windows.yaml"
            new_path = Path(temp_dir) / "INetworkMessages_GetLoggingChannel.new.windows.yaml"

            _write_yaml(
                old_path,
                {
                    "func_name": "INetworkMessages_GetLoggingChannel",
                    "vfunc_sig": "FF 90 20 01 00 00",
                    "vfunc_sig_max_match": 10,
                    "vtable_name": "INetworkMessages",
                    "vfunc_offset": "0x120",
                    "vfunc_index": 36,
                    "func_va": "0x180111111",
                },
            )
            _write_yaml(
                Path(temp_dir) / "INetworkMessages_vtable.windows.yaml",
                {
                    "vtable_entries": {
                        36: "0x180222222",
                    }
                },
            )

            session = AsyncMock()

            async def _fake_call_tool(*, name: str, arguments: dict[str, object]):
                if name == "find_bytes":
                    self.assertEqual(
                        ["FF 90 20 01 00 00"],
                        arguments["patterns"],
                    )
                    return _FakeCallToolResult(
                        [
                            {
                                "matches": ["0x180012340", "0x180056780"],
                                "n": 2,
                            }
                        ]
                    )
                if name == "py_eval":
                    return _py_eval_payload(
                        {
                            "func_va": "0x180222222",
                            "func_size": "0x40",
                        }
                    )
                raise AssertionError(f"unexpected MCP tool: {name}")

            session.call_tool.side_effect = _fake_call_tool

            result = await ida_analyze_util.preprocess_func_sig_via_mcp(
                session=session,
                new_path=str(new_path),
                old_path=str(old_path),
                image_base=0x180000000,
                new_binary_dir=temp_dir,
                platform="windows",
                debug=True,
            )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(10, result["vfunc_sig_max_match"])
        self.assertEqual("FF 90 20 01 00 00", result["vfunc_sig"])
        self.assertEqual(36, result["vfunc_index"])

    async def test_preprocess_func_sig_via_mcp_rejects_invalid_vfunc_sig_max_match(
        self,
    ) -> None:
        invalid_values = [True, 1.5, 0, "abc"]

        for invalid_value in invalid_values:
            with self.subTest(vfunc_sig_max_match=invalid_value):
                result, session = await self._preprocess_with_vfunc_sig_max_match(
                    invalid_value,
                )

                self.assertIsNone(result)
                session.call_tool.assert_not_awaited()

    async def test_preprocess_func_sig_via_mcp_vfunc_fallback_generates_func_sig_with_boundary_flag(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "INetworkMessages_GetLoggingChannel.windows.yaml"
            new_path = Path(temp_dir) / "INetworkMessages_GetLoggingChannel.new.windows.yaml"

            _write_yaml(
                old_path,
                {
                    "func_name": "INetworkMessages_GetLoggingChannel",
                    "vfunc_sig": "FF 90 20 01 00 00",
                    "vfunc_sig_max_match": 10,
                    "vtable_name": "INetworkMessages",
                    "vfunc_offset": "0x120",
                    "vfunc_index": 36,
                    "func_va": "0x180111111",
                },
            )
            _write_yaml(
                Path(temp_dir) / "INetworkMessages_vtable.windows.yaml",
                {
                    "vtable_entries": {
                        36: "0x180222222",
                    }
                },
            )

            session = AsyncMock()

            async def _fake_call_tool(*, name: str, arguments: dict[str, object]):
                if name == "find_bytes":
                    return _FakeCallToolResult(
                        [
                            {
                                "matches": ["0x180012340", "0x180056780"],
                                "n": 2,
                            }
                        ]
                    )
                if name == "py_eval":
                    return _py_eval_payload(
                        {
                            "func_va": "0x180222222",
                            "func_size": "0x40",
                        }
                    )
                raise AssertionError(f"unexpected MCP tool: {name}")

            session.call_tool.side_effect = _fake_call_tool

            with patch.object(
                ida_analyze_util,
                "preprocess_gen_func_sig_via_mcp",
                AsyncMock(return_value={"func_sig": "40 53"}),
            ) as mock_gen_sig:
                result = await ida_analyze_util.preprocess_func_sig_via_mcp(
                    session=session,
                    new_path=str(new_path),
                    old_path=str(old_path),
                    image_base=0x180000000,
                    new_binary_dir=temp_dir,
                    platform="windows",
                    allow_func_sig_across_function_boundary=True,
                    debug=True,
                )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("40 53", result["func_sig"])
        self.assertEqual("FF 90 20 01 00 00", result["vfunc_sig"])
        mock_gen_sig.assert_awaited_once()
        self.assertTrue(
            mock_gen_sig.await_args.kwargs["allow_across_function_boundary"]
        )


if __name__ == "__main__":
    unittest.main()

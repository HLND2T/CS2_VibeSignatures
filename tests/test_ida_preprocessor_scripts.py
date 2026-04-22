import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import ida_skill_preprocessor


FLATTENED_SERIALIZERS_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CFlattenedSerializers_CreateFieldChangedEventQueue.py"
)
SET_IS_FOR_SERVER_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CNetworkMessages_SetIsForServer.py"
)
I_SET_IS_FOR_SERVER_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-INetworkMessages_SetIsForServer.py"
)
I_GET_LOGGING_CHANNEL_WINDOWS_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-INetworkMessages_GetLoggingChannel-windows.py"
)
I_GET_LOGGING_CHANNEL_LINUX_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-INetworkMessages_GetLoggingChannel-linux.py"
)
NETWORK_GROUP_STATS_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-INetworkMessages_GetNetworkGroupCount-AND-"
    "INetworkMessages_GetNetworkGroupName-AND-"
    "INetworkMessages_GetNetworkGroupColor.py"
)
REALLOCATING_FACTORY_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_vtable.py"
)
REALLOCATING_FACTORY_DEALLOCATE_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Deallocate-impl.py"
)
CSPAWNGROUP_VTABLE2_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CSpawnGroupMgrGameSystem_vtable2.py"
)
CSPAWNGROUP_DOES_REALLOCATE_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py"
)
ORDINAL_VTABLE_COMMON_PATH = Path(
    "ida_preprocessor_scripts/_ordinal_vtable_common.py"
)
FIND_NETWORK_GROUP_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CNetworkMessages_FindNetworkGroup.py"
)
CNETWORK_SERVER_SERVICE_INIT_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CNetworkServerService_Init.py"
)
PROCESS_MOVEMENT_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CCSPlayer_MovementServices_ProcessMovement.py"
)
BOT_ADD_COMMAND_HANDLER_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-BotAdd_CommandHandler.py"
)
SHOW_HUD_HINT_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-ShowHudHint.py"
)
ON_EVENT_MAP_CALLBACKS_CLIENT_SCRIPT_PATH = Path(
    "ida_preprocessor_scripts/"
    "find-CLoopModeGame_OnEventMapCallbacks-client.py"
)

class _FakeStreamableHttpClient:
    async def __aenter__(self):
        return ("read-stream", "write-stream", None)

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeClientSession:
    def __init__(self, read_stream, write_stream):
        self.read_stream = read_stream
        self.write_stream = write_stream

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def initialize(self):
        return None

    async def call_tool(self, name, arguments):
        return {"name": name, "arguments": arguments}


def _load_module(script_path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        script_path,
    )
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


class _FakeSegment:
    def __init__(self, start_ea: int, end_ea: int, perm: int) -> None:
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.perm = perm


def _run_ordinal_vtable_py_eval(
    *,
    class_name: str,
    ordinal: int,
    symbol_aliases=None,
    expected_offset_to_top=None,
    name_to_ea=None,
    name_by_ea=None,
    data_refs=None,
    ptr_values=None,
    func_addrs=None,
    code_addrs=None,
    segments=None,
):
    module = _load_module(
        ORDINAL_VTABLE_COMMON_PATH,
        "ordinal_vtable_common_exec",
    )
    py_code = module._build_ordinal_vtable_py_eval(
        class_name=class_name,
        ordinal=ordinal,
        symbol_aliases=symbol_aliases,
        expected_offset_to_top=expected_offset_to_top,
    )

    name_to_ea = dict(name_to_ea or {})
    name_by_ea = dict(name_by_ea or {})
    data_refs = {
        int(target): list(refs)
        for target, refs in dict(data_refs or {}).items()
    }
    ptr_values = dict(ptr_values or {})
    func_addrs = set(func_addrs or [])
    code_addrs = set(code_addrs or [])
    segments = list(segments or [])

    def _get_seg(ea: int):
        for segment in segments:
            if segment.start_ea <= ea < segment.end_ea:
                return segment
        return None

    idaapi = types.ModuleType("idaapi")
    idaapi.BADADDR = -1
    idaapi.inf_is_64bit = lambda: True
    idaapi.get_func = (
        lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 1)
        if ea in func_addrs else None
    )

    ida_bytes = types.ModuleType("ida_bytes")
    ida_bytes.get_qword = lambda ea: ptr_values.get(ea, 0)
    ida_bytes.get_dword = lambda ea: ptr_values.get(ea, 0) & 0xFFFFFFFF
    ida_bytes.get_full_flags = lambda ea: 1 if ea in code_addrs else 0
    ida_bytes.is_code = lambda flags: bool(flags)

    ida_name = types.ModuleType("ida_name")
    ida_name.get_name_ea = lambda badaddr, name: name_to_ea.get(name, badaddr)
    ida_name.get_name = lambda ea: name_by_ea.get(ea, "")

    idautils = types.ModuleType("idautils")
    idautils.DataRefsTo = lambda ea: list(data_refs.get(ea, []))
    idautils.Names = lambda: [
        (ea, name)
        for name, ea in name_to_ea.items()
    ]

    ida_segment = types.ModuleType("ida_segment")
    ida_segment.SEGPERM_EXEC = 1
    ida_segment.getseg = _get_seg

    fake_modules = {
        "idaapi": idaapi,
        "ida_bytes": ida_bytes,
        "ida_name": ida_name,
        "idautils": idautils,
        "ida_segment": ida_segment,
    }
    globals_dict = {"__builtins__": __builtins__}
    with patch.dict(sys.modules, fake_modules, clear=False):
        exec(py_code, globals_dict)

    return json.loads(globals_dict["result"])


class TestOrdinalVtableCommon(unittest.IsolatedAsyncioTestCase):
    def test_build_ordinal_vtable_py_eval_embeds_constraints(self) -> None:
        module = _load_module(
            ORDINAL_VTABLE_COMMON_PATH,
            "ordinal_vtable_common",
        )

        py_code = module._build_ordinal_vtable_py_eval(
            class_name="CSpawnGroupMgrGameSystem",
            ordinal=2,
            symbol_aliases=["??_7CSpawnGroupMgrGameSystem@@6B@_0"],
            expected_offset_to_top=-8,
        )

        self.assertIn('"CSpawnGroupMgrGameSystem"', py_code)
        self.assertIn("??_7CSpawnGroupMgrGameSystem@@6B@_0", py_code)
        self.assertIn("ordinal = 2", py_code)
        self.assertIn("expected_offset_to_top = -8", py_code)
        self.assertIn("debug_trace_enabled = False", py_code)
        self.assertIn("globals().update(locals())", py_code)
        self.assertIn("addr + (2 * ptr_size)", py_code)
        self.assertIn('symbol_name + " + " + hex(2 * ptr_size)', py_code)
        self.assertIn("if ptr_value == 0:", py_code)
        self.assertIn("if is_linux:", py_code)

    def test_ordinal_py_eval_runs_with_separate_globals_and_locals(self) -> None:
        module = _load_module(
            ORDINAL_VTABLE_COMMON_PATH,
            "ordinal_vtable_common_separate_exec",
        )
        py_code = module._build_ordinal_vtable_py_eval(
            class_name="Foo",
            ordinal=0,
            symbol_aliases=["??_7Foo@@6B@_0"],
            expected_offset_to_top=None,
        )

        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = -1
        idaapi.inf_is_64bit = lambda: True
        idaapi.get_func = (
            lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 1)
            if ea == 0x9000 else None
        )

        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.get_qword = lambda ea: {
            0x2008: 0x9000,
            0x2010: 0,
        }.get(ea, 0)
        ida_bytes.get_dword = lambda ea: 0
        ida_bytes.get_full_flags = lambda ea: 0
        ida_bytes.is_code = lambda flags: False

        ida_name = types.ModuleType("ida_name")
        ida_name.get_name_ea = lambda badaddr, name: badaddr
        ida_name.get_name = lambda ea: {
            0x2008: "??_7Foo@@6B@_0",
        }.get(ea, "")

        idautils = types.ModuleType("idautils")
        idautils.DataRefsTo = lambda ea: [0x2000] if ea == 0x1500 else []
        idautils.Names = lambda: [(0x1500, "??_R4Foo@@6B@_0")]

        ida_segment = types.ModuleType("ida_segment")
        ida_segment.SEGPERM_EXEC = 1
        ida_segment.getseg = lambda ea: (
            _FakeSegment(0x2000, 0x3000, 0)
            if 0x2000 <= ea < 0x3000 else
            _FakeSegment(0x9000, 0xA000, 1)
            if 0x9000 <= ea < 0xA000 else
            None
        )

        fake_modules = {
            "idaapi": idaapi,
            "ida_bytes": ida_bytes,
            "ida_name": ida_name,
            "idautils": idautils,
            "ida_segment": ida_segment,
        }
        exec_globals = {"__builtins__": __builtins__}
        exec_locals = {}
        with patch.dict(sys.modules, fake_modules, clear=False):
            exec(py_code, exec_globals, exec_locals)

        result = json.loads(exec_locals["result"])
        self.assertEqual("??_7Foo@@6B@_0", result["vtable_symbol"])
        self.assertEqual("0x2008", result["vtable_va"])

    async def test_preprocess_ordinal_vtable_normalizes_result(self) -> None:
        module = _load_module(
            ORDINAL_VTABLE_COMMON_PATH,
            "ordinal_vtable_common_preprocess",
        )
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "vtable_class": "CSpawnGroupMgrGameSystem",
                "vtable_symbol": "??_7CSpawnGroupMgrGameSystem@@6B@_0",
                "vtable_va": "0x1819682b0",
                "vtable_size": "0x10",
                "vtable_numvfunc": 2,
                "vtable_entries": {
                    "0": "0x18014c840",
                    "1": "0x18014c850",
                },
                "offset_to_top": -8,
                "source": "linux-typeinfo",
            }
        )

        result = await module.preprocess_ordinal_vtable_via_mcp(
            session=session,
            class_name="CSpawnGroupMgrGameSystem",
            ordinal=0,
            image_base=0x180000000,
            platform="windows",
            debug=True,
            symbol_aliases=["??_7CSpawnGroupMgrGameSystem@@6B@_0"],
            expected_offset_to_top=None,
        )

        self.assertEqual(
            {
                "vtable_class": "CSpawnGroupMgrGameSystem",
                "vtable_symbol": "??_7CSpawnGroupMgrGameSystem@@6B@_0",
                "vtable_va": "0x1819682b0",
                "vtable_rva": "0x19682b0",
                "vtable_size": "0x10",
                "vtable_numvfunc": 2,
                "vtable_entries": {
                    0: "0x18014c840",
                    1: "0x18014c850",
                },
            },
            result,
        )
        self.assertNotIn("offset_to_top", result)
        self.assertNotIn("source", result)
        session.call_tool.assert_awaited_once()

    async def test_preprocess_ordinal_vtable_prints_debug_trace_from_wrapped_payload(self) -> None:
        module = _load_module(
            ORDINAL_VTABLE_COMMON_PATH,
            "ordinal_vtable_common_debug_trace",
        )
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "selected": None,
                "debug_trace": [
                    "[direct-miss] symbol=??_7CSpawnGroupMgrGameSystem@@6B@_0",
                    "[result-none] reason=no_alias_candidate_matched aliases=['??_7CSpawnGroupMgrGameSystem@@6B@_0']",
                ],
            }
        )

        with patch("builtins.print") as mock_print:
            result = await module.preprocess_ordinal_vtable_via_mcp(
                session=session,
                class_name="CSpawnGroupMgrGameSystem",
                ordinal=0,
                image_base=0x180000000,
                platform="windows",
                debug=True,
                symbol_aliases=["??_7CSpawnGroupMgrGameSystem@@6B@_0"],
                expected_offset_to_top=None,
            )

        self.assertIsNone(result)
        mock_print.assert_any_call(
            "    Preprocess ordinal vtable trace: "
            "[direct-miss] symbol=??_7CSpawnGroupMgrGameSystem@@6B@_0"
        )
        mock_print.assert_any_call(
            "    Preprocess ordinal vtable trace: "
            "[result-none] reason=no_alias_candidate_matched "
            "aliases=['??_7CSpawnGroupMgrGameSystem@@6B@_0']"
        )
        mock_print.assert_any_call(
            "    Preprocess ordinal vtable: no result for "
            "CSpawnGroupMgrGameSystem[0]"
        )

    async def test_preprocess_ordinal_vtable_prints_py_eval_stderr_when_result_empty(self) -> None:
        module = _load_module(
            ORDINAL_VTABLE_COMMON_PATH,
            "ordinal_vtable_common_stderr",
        )
        session = AsyncMock()
        session.call_tool.return_value = _FakeCallToolResult(
            {
                "result": "",
                "stdout": "debug stdout",
                "stderr": "Traceback: boom",
            }
        )

        with patch("builtins.print") as mock_print:
            result = await module.preprocess_ordinal_vtable_via_mcp(
                session=session,
                class_name="CSpawnGroupMgrGameSystem",
                ordinal=0,
                image_base=0x180000000,
                platform="windows",
                debug=True,
                symbol_aliases=["??_7CSpawnGroupMgrGameSystem@@6B@_0"],
                expected_offset_to_top=None,
            )

        self.assertIsNone(result)
        mock_print.assert_any_call(
            "    Preprocess ordinal vtable py_eval stderr:"
        )
        mock_print.assert_any_call("Traceback: boom")
        mock_print.assert_any_call(
            "    Preprocess ordinal vtable py_eval stdout:"
        )
        mock_print.assert_any_call("debug stdout")
        mock_print.assert_any_call(
            "    Preprocess ordinal vtable: empty py_eval result for "
            "CSpawnGroupMgrGameSystem[0]"
        )

    async def test_preprocess_ordinal_vtable_forwards_constraints_into_py_eval(self) -> None:
        module = _load_module(
            ORDINAL_VTABLE_COMMON_PATH,
            "ordinal_vtable_common_constraints",
        )
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(None)

        result = await module.preprocess_ordinal_vtable_via_mcp(
            session=session,
            class_name="CSpawnGroupMgrGameSystem",
            ordinal=2,
            image_base=0x180000000,
            platform="linux",
            debug=False,
            expected_offset_to_top=-16,
        )

        self.assertIsNone(result)
        py_code = session.call_tool.await_args.kwargs["arguments"]["code"]
        self.assertIn("ordinal = 2", py_code)
        self.assertIn("expected_offset_to_top = -16", py_code)

    async def test_preprocess_ordinal_vtable_returns_none_for_empty_result(self) -> None:
        module = _load_module(
            ORDINAL_VTABLE_COMMON_PATH,
            "ordinal_vtable_common_none",
        )
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(None)

        result = await module.preprocess_ordinal_vtable_via_mcp(
            session=session,
            class_name="CSpawnGroupMgrGameSystem",
            ordinal=0,
            image_base=0x180000000,
            platform="linux",
            debug=False,
            symbol_aliases=["??_7CSpawnGroupMgrGameSystem@@6B@_0"],
            expected_offset_to_top=-8,
        )

        self.assertIsNone(result)

    def test_ordinal_py_eval_alias_fail_closed_even_when_rtti_is_available(self) -> None:
        shared_kwargs = {
            "class_name": "Foo",
            "ordinal": 0,
            "name_to_ea": {
                "??_R4Foo@@6B@": 0x1500,
            },
            "name_by_ea": {
                0x2008: "rtti_candidate",
            },
            "data_refs": {
                0x1500: [0x2000],
            },
            "ptr_values": {
                0x2008: 0x9000,
                0x2010: 0,
            },
            "func_addrs": {0x9000},
            "segments": [
                _FakeSegment(0x2000, 0x3000, 0),
                _FakeSegment(0x9000, 0xA000, 1),
            ],
        }

        fallback_result = _run_ordinal_vtable_py_eval(**shared_kwargs)
        self.assertEqual("rtti_candidate", fallback_result["vtable_symbol"])
        self.assertEqual("0x2008", fallback_result["vtable_va"])

        fail_closed_result = _run_ordinal_vtable_py_eval(
            **shared_kwargs,
            symbol_aliases=["??_7Foo@@6B@_0"],
        )
        self.assertIsNone(fail_closed_result)

    def test_ordinal_py_eval_can_match_alias_via_windows_rtti_when_direct_lookup_misses(self) -> None:
        result = _run_ordinal_vtable_py_eval(
            class_name="Foo",
            ordinal=0,
            symbol_aliases=["??_7Foo@@6B@_0"],
            name_to_ea={
                "??_R4Foo@@6B@_0": 0x1500,
            },
            name_by_ea={
                0x2008: "??_7Foo@@6B@_0",
            },
            data_refs={
                0x1500: [0x2000],
            },
            ptr_values={
                0x2008: 0x9000,
                0x2010: 0,
            },
            func_addrs={0x9000},
            segments=[
                _FakeSegment(0x2000, 0x3000, 0),
                _FakeSegment(0x9000, 0xA000, 1),
            ],
        )

        self.assertEqual("??_7Foo@@6B@_0", result["vtable_symbol"])
        self.assertEqual("0x2008", result["vtable_va"])

    def test_ordinal_py_eval_linux_zero_slot_continues_until_boundary(self) -> None:
        result = _run_ordinal_vtable_py_eval(
            class_name="Foo",
            ordinal=0,
            symbol_aliases=["_ZTV3Foo"],
            name_to_ea={
                "_ZTV3Foo": 0x2000,
            },
            name_by_ea={
                0x2028: "_ZTI3Foo",
            },
            ptr_values={
                0x2010: 0x9000,
                0x2018: 0,
                0x2020: 0x9010,
            },
            func_addrs={0x9000, 0x9010},
            segments=[
                _FakeSegment(0x2000, 0x3000, 0),
                _FakeSegment(0x9000, 0xA000, 1),
            ],
        )

        self.assertEqual("_ZTV3Foo + 0x10", result["vtable_symbol"])
        self.assertEqual(
            {
                "0": "0x9000",
                "1": "0x0",
                "2": "0x9010",
            },
            result["vtable_entries"],
        )
        self.assertEqual(3, result["vtable_numvfunc"])

    def test_ordinal_py_eval_filters_sorts_then_selects_by_ordinal(self) -> None:
        result = _run_ordinal_vtable_py_eval(
            class_name="Foo",
            ordinal=1,
            expected_offset_to_top=-8,
            name_to_ea={
                "_ZTI3Foo": 0x1800,
            },
            name_by_ea={
                0x5010: "vt_high",
                0x3010: "vt_filtered_out",
                0x4010: "vt_low",
                0x5018: "_ZTVboundary_high",
                0x3018: "_ZTVboundary_filtered_out",
                0x4018: "_ZTIboundary_low",
            },
            data_refs={
                0x1800: [0x5008, 0x3008, 0x4008],
            },
            ptr_values={
                0x5000: 0xFFFFFFFFFFFFFFF8,
                0x3000: 0xFFFFFFFFFFFFFFF0,
                0x4000: 0xFFFFFFFFFFFFFFF8,
                0x5010: 0x9500,
                0x3010: 0x9300,
                0x4010: 0x9400,
            },
            func_addrs={0x9300, 0x9400, 0x9500},
            segments=[
                _FakeSegment(0x3000, 0x6000, 0),
                _FakeSegment(0x9300, 0x9600, 1),
            ],
        )

        self.assertEqual("vt_high", result["vtable_symbol"])
        self.assertEqual("0x5010", result["vtable_va"])


class TestFindBotAddCommandHandler(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_registerconcommand_contract(self) -> None:
        module = _load_module(
            BOT_ADD_COMMAND_HANDLER_SCRIPT_PATH,
            "find_BotAdd_CommandHandler",
        )
        mock_preprocess_registerconcommand_skill = AsyncMock(return_value=True)
        expected_generate_yaml_desired_fields = [
            (
                "BotAdd_CommandHandler",
                [
                    "func_name",
                    "func_sig",
                    "func_va",
                    "func_rva",
                    "func_size",
                ],
            )
        ]

        with patch.object(
            module,
            "preprocess_registerconcommand_skill",
            mock_preprocess_registerconcommand_skill,
        ):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="linux",
                image_base=0x400000,
                debug=True,
            )

        self.assertEqual("success", result)
        mock_preprocess_registerconcommand_skill.assert_awaited_once_with(
            session="session",
            expected_outputs=["out.yaml"],
            new_binary_dir="bin_dir",
            platform="linux",
            image_base=0x400000,
            target_name="BotAdd_CommandHandler",
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            command_name="bot_add",
            help_string="bot_add <t|ct> <type> <difficulty> <name> - Adds a bot matching the given criteria.",
            rename_to="BotAdd_CommandHandler",
            search_window_before_call=96,
            search_window_after_xref=96,
            debug=True,
        )


class TestFindShowHudHint(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_define_inputfunc_contract(self) -> None:
        module = _load_module(
            SHOW_HUD_HINT_SCRIPT_PATH,
            "find_ShowHudHint",
        )
        mock_helper = AsyncMock(return_value=True)
        expected_generate_yaml_desired_fields = [
            (
                "ShowHudHint",
                ["func_name", "func_va", "func_rva", "func_size", "func_sig"],
            )
        ]

        with patch.object(
            module,
            "preprocess_define_inputfunc_skill",
            mock_helper,
            create=True,
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

        self.assertEqual("success", result)
        mock_helper.assert_awaited_once_with(
            session="session",
            expected_outputs=["out.yaml"],
            platform="windows",
            image_base=0x180000000,
            target_name="ShowHudHint",
            input_name="ShowHudHint",
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            handler_ptr_offset=0x10,
            allowed_segment_names=(".data",),
            rename_to="ShowHudHint",
            debug=True,
        )


class TestFindCLoopModeGameOnEventMapCallbacksClient(
    unittest.IsolatedAsyncioTestCase
):
    async def test_preprocess_skill_forwards_register_event_listener_contract(
        self,
    ) -> None:
        module = _load_module(
            ON_EVENT_MAP_CALLBACKS_CLIENT_SCRIPT_PATH,
            "find_CLoopModeGame_OnEventMapCallbacks_client",
        )
        mock_helper = AsyncMock(return_value=True)

        with patch.object(
            module,
            "preprocess_register_event_listener_abstract_skill",
            mock_helper,
            create=True,
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
        mock_helper.assert_awaited_once_with(
            session="session",
            expected_outputs=["out.yaml"],
            new_binary_dir="bin_dir",
            platform="windows",
            image_base=0x180000000,
            source_yaml_stem=module.SOURCE_YAML_STEM,
            register_func_target_name=module.REGISTER_FUNC_TARGET_NAME,
            anchor_event_name=module.ANCHOR_EVENT_NAME,
            target_specs=module.TARGET_SPECS,
            generate_yaml_desired_fields=module.GENERATE_YAML_DESIRED_FIELDS,
            search_window_after_anchor=module.SEARCH_WINDOW_AFTER_ANCHOR,
            search_window_before_call=module.SEARCH_WINDOW_BEFORE_CALL,
            debug=True,
        )


class TestFindCFlattenedSerializersCreateFieldChangedEventQueueImpl(
    unittest.IsolatedAsyncioTestCase
):
    async def test_preprocess_skill_forwards_expected_inherit_vfuncs(self) -> None:
        module = _load_module(
            FLATTENED_SERIALIZERS_SCRIPT_PATH,
            "find_CFlattenedSerializers_CreateFieldChangedEventQueue",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_inherit_vfuncs = [
            (
                "CFlattenedSerializers_CreateFieldChangedEventQueue",
                "CFlattenedSerializers",
                "../server/IFlattenedSerializers_CreateFieldChangedEventQueue",
                True,
            )
        ]
        expected_generate_yaml_desired_fields = [
            (
                "CFlattenedSerializers_CreateFieldChangedEventQueue",
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
            inherit_vfuncs=expected_inherit_vfuncs,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
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
                "../engine/INetworkMessages_SetIsForServer",
                True,
            )
        ]
        expected_generate_yaml_desired_fields = [
            (
                "CNetworkMessages_SetIsForServer",
                [
                    "func_name",
                    "func_va",
                    "func_rva",
                    "func_size",
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
            inherit_vfuncs=expected_inherit_vfuncs,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
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
            (
                "INetworkMessages_SetIsForServer",
                "prompt/call_llm_decompile.md",
                "references/engine/CNetworkServerService_Init.{platform}.yaml",
            )
        ]
        expected_func_vtable_relations = [
            ("INetworkMessages_SetIsForServer", "INetworkMessages")
        ]
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


class TestFindCNetworkMessagesGetNetworkGroupStats(
    unittest.IsolatedAsyncioTestCase
):
    async def test_preprocess_skill_forwards_llm_and_vtable_wiring(self) -> None:
        module = _load_module(
            NETWORK_GROUP_STATS_SCRIPT_PATH,
            "find_INetworkMessages_GetNetworkGroupStats",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_llm_decompile_specs = [
            (
                "INetworkMessages_GetNetworkGroupCount",
                "prompt/call_llm_decompile.md",
                "references/networksystem/CNetworkSystem_SendNetworkStats.{platform}.yaml",
            ),
            (
                "INetworkMessages_GetNetworkGroupName",
                "prompt/call_llm_decompile.md",
                "references/networksystem/CNetworkSystem_SendNetworkStats.{platform}.yaml",
            ),
            (
                "INetworkMessages_GetNetworkGroupColor",
                "prompt/call_llm_decompile.md",
                "references/networksystem/CNetworkSystem_SendNetworkStats.{platform}.yaml",
            ),
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
        expected_generate_yaml_desired_fields = [
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
            vtable_class_names=expected_vtable_class_names,
            mangled_class_names=expected_mangled_class_names,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
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
        expected_generate_yaml_desired_fields = [
            (
                "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_Deallocate",
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
            inherit_vfuncs=expected_inherit_vfuncs,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            debug=True,
        )


class TestFindCSpawnGroupMgrGameSystemVtable2(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_uses_windows_secondary_vtable_alias(self) -> None:
        module = _load_module(
            CSPAWNGROUP_VTABLE2_SCRIPT_PATH,
            "find_CSpawnGroupMgrGameSystem_vtable2_windows",
        )
        mock_preprocess_ordinal_vtable = AsyncMock(
            return_value={
                "vtable_class": "CSpawnGroupMgrGameSystem",
                "vtable_symbol": "??_7CSpawnGroupMgrGameSystem@@6B@_0 + 0x10",
                "vtable_va": "0x1819682c0",
                "vtable_rva": "0x19682c0",
                "vtable_size": "0x20",
                "vtable_numvfunc": 4,
                "vtable_entries": {0: "0x180100000"},
            }
        )

        with patch.object(
            module,
            "preprocess_ordinal_vtable_via_mcp",
            mock_preprocess_ordinal_vtable,
        ), patch.object(module, "write_vtable_yaml") as mock_write_vtable_yaml:
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["tmp/CSpawnGroupMgrGameSystem_vtable2.windows.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="windows",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess_ordinal_vtable.assert_awaited_once_with(
            session="session",
            class_name="CSpawnGroupMgrGameSystem",
            ordinal=0,
            image_base=0x180000000,
            platform="windows",
            debug=True,
            symbol_aliases=["??_7CSpawnGroupMgrGameSystem@@6B@_0"],
            expected_offset_to_top=None,
        )
        mock_write_vtable_yaml.assert_called_once_with(
            "tmp/CSpawnGroupMgrGameSystem_vtable2.windows.yaml",
            mock_preprocess_ordinal_vtable.return_value,
        )

    async def test_preprocess_skill_uses_linux_offset_to_top_filter(self) -> None:
        module = _load_module(
            CSPAWNGROUP_VTABLE2_SCRIPT_PATH,
            "find_CSpawnGroupMgrGameSystem_vtable2_linux",
        )
        mock_preprocess_ordinal_vtable = AsyncMock(
            return_value={
                "vtable_class": "CSpawnGroupMgrGameSystem",
                "vtable_symbol": "_ZTI24CSpawnGroupMgrGameSystem ref 0x0",
                "vtable_va": "0x1819682d0",
                "vtable_rva": "0x19682d0",
                "vtable_size": "0x18",
                "vtable_numvfunc": 3,
                "vtable_entries": {0: "0x180100000"},
            }
        )

        with patch.object(
            module,
            "preprocess_ordinal_vtable_via_mcp",
            mock_preprocess_ordinal_vtable,
        ), patch.object(module, "write_vtable_yaml") as mock_write_vtable_yaml:
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["tmp/CSpawnGroupMgrGameSystem_vtable2.linux.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="linux",
                image_base=0x180000000,
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess_ordinal_vtable.assert_awaited_once_with(
            session="session",
            class_name="CSpawnGroupMgrGameSystem",
            ordinal=0,
            image_base=0x180000000,
            platform="linux",
            debug=True,
            symbol_aliases=None,
            expected_offset_to_top=-8,
        )
        mock_write_vtable_yaml.assert_called_once_with(
            "tmp/CSpawnGroupMgrGameSystem_vtable2.linux.yaml",
            mock_preprocess_ordinal_vtable.return_value,
        )


class TestFindCSpawnGroupMgrGameSystemDoesGameSystemReallocate(
    unittest.IsolatedAsyncioTestCase
):
    def test_build_factory_yaml_paths_prefers_local_then_sibling_client(self) -> None:
        module = _load_module(
            CSPAWNGROUP_DOES_REALLOCATE_SCRIPT_PATH,
            "find_CSpawnGroupMgrGameSystem_DoesGameSystemReallocate_paths",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141" / "server"
            paths = module._build_factory_yaml_paths(module_dir, "linux")

        self.assertEqual(
            [
                str(
                    Path(temp_dir)
                    / "bin"
                    / "14141"
                    / "server"
                    / "IGameSystemFactory_DoesGameSystemReallocate.linux.yaml"
                ),
                str(
                    Path(temp_dir)
                    / "bin"
                    / "14141"
                    / "client"
                    / "IGameSystemFactory_DoesGameSystemReallocate.linux.yaml"
                ),
            ],
            paths,
        )

    async def test_preprocess_skill_binds_to_secondary_vtable_artifact(self) -> None:
        module = _load_module(
            CSPAWNGROUP_DOES_REALLOCATE_SCRIPT_PATH,
            "find_CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)

        with patch.object(
            module,
            "preprocess_common_skill",
            mock_preprocess_common_skill,
        ), patch.object(
            module,
            "_read_vfunc_offset",
            return_value=0x18,
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
        self.assertEqual(
            [
                (
                    "CSpawnGroupMgrGameSystem_DoesGameSystemReallocate",
                    "CSpawnGroupMgrGameSystem_vtable2",
                )
            ],
            mock_preprocess_common_skill.await_args.kwargs[
                "func_vtable_relations"
            ],
        )
        self.assertEqual(
            "48 8B 0D ?? ?? ?? ?? 48 8B 01 48 FF 60 18",
            mock_preprocess_common_skill.await_args.kwargs["func_xrefs"][0][
                "xref_signatures"
            ][0],
        )

    async def test_preprocess_skill_reads_factory_yaml_from_sibling_client(self) -> None:
        module = _load_module(
            CSPAWNGROUP_DOES_REALLOCATE_SCRIPT_PATH,
            "find_CSpawnGroupMgrGameSystem_DoesGameSystemReallocate_linux",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            module_dir = Path(temp_dir) / "bin" / "14141"
            server_dir = module_dir / "server"
            client_dir = module_dir / "client"
            server_dir.mkdir(parents=True, exist_ok=True)
            client_dir.mkdir(parents=True, exist_ok=True)
            (
                client_dir / "IGameSystemFactory_DoesGameSystemReallocate.linux.yaml"
            ).write_text("vfunc_offset: 0x20\n", encoding="utf-8")

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
                    new_binary_dir=str(server_dir),
                    platform="linux",
                    image_base=0x180000000,
                    debug=True,
                )

        self.assertTrue(result)
        self.assertEqual(
            "48 8B 3D ?? ?? ?? ?? 48 8B 07 FF 60 20",
            mock_preprocess_common_skill.await_args.kwargs["func_xrefs"][0][
                "xref_signatures"
            ][0],
        )


class TestPreprocessSingleSkillViaMcp(unittest.IsolatedAsyncioTestCase):
    async def test_forwards_llm_config_when_script_accepts_it(self) -> None:
        received = {}

        async def fake_preprocess_skill(
            session, skill_name, expected_outputs, old_yaml_map,
            new_binary_dir, platform, image_base, llm_config, debug=False,
        ):
            received["args"] = {
                "session": session,
                "skill_name": skill_name,
                "expected_outputs": expected_outputs,
                "old_yaml_map": old_yaml_map,
                "new_binary_dir": new_binary_dir,
                "platform": platform,
                "image_base": image_base,
                "llm_config": llm_config,
                "debug": debug,
            }
            return True

        with patch.object(
            ida_skill_preprocessor,
            "_get_preprocess_entry",
            return_value=fake_preprocess_skill,
        ), patch.object(
            ida_skill_preprocessor.httpx,
            "AsyncClient",
            _FakeAsyncClient,
        ), patch.object(
            ida_skill_preprocessor,
            "streamable_http_client",
            return_value=_FakeStreamableHttpClient(),
        ), patch.object(
            ida_skill_preprocessor,
            "ClientSession",
            _FakeClientSession,
        ), patch.object(
            ida_skill_preprocessor,
            "parse_mcp_result",
            return_value={"result": "0x180000000"},
        ):
            result = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                host="127.0.0.1",
                port=13337,
                skill_name="find-CNetworkMessages_FindNetworkGroup",
                expected_outputs=["out.yaml"],
                old_yaml_map={"out.yaml": "old.yaml"},
                new_binary_dir="bin_dir",
                platform="windows",
                llm_model="gpt-4.1-mini",
                llm_apikey="test-api-key",
                llm_baseurl="https://example.invalid/v1",
                debug=True,
            )

        self.assertTrue(result)
        self.assertEqual(
            {
                "model": "gpt-4.1-mini",
                "api_key": "test-api-key",
                "base_url": "https://example.invalid/v1",
                "temperature": None,
                "effort": None,
                "fake_as": None,
            },
            received["args"]["llm_config"],
        )
        self.assertEqual(0x180000000, received["args"]["image_base"])
        self.assertTrue(received["args"]["debug"])

    async def test_forwards_full_llm_config_with_effort_and_fake_as(self) -> None:
        received = {}

        async def fake_preprocess_skill(
            session, skill_name, expected_outputs, old_yaml_map,
            new_binary_dir, platform, image_base, llm_config, debug=False,
        ):
            received["args"] = {
                "session": session,
                "skill_name": skill_name,
                "expected_outputs": expected_outputs,
                "old_yaml_map": old_yaml_map,
                "new_binary_dir": new_binary_dir,
                "platform": platform,
                "image_base": image_base,
                "llm_config": llm_config,
                "debug": debug,
            }
            return True

        with patch.object(
            ida_skill_preprocessor,
            "_get_preprocess_entry",
            return_value=fake_preprocess_skill,
        ), patch.object(
            ida_skill_preprocessor.httpx,
            "AsyncClient",
            _FakeAsyncClient,
        ), patch.object(
            ida_skill_preprocessor,
            "streamable_http_client",
            return_value=_FakeStreamableHttpClient(),
        ), patch.object(
            ida_skill_preprocessor,
            "ClientSession",
            _FakeClientSession,
        ), patch.object(
            ida_skill_preprocessor,
            "parse_mcp_result",
            return_value={"result": "0x180000000"},
        ):
            result = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                host="127.0.0.1",
                port=13337,
                skill_name="find-CNetworkMessages_FindNetworkGroup",
                expected_outputs=["out.yaml"],
                old_yaml_map={"out.yaml": "old.yaml"},
                new_binary_dir="bin_dir",
                platform="windows",
                llm_model="gpt-4.1-mini",
                llm_apikey="test-api-key",
                llm_baseurl="https://example.invalid/v1",
                llm_temperature=0.6,
                llm_effort="high",
                llm_fake_as="codex",
                debug=True,
            )

        self.assertTrue(result)
        self.assertEqual(
            {
                "model": "gpt-4.1-mini",
                "api_key": "test-api-key",
                "base_url": "https://example.invalid/v1",
                "temperature": 0.6,
                "effort": "high",
                "fake_as": "codex",
            },
            received["args"]["llm_config"],
        )
        self.assertEqual(0x180000000, received["args"]["image_base"])
        self.assertTrue(received["args"]["debug"])

    async def test_forwards_llm_max_retries_when_provided(self) -> None:
        received = {}

        async def fake_preprocess_skill(
            session, skill_name, expected_outputs, old_yaml_map,
            new_binary_dir, platform, image_base, llm_config, debug=False,
        ):
            received["llm_config"] = llm_config
            return True

        with patch.object(
            ida_skill_preprocessor,
            "_get_preprocess_entry",
            return_value=fake_preprocess_skill,
        ), patch.object(
            ida_skill_preprocessor.httpx,
            "AsyncClient",
            _FakeAsyncClient,
        ), patch.object(
            ida_skill_preprocessor,
            "streamable_http_client",
            return_value=_FakeStreamableHttpClient(),
        ), patch.object(
            ida_skill_preprocessor,
            "ClientSession",
            _FakeClientSession,
        ), patch.object(
            ida_skill_preprocessor,
            "parse_mcp_result",
            return_value={"result": "0x180000000"},
        ):
            result = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                host="127.0.0.1",
                port=13337,
                skill_name="find-CNetworkMessages_FindNetworkGroup",
                expected_outputs=["out.yaml"],
                old_yaml_map={"out.yaml": "old.yaml"},
                new_binary_dir="bin_dir",
                platform="windows",
                llm_model="gpt-5.4",
                llm_fake_as="codex",
                llm_max_retries=4,
                debug=True,
            )

        self.assertTrue(result)
        self.assertEqual(4, received["llm_config"]["max_retries"])

    async def test_skips_llm_config_when_script_does_not_accept_it(self) -> None:
        received = {}

        async def fake_preprocess_skill(
            session, skill_name, expected_outputs, old_yaml_map,
            new_binary_dir, platform, image_base, debug=False,
        ):
            received["args"] = {
                "session": session,
                "skill_name": skill_name,
                "expected_outputs": expected_outputs,
                "old_yaml_map": old_yaml_map,
                "new_binary_dir": new_binary_dir,
                "platform": platform,
                "image_base": image_base,
                "debug": debug,
            }
            return True

        with patch.object(
            ida_skill_preprocessor,
            "_get_preprocess_entry",
            return_value=fake_preprocess_skill,
        ), patch.object(
            ida_skill_preprocessor.httpx,
            "AsyncClient",
            _FakeAsyncClient,
        ), patch.object(
            ida_skill_preprocessor,
            "streamable_http_client",
            return_value=_FakeStreamableHttpClient(),
        ), patch.object(
            ida_skill_preprocessor,
            "ClientSession",
            _FakeClientSession,
        ), patch.object(
            ida_skill_preprocessor,
            "parse_mcp_result",
            return_value={"result": "0x180000000"},
        ):
            result = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                host="127.0.0.1",
                port=13337,
                skill_name="find-CNetworkMessages_FindNetworkGroup",
                expected_outputs=["out.yaml"],
                old_yaml_map={"out.yaml": "old.yaml"},
                new_binary_dir="bin_dir",
                platform="windows",
                llm_model="gpt-4.1-mini",
                llm_apikey="test-api-key",
                llm_baseurl="https://example.invalid/v1",
                debug=True,
            )

        self.assertEqual("success", result)
        self.assertEqual(0x180000000, received["args"]["image_base"])
        self.assertTrue(received["args"]["debug"])

    async def test_normalizes_absent_ok_status(self) -> None:
        async def fake_preprocess_skill(
            session, skill_name, expected_outputs, old_yaml_map,
            new_binary_dir, platform, image_base, llm_config, debug=False,
        ):
            return "absent_ok"

        with patch.object(
            ida_skill_preprocessor,
            "_get_preprocess_entry",
            return_value=fake_preprocess_skill,
        ), patch.object(
            ida_skill_preprocessor.httpx,
            "AsyncClient",
            _FakeAsyncClient,
        ), patch.object(
            ida_skill_preprocessor,
            "streamable_http_client",
            return_value=_FakeStreamableHttpClient(),
        ), patch.object(
            ida_skill_preprocessor,
            "ClientSession",
            _FakeClientSession,
        ), patch.object(
            ida_skill_preprocessor,
            "parse_mcp_result",
            return_value={"result": "0x180000000"},
        ):
            result = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                host="127.0.0.1",
                port=13337,
                skill_name="find-CNetworkMessages_FindNetworkGroup",
                expected_outputs=["out.yaml"],
                old_yaml_map={"out.yaml": "old.yaml"},
                new_binary_dir="bin_dir",
                platform="windows",
                llm_model="gpt-4.1-mini",
                llm_apikey="test-api-key",
                llm_baseurl="https://example.invalid/v1",
                debug=True,
            )

        self.assertEqual("absent_ok", result)
        self.assertTrue(result)

    async def test_normalizes_failed_status_as_falsey(self) -> None:
        async def fake_preprocess_skill(
            session, skill_name, expected_outputs, old_yaml_map,
            new_binary_dir, platform, image_base, llm_config, debug=False,
        ):
            return False

        with patch.object(
            ida_skill_preprocessor,
            "_get_preprocess_entry",
            return_value=fake_preprocess_skill,
        ), patch.object(
            ida_skill_preprocessor.httpx,
            "AsyncClient",
            _FakeAsyncClient,
        ), patch.object(
            ida_skill_preprocessor,
            "streamable_http_client",
            return_value=_FakeStreamableHttpClient(),
        ), patch.object(
            ida_skill_preprocessor,
            "ClientSession",
            _FakeClientSession,
        ), patch.object(
            ida_skill_preprocessor,
            "parse_mcp_result",
            return_value={"result": "0x180000000"},
        ):
            result = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                host="127.0.0.1",
                port=13337,
                skill_name="find-CNetworkMessages_FindNetworkGroup",
                expected_outputs=["out.yaml"],
                old_yaml_map={"out.yaml": "old.yaml"},
                new_binary_dir="bin_dir",
                platform="windows",
                llm_model="gpt-4.1-mini",
                llm_apikey="test-api-key",
                llm_baseurl="https://example.invalid/v1",
                debug=True,
            )

        self.assertEqual("failed", result)
        self.assertFalse(result)


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
        expected_func_vtable_relations = [
            ("CNetworkMessages_FindNetworkGroup", "CNetworkMessages")
        ]
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
            (
                "INetworkMessages_FindNetworkGroup",
                "prompt/call_llm_decompile.md",
                "references/engine/CNetworkGameClient_RecordEntityBandwidth.{platform}.yaml",
            )
        ]
        expected_func_vtable_relations = [
            ("INetworkMessages_FindNetworkGroup", "INetworkMessages")
        ]
        expected_generate_yaml_desired_fields = [
            (
                "INetworkMessages_FindNetworkGroup",
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
            func_names=["INetworkMessages_FindNetworkGroup"],
            func_vtable_relations=expected_func_vtable_relations,
            llm_decompile_specs=expected_llm_decompile_specs,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            llm_config=llm_config,
            debug=True,
        )


class TestFindINetworkMessagesSetNetworkSerializationContextDataAndCFlattenedSerializersCreateFieldChangedEventQueue(
    unittest.IsolatedAsyncioTestCase
):
    async def test_preprocess_skill_forwards_split_field_contracts(self) -> None:
        module = _load_module(
            "ida_preprocessor_scripts/find-INetworkMessages_SetNetworkSerializationContextData-AND-IFlattenedSerializers_CreateFieldChangedEventQueue.py",
            "find_INetworkMessages_SetNetworkSerializationContextData_AND_IFlattenedSerializers_CreateFieldChangedEventQueue",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_llm_decompile_specs = [
            (
                "INetworkMessages_SetNetworkSerializationContextData",
                "prompt/call_llm_decompile.md",
                "references/server/CEntitySystem_Activate.{platform}.yaml",
            ),
            (
                "IFlattenedSerializers_CreateFieldChangedEventQueue",
                "prompt/call_llm_decompile.md",
                "references/server/CEntitySystem_Activate.{platform}.yaml",
            ),
        ]
        expected_func_vtable_relations = [
            ("INetworkMessages_SetNetworkSerializationContextData", "INetworkMessages"),
            (
                "IFlattenedSerializers_CreateFieldChangedEventQueue",
                "IFlattenedSerializers",
            ),
        ]
        expected_generate_yaml_desired_fields = [
            (
                "INetworkMessages_SetNetworkSerializationContextData",
                [
                    "func_name",
                    "vfunc_sig",
                    "vfunc_offset",
                    "vfunc_index",
                    "vtable_name",
                ],
            ),
            (
                "IFlattenedSerializers_CreateFieldChangedEventQueue",
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
                expected_outputs=["out-a.yaml", "out-b.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="linux",
                image_base=0x180000000,
                llm_config=llm_config,
                debug=True,
            )

        self.assertTrue(result)
        mock_preprocess_common_skill.assert_awaited_once_with(
            session="session",
            expected_outputs=["out-a.yaml", "out-b.yaml"],
            old_yaml_map={"k": "v"},
            new_binary_dir="bin_dir",
            platform="linux",
            image_base=0x180000000,
            func_names=[
                "INetworkMessages_SetNetworkSerializationContextData",
                "IFlattenedSerializers_CreateFieldChangedEventQueue",
            ],
            func_vtable_relations=expected_func_vtable_relations,
            llm_decompile_specs=expected_llm_decompile_specs,
            llm_config=llm_config,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            debug=True,
        )


class TestFindCBaseEntityCollisionRulesChanged(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_generate_yaml_desired_fields(self) -> None:
        module = _load_module(
            "ida_preprocessor_scripts/find-CBaseEntity_CollisionRulesChanged.py",
            "find_CBaseEntity_CollisionRulesChanged",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_llm_decompile_specs = [
            (
                "CBaseEntity_CollisionRulesChanged",
                "prompt/call_llm_decompile.md",
                "references/server/PhysEnableEntityCollisions.{platform}.yaml",
            )
        ]
        expected_func_vtable_relations = [
            ("CBaseEntity_CollisionRulesChanged", "CBaseEntity")
        ]
        expected_generate_yaml_desired_fields = [
            (
                "CBaseEntity_CollisionRulesChanged",
                [
                    "func_name",
                    "vfunc_sig",
                    "vfunc_offset",
                    "vfunc_index",
                    "vtable_name",
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
            func_names=["CBaseEntity_CollisionRulesChanged"],
            func_vtable_relations=expected_func_vtable_relations,
            llm_decompile_specs=expected_llm_decompile_specs,
            llm_config=None,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            debug=True,
        )


class TestFindINetworkMessagesGetLoggingChannelWindows(
    unittest.IsolatedAsyncioTestCase
):
    async def test_preprocess_skill_forwards_vfunc_sig_max_match_directive(
        self,
    ) -> None:
        module = _load_module(
            I_GET_LOGGING_CHANNEL_WINDOWS_SCRIPT_PATH,
            "find_INetworkMessages_GetLoggingChannel_windows",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        llm_config = {"model": "gpt-4.1-mini", "api_key": "test-api-key"}
        expected_llm_decompile_specs = [
            (
                "INetworkMessages_GetLoggingChannel",
                "prompt/call_llm_decompile.md",
                (
                    "references/server/"
                    "CNetworkUtlVectorEmbedded_TryLateResolve_m_vecRenderAttributes."
                    "{platform}.yaml"
                ),
            )
        ]
        expected_func_vtable_relations = [
            ("INetworkMessages_GetLoggingChannel", "INetworkMessages")
        ]
        expected_generate_yaml_desired_fields = [
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
            func_names=["INetworkMessages_GetLoggingChannel"],
            func_vtable_relations=expected_func_vtable_relations,
            llm_decompile_specs=expected_llm_decompile_specs,
            llm_config=llm_config,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            debug=True,
        )


class TestFindINetworkMessagesGetLoggingChannelLinux(
    unittest.IsolatedAsyncioTestCase
):
    async def test_preprocess_skill_forwards_linux_llm_decompile_spec(
        self,
    ) -> None:
        module = _load_module(
            I_GET_LOGGING_CHANNEL_LINUX_SCRIPT_PATH,
            "find_INetworkMessages_GetLoggingChannel_linux",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        llm_config = {"model": "gpt-4.1-mini", "api_key": "test-api-key"}
        expected_llm_decompile_specs = [
            (
                "INetworkMessages_GetLoggingChannel",
                "prompt/call_llm_decompile.md",
                (
                    "references/server/"
                    "CNetworkUtlVectorEmbedded_NetworkStateChanged_m_vecRenderAttributes."
                    "{platform}.yaml"
                ),
            )
        ]
        expected_func_vtable_relations = [
            ("INetworkMessages_GetLoggingChannel", "INetworkMessages")
        ]
        expected_generate_yaml_desired_fields = [
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
                platform="linux",
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
            platform="linux",
            image_base=0x180000000,
            func_names=["INetworkMessages_GetLoggingChannel"],
            func_vtable_relations=expected_func_vtable_relations,
            llm_decompile_specs=expected_llm_decompile_specs,
            llm_config=llm_config,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
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
        expected_func_vtable_relations = [
            ("CNetworkServerService_Init", "CNetworkServerService")
        ]
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


class TestFindCcsPlayerMovementServicesProcessMovement(
    unittest.IsolatedAsyncioTestCase
):
    async def test_script_forwards_gv_backed_func_xrefs(self) -> None:
        module = _load_module(
            PROCESS_MOVEMENT_SCRIPT_PATH,
            "find_CCSPlayer_MovementServices_ProcessMovement",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        expected_func_xrefs = [
            {
                "func_name": "CCSPlayer_MovementServices_ProcessMovement",
                "xref_strings": [],
                "xref_gvs": ["CPlayer_MovementServices_s_pRunCommandPawn"],
                "xref_signatures": [],
                "xref_funcs": [],
                "xref_floats": ["64.0", "0.5"],
                "exclude_funcs": [
                    "CPlayer_MovementServices_ForceButtons",
                    "CPlayer_MovementServices_ForceButtonState",
                ],
                "exclude_strings": [],
                "exclude_gvs": [],
                "exclude_signatures": [],
                "exclude_floats": [],
            }
        ]
        expected_func_names = [
            "CCSPlayer_MovementServices_ProcessMovement",
        ]
        expected_generate_yaml_desired_fields = [
            (
                "CCSPlayer_MovementServices_ProcessMovement",
                [
                    "func_name",
                    "func_va",
                    "func_rva",
                    "func_size",
                    "func_sig",
                ],
            ),
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
            func_names=expected_func_names,
            func_xrefs=expected_func_xrefs,
            generate_yaml_desired_fields=expected_generate_yaml_desired_fields,
            debug=True,
        )


class TestFindILoopTypeDeallocateLoopMode(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_forwards_two_llm_specs_in_fixed_order(self) -> None:
        module = _load_module(
            Path("ida_preprocessor_scripts/find-ILoopType_DeallocateLoopMode.py"),
            "find_ILoopType_DeallocateLoopMode",
        )
        mock_preprocess_common_skill = AsyncMock(return_value=True)
        llm_config = {"model": "gpt-5.4", "fake_as": "codex"}
        expected_llm_decompile_specs = [
            (
                "ILoopType_DeallocateLoopMode",
                "prompt/call_llm_decompile.md",
                "references/engine/CEngineServiceMgr_DeactivateLoop.{platform}.yaml",
            ),
            (
                "ILoopType_DeallocateLoopMode",
                "prompt/call_llm_decompile.md",
                "references/engine/CEngineServiceMgr__MainLoop.{platform}.yaml",
            ),
        ]

        with patch.object(module, "preprocess_common_skill", mock_preprocess_common_skill):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={"k": "v"},
                new_binary_dir="bin_dir",
                platform="linux",
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
            platform="linux",
            image_base=0x180000000,
            func_names=["ILoopType_DeallocateLoopMode"],
            func_vtable_relations=[("ILoopType_DeallocateLoopMode", "ILoopType")],
            llm_decompile_specs=expected_llm_decompile_specs,
            llm_config=llm_config,
            generate_yaml_desired_fields=[
                (
                    "ILoopType_DeallocateLoopMode",
                    [
                        "func_name",
                        "vfunc_sig",
                        "vfunc_offset",
                        "vfunc_index",
                        "vtable_name",
                    ],
                )
            ],
            debug=True,
        )


class TestFindCEngineServiceMgrDeactivateLoop(unittest.IsolatedAsyncioTestCase):
    async def test_preprocess_skill_returns_absent_ok_for_verified_inline_sequence(
        self,
    ) -> None:
        module = _load_module(
            Path("ida_preprocessor_scripts/find-CEngineServiceMgr_DeactivateLoop.py"),
            "find_CEngineServiceMgr_DeactivateLoop",
        )

        with patch.object(
            module,
            "preprocess_common_skill",
            AsyncMock(return_value=False),
        ), patch.object(
            module,
            "_load_llm_decompile_target_detail_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "CEngineServiceMgr__MainLoop",
                    "func_va": "0x180555500",
                    "disasm_code": (
                        "call    qword ptr [rax+40h]\n"
                        "call    qword ptr [rax+30h]"
                    ),
                    "procedure": (
                        "loop_type->LoopDeactivate(loop_state);\n"
                        "loop_type->DeallocateLoopMode();"
                    ),
                }
            ),
        ) as mock_load_detail:
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={},
                new_binary_dir="bin_dir",
                platform="linux",
                image_base=0x180000000,
                llm_config={"model": "gpt-5.4", "fake_as": "codex"},
                debug=True,
            )

        self.assertEqual("absent_ok", result)
        mock_load_detail.assert_awaited_once_with(
            "session",
            "CEngineServiceMgr__MainLoop",
            new_binary_dir="bin_dir",
            platform="linux",
            debug=True,
        )

    async def test_preprocess_skill_keeps_failure_when_inline_markers_are_incomplete(
        self,
    ) -> None:
        module = _load_module(
            Path("ida_preprocessor_scripts/find-CEngineServiceMgr_DeactivateLoop.py"),
            "find_CEngineServiceMgr_DeactivateLoop",
        )

        with patch.object(
            module,
            "preprocess_common_skill",
            AsyncMock(return_value=False),
        ), patch.object(
            module,
            "_load_llm_decompile_target_detail_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "CEngineServiceMgr__MainLoop",
                    "func_va": "0x180555500",
                    "disasm_code": "call    qword ptr [rax+40h]",
                    "procedure": "loop_type->LoopDeactivate(loop_state);",
                }
            ),
        ):
            result = await module.preprocess_skill(
                session="session",
                skill_name="skill",
                expected_outputs=["out.yaml"],
                old_yaml_map={},
                new_binary_dir="bin_dir",
                platform="linux",
                image_base=0x180000000,
                llm_config={"model": "gpt-5.4", "fake_as": "codex"},
                debug=True,
            )

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()

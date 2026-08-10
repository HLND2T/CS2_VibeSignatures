import types
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import AsyncMock, MagicMock, patch

import ida_skill_preprocessor
from tests.ida_preprocessor_test_support import (
    FakeAsyncClient as _FakeAsyncClient,
    FakeClientSession as _FakeClientSession,
    FakeStreamableHttpClient as _FakeStreamableHttpClient,
    async_context as _async_context,
)

ida_skill_preprocessor.httpx = types.SimpleNamespace(AsyncClient=None)
ida_skill_preprocessor.streamable_http_client = None
ida_skill_preprocessor.ClientSession = None


class TestPreprocessSingleSkillViaMcp(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.open_session_patcher = patch.object(
            ida_skill_preprocessor,
            "open_ida_mcp_session",
            side_effect=lambda *args, **kwargs: _async_context(_FakeClientSession("read-stream", "write-stream")),
        )
        self.open_session_patcher.start()
        self.addCleanup(self.open_session_patcher.stop)

    async def test_returns_no_script_when_skill_has_no_preprocessor_script(self) -> None:
        with patch.object(
            ida_skill_preprocessor,
            "_get_preprocess_entry",
            return_value=None,
        ):
            result = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                host="127.0.0.1",
                port=13337,
                skill_name="find-NoPreprocessorScript",
                expected_outputs=["out.yaml"],
                old_yaml_map={},
                new_binary_dir="bin_dir",
                platform="windows",
                debug=True,
            )

        self.assertEqual("no_script", result)

    async def test_binds_expected_binary_to_one_preprocessor_session(self) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(return_value={})
        received = {}

        async def fake_preprocess_skill(**kwargs):
            received["session"] = kwargs["session"]
            return True

        with (
            patch.object(
                ida_skill_preprocessor,
                "_get_preprocess_entry",
                return_value=fake_preprocess_skill,
            ),
            patch.object(
                ida_skill_preprocessor,
                "open_ida_mcp_session",
                return_value=_async_context(session),
                create=True,
            ) as open_session,
            patch.object(
                ida_skill_preprocessor.httpx,
                "AsyncClient",
                _FakeAsyncClient,
            ),
            patch.object(
                ida_skill_preprocessor,
                "streamable_http_client",
                return_value=_FakeStreamableHttpClient(),
            ),
            patch.object(
                ida_skill_preprocessor,
                "ClientSession",
                _FakeClientSession,
            ),
            patch.object(ida_skill_preprocessor, "parse_mcp_result", return_value={"result": "0x180000000"}),
        ):
            result = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                host="127.0.0.1",
                port=13337,
                skill_name="find-CNetworkMessages_FindNetworkGroup",
                expected_outputs=["out.yaml"],
                old_yaml_map=None,
                new_binary_dir="bin_dir",
                platform="windows",
                expected_binary=r"D:\repo\server.dll",
            )

        self.assertEqual("success", result)
        self.assertIs(session, received["session"])
        open_session.assert_called_once_with(
            "127.0.0.1",
            13337,
            expected_binary=r"D:\repo\server.dll",
        )

    async def test_forwards_llm_config_when_script_accepts_it(self) -> None:
        received = {}

        async def fake_preprocess_skill(
            session,
            skill_name,
            expected_outputs,
            old_yaml_map,
            new_binary_dir,
            platform,
            image_base,
            llm_config,
            debug=False,
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

        with (
            patch.object(
                ida_skill_preprocessor,
                "_get_preprocess_entry",
                return_value=fake_preprocess_skill,
            ),
            patch.object(
                ida_skill_preprocessor.httpx,
                "AsyncClient",
                _FakeAsyncClient,
            ),
            patch.object(
                ida_skill_preprocessor,
                "streamable_http_client",
                return_value=_FakeStreamableHttpClient(),
            ),
            patch.object(
                ida_skill_preprocessor,
                "ClientSession",
                _FakeClientSession,
            ),
            patch.object(
                ida_skill_preprocessor,
                "parse_mcp_result",
                return_value={"result": "0x180000000"},
            ),
        ):
            result = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                host="127.0.0.1",
                port=13337,
                skill_name="find-CNetworkMessages_FindNetworkGroup",
                expected_outputs=["out.yaml"],
                expected_inputs=[r"D:\repo\Input.windows.yaml"],
                optional_inputs=[r"D:\repo\Optional.windows.yaml"],
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
                "_expected_inputs": [r"D:\repo\Input.windows.yaml"],
                "_optional_inputs": [r"D:\repo\Optional.windows.yaml"],
            },
            received["args"]["llm_config"],
        )
        self.assertEqual(0x180000000, received["args"]["image_base"])
        self.assertTrue(received["args"]["debug"])

    async def test_forwards_full_llm_config_with_effort_and_fake_as(self) -> None:
        received = {}

        async def fake_preprocess_skill(
            session,
            skill_name,
            expected_outputs,
            old_yaml_map,
            new_binary_dir,
            platform,
            image_base,
            llm_config,
            debug=False,
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

        with (
            patch.object(
                ida_skill_preprocessor,
                "_get_preprocess_entry",
                return_value=fake_preprocess_skill,
            ),
            patch.object(
                ida_skill_preprocessor.httpx,
                "AsyncClient",
                _FakeAsyncClient,
            ),
            patch.object(
                ida_skill_preprocessor,
                "streamable_http_client",
                return_value=_FakeStreamableHttpClient(),
            ),
            patch.object(
                ida_skill_preprocessor,
                "ClientSession",
                _FakeClientSession,
            ),
            patch.object(
                ida_skill_preprocessor,
                "parse_mcp_result",
                return_value={"result": "0x180000000"},
            ),
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
                "_expected_inputs": [],
                "_optional_inputs": [],
            },
            received["args"]["llm_config"],
        )
        self.assertEqual(0x180000000, received["args"]["image_base"])
        self.assertTrue(received["args"]["debug"])

    async def test_forwards_llm_max_retries_when_provided(self) -> None:
        received = {}

        async def fake_preprocess_skill(
            session,
            skill_name,
            expected_outputs,
            old_yaml_map,
            new_binary_dir,
            platform,
            image_base,
            llm_config,
            debug=False,
        ):
            received["llm_config"] = llm_config
            return True

        with (
            patch.object(
                ida_skill_preprocessor,
                "_get_preprocess_entry",
                return_value=fake_preprocess_skill,
            ),
            patch.object(
                ida_skill_preprocessor.httpx,
                "AsyncClient",
                _FakeAsyncClient,
            ),
            patch.object(
                ida_skill_preprocessor,
                "streamable_http_client",
                return_value=_FakeStreamableHttpClient(),
            ),
            patch.object(
                ida_skill_preprocessor,
                "ClientSession",
                _FakeClientSession,
            ),
            patch.object(
                ida_skill_preprocessor,
                "parse_mcp_result",
                return_value={"result": "0x180000000"},
            ),
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
            session,
            skill_name,
            expected_outputs,
            old_yaml_map,
            new_binary_dir,
            platform,
            image_base,
            debug=False,
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

        with (
            patch.object(
                ida_skill_preprocessor,
                "_get_preprocess_entry",
                return_value=fake_preprocess_skill,
            ),
            patch.object(
                ida_skill_preprocessor.httpx,
                "AsyncClient",
                _FakeAsyncClient,
            ),
            patch.object(
                ida_skill_preprocessor,
                "streamable_http_client",
                return_value=_FakeStreamableHttpClient(),
            ),
            patch.object(
                ida_skill_preprocessor,
                "ClientSession",
                _FakeClientSession,
            ),
            patch.object(
                ida_skill_preprocessor,
                "parse_mcp_result",
                return_value={"result": "0x180000000"},
            ),
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

    async def test_reports_script_exceptions_without_requiring_debug(self) -> None:
        async def fake_preprocess_skill(**kwargs):
            raise RuntimeError("exploded")

        for debug in (False, True):
            with self.subTest(debug=debug):
                output = StringIO()
                with (
                    patch.object(
                        ida_skill_preprocessor,
                        "_get_preprocess_entry",
                        return_value=fake_preprocess_skill,
                    ),
                    patch.object(
                        ida_skill_preprocessor,
                        "open_ida_mcp_session",
                        return_value=_async_context(_FakeClientSession("read-stream", "write-stream")),
                    ),
                    patch.object(
                        ida_skill_preprocessor,
                        "parse_mcp_result",
                        return_value={"result": "0x180000000"},
                    ),
                    redirect_stdout(output),
                ):
                    result = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                        host="127.0.0.1",
                        port=13337,
                        skill_name="find-CNetworkMessages_FindNetworkGroup",
                        expected_outputs=["out.yaml"],
                        old_yaml_map={},
                        new_binary_dir="bin_dir",
                        platform="windows",
                        debug=debug,
                    )

                diagnostic = output.getvalue()
                self.assertEqual("failed", result)
                self.assertIn(
                    "Preprocess error [script execution] for find-CNetworkMessages_FindNetworkGroup: RuntimeError: exploded",
                    diagnostic,
                )
                self.assertEqual(debug, "Traceback (most recent call last):" in diagnostic)

    async def test_normalizes_script_statuses(self) -> None:
        cases = [
            ("absent_ok", "absent_ok", True),
            (False, "failed", False),
        ]

        for script_result, expected_status, expected_truthiness in cases:
            with self.subTest(script_result=script_result):

                async def fake_preprocess_skill(
                    session,
                    skill_name,
                    expected_outputs,
                    old_yaml_map,
                    new_binary_dir,
                    platform,
                    image_base,
                    llm_config,
                    debug=False,
                ):
                    return script_result

                with (
                    patch.object(
                        ida_skill_preprocessor,
                        "_get_preprocess_entry",
                        return_value=fake_preprocess_skill,
                    ),
                    patch.object(
                        ida_skill_preprocessor.httpx,
                        "AsyncClient",
                        _FakeAsyncClient,
                    ),
                    patch.object(
                        ida_skill_preprocessor,
                        "streamable_http_client",
                        return_value=_FakeStreamableHttpClient(),
                    ),
                    patch.object(
                        ida_skill_preprocessor,
                        "ClientSession",
                        _FakeClientSession,
                    ),
                    patch.object(
                        ida_skill_preprocessor,
                        "parse_mcp_result",
                        return_value={"result": "0x180000000"},
                    ),
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

                self.assertEqual(expected_status, result)
                self.assertEqual(expected_truthiness, bool(result))


if __name__ == "__main__":
    unittest.main()

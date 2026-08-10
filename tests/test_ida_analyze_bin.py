import io
import json
import subprocess
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call, patch

import ida_analyze_bin
from ida_mcp_session import (
    McpDatabaseBinding,
    McpDatabaseSelectionError,
    McpDatabaseUnavailableError,
    McpToolCallError,
)
from process_reporter import (
    EdgeType,
    PlanNodeType,
    ProcessEventType,
    ProcessPhase,
    ProcessReason,
    RunStatus,
    TaskStatus,
)


def _tool_result(payload):
    return SimpleNamespace(content=[SimpleNamespace(text=json.dumps(payload))])


@asynccontextmanager
async def _async_context(value):
    yield value


class TestQuitIdaGracefully(unittest.IsolatedAsyncioTestCase):
    async def test_quit_ida_gracefully_async_stops_only_supplied_process(self) -> None:
        process = MagicMock()
        process.poll.return_value = None

        with (
            patch.object(
                ida_analyze_bin,
                "quit_ida_via_mcp",
                AsyncMock(return_value=True),
            ) as quit_ida_via_mcp,
            patch.object(ida_analyze_bin, "stop_idalib_mcp_process") as stop_process,
            patch.object(ida_analyze_bin, "wait_for_port_release", return_value=True) as wait_for_release,
        ):
            await ida_analyze_bin.quit_ida_gracefully_async(
                process,
                "127.0.0.1",
                13337,
                expected_binary="server.dll",
                debug=False,
            )

        quit_ida_via_mcp.assert_awaited_once_with(
            "127.0.0.1",
            13337,
            expected_binary="server.dll",
            auto_started=True,
        )
        stop_process.assert_called_once_with(process, debug=False)
        wait_for_release.assert_called_once_with(
            "127.0.0.1",
            13337,
            ida_analyze_bin.MCP_SHUTDOWN_TIMEOUT,
        )

    async def test_quit_owned_auto_started_worker(self) -> None:
        session = MagicMock()
        session.binding = McpDatabaseBinding(True, "server-db", "server.dll", "worker", True, True)
        session.call_tool = AsyncMock()

        with patch.object(
            ida_analyze_bin,
            "open_ida_mcp_session",
            return_value=_async_context(session),
        ):
            result = await ida_analyze_bin.quit_ida_via_mcp(
                "127.0.0.1",
                13337,
                expected_binary="server.dll",
                auto_started=True,
            )

        self.assertTrue(result)
        session.call_tool.assert_awaited_once_with("py_eval", {"code": "import idc; idc.qexit(0)"})

    async def test_worker_disconnect_after_qexit_is_successful_cleanup(self) -> None:
        session = MagicMock()
        session.binding = McpDatabaseBinding(True, "server-db", "server.dll", "worker", True, True)
        session.call_tool = AsyncMock(
            side_effect=McpToolCallError("MCP tool py_eval failed: [WinError 10054] 远程主机强迫关闭了一个现有的连接。")
        )

        with patch.object(
            ida_analyze_bin,
            "open_ida_mcp_session",
            return_value=_async_context(session),
        ):
            result = await ida_analyze_bin.quit_ida_via_mcp(
                "127.0.0.1",
                13337,
                expected_binary="server.dll",
                auto_started=True,
            )

        self.assertTrue(result)

    async def test_does_not_quit_unowned_gui_or_attach_existing_worker(self) -> None:
        bindings = (
            McpDatabaseBinding(True, "server-db", "server.dll", "worker", False, True),
            McpDatabaseBinding(True, "server-db", "server.dll", "gui", True, True),
            McpDatabaseBinding(True, "server-db", "server.dll", "worker", True, False),
        )

        for binding in bindings:
            with self.subTest(binding=binding):
                session = MagicMock()
                session.binding = binding
                session.call_tool = AsyncMock()
                with patch.object(
                    ida_analyze_bin,
                    "open_ida_mcp_session",
                    return_value=_async_context(session),
                ):
                    result = await ida_analyze_bin.quit_ida_via_mcp(
                        "127.0.0.1",
                        13337,
                        expected_binary="server.dll",
                        auto_started=binding.auto_started,
                    )

                self.assertFalse(result)
                session.call_tool.assert_not_awaited()

    async def test_database_selection_failure_skips_qexit(self) -> None:
        with patch.object(
            ida_analyze_bin,
            "open_ida_mcp_session",
            side_effect=McpDatabaseSelectionError("multiple active MCP databases"),
        ):
            result = await ida_analyze_bin.quit_ida_via_mcp(
                "127.0.0.1",
                13337,
                expected_binary="server.dll",
                auto_started=True,
            )

        self.assertFalse(result)

    async def test_quit_ida_gracefully_rejects_running_loop(self) -> None:
        process = MagicMock()
        process.poll.return_value = None

        with self.assertRaisesRegex(
            RuntimeError,
            "use await quit_ida_gracefully_async\\(\\) instead",
        ):
            ida_analyze_bin.quit_ida_gracefully(
                process,
                "127.0.0.1",
                13337,
                expected_binary="server.dll",
                debug=False,
            )


class TestQuitIdaGracefullySyncWrapper(unittest.TestCase):
    def test_quit_ida_gracefully_runs_async_helper_from_sync_context(self) -> None:
        process = MagicMock()
        process.poll.return_value = None

        with patch.object(
            ida_analyze_bin,
            "quit_ida_gracefully_async",
            AsyncMock(),
        ) as quit_ida_gracefully_async:
            ida_analyze_bin.quit_ida_gracefully(
                process,
                "127.0.0.1",
                13337,
                expected_binary="server.dll",
                debug=True,
            )

        quit_ida_gracefully_async.assert_awaited_once_with(
            process,
            "127.0.0.1",
            13337,
            expected_binary="server.dll",
            debug=True,
        )


class TestStopIdalibMcpProcess(unittest.TestCase):
    def test_terminates_owned_process_without_contacting_mcp(self) -> None:
        process = MagicMock()
        process.poll.return_value = None

        ida_analyze_bin.stop_idalib_mcp_process(process, debug=False)

        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=10)
        process.kill.assert_not_called()

    def test_kills_owned_process_when_terminate_times_out(self) -> None:
        process = MagicMock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("idalib-mcp", 10), 0]

        ida_analyze_bin.stop_idalib_mcp_process(process, debug=False)

        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual([call(timeout=10), call(timeout=5)], process.wait.call_args_list)


class TestIsPortInUse(unittest.TestCase):
    def test_returns_true_when_connection_succeeds(self) -> None:
        connection = MagicMock()
        with patch.object(ida_analyze_bin.socket, "create_connection", return_value=connection) as create_connection:
            result = ida_analyze_bin.is_port_in_use("127.0.0.1", 13337)

        self.assertTrue(result)
        create_connection.assert_called_once_with(("127.0.0.1", 13337), timeout=1)
        connection.__enter__.assert_called_once_with()
        connection.__exit__.assert_called_once()

    def test_returns_false_when_connection_fails(self) -> None:
        with patch.object(ida_analyze_bin.socket, "create_connection", side_effect=OSError) as create_connection:
            result = ida_analyze_bin.is_port_in_use("127.0.0.1", 13337)

        self.assertFalse(result)
        create_connection.assert_called_once_with(("127.0.0.1", 13337), timeout=1)


class TestWaitForPortRelease(unittest.TestCase):
    def test_waits_until_the_supervisor_port_is_released(self) -> None:
        with (
            patch.object(ida_analyze_bin, "is_port_in_use", side_effect=[True, True, False]) as port_in_use,
            patch.object(ida_analyze_bin.time, "sleep") as sleep,
        ):
            released = ida_analyze_bin.wait_for_port_release(
                "127.0.0.1",
                13337,
                timeout=1.0,
                retry_interval=0.01,
            )

        self.assertTrue(released)
        self.assertEqual(3, port_in_use.call_count)
        self.assertEqual(2, sleep.call_count)

    def test_returns_false_when_the_port_does_not_release_before_timeout(self) -> None:
        with (
            patch.object(ida_analyze_bin, "is_port_in_use", return_value=True),
            patch.object(ida_analyze_bin.time, "monotonic", side_effect=[0.0, 1.0]),
            patch.object(ida_analyze_bin.time, "sleep") as sleep,
        ):
            released = ida_analyze_bin.wait_for_port_release(
                "127.0.0.1",
                13337,
                timeout=0.5,
                retry_interval=0.01,
            )

        self.assertFalse(released)
        sleep.assert_not_called()


class TestSurveyBinaryViaSession(unittest.IsolatedAsyncioTestCase):
    async def test_survey_binary_via_mcp_binds_expected_binary(self) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(
            side_effect=[
                _tool_result({"metadata": {"path": "server.dll"}}),
                _tool_result({"result": json.dumps({"metadata": {"path": "server.dll.i64"}})}),
            ]
        )

        with patch.object(
            ida_analyze_bin,
            "open_ida_mcp_session",
            return_value=_async_context(session),
        ) as open_session:
            result = await ida_analyze_bin.survey_binary_via_mcp(
                "127.0.0.1",
                13337,
                expected_binary=r"D:\repo\server.dll",
            )

        self.assertEqual("server.dll.i64", result["metadata"]["path"])
        open_session.assert_called_once_with(
            "127.0.0.1",
            13337,
            expected_binary=r"D:\repo\server.dll",
        )

    async def test_checks_supervisor_and_worker_health_separately(self) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(return_value=_tool_result({"result": "1"}))

        with (
            patch.object(
                ida_analyze_bin,
                "check_ida_mcp_supervisor_health",
                new=AsyncMock(return_value=True),
            ) as supervisor_health,
            patch.object(
                ida_analyze_bin,
                "open_ida_mcp_session",
                return_value=_async_context(session),
            ) as open_session,
        ):
            self.assertTrue(await ida_analyze_bin.check_mcp_supervisor_health("127.0.0.1", 13337))
            self.assertTrue(
                await ida_analyze_bin.check_mcp_worker_health(
                    "127.0.0.1",
                    13337,
                    r"D:\repo\server.dll",
                )
            )

        supervisor_health.assert_awaited_once_with("127.0.0.1", 13337)
        open_session.assert_called_once_with(
            "127.0.0.1",
            13337,
            expected_binary=r"D:\repo\server.dll",
        )
        session.call_tool.assert_awaited_once_with(name="py_eval", arguments={"code": "1"})

    async def test_survey_binary_via_session_falls_back_to_current_idb_path(self) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(
            side_effect=[
                RuntimeError("Invalid structured content returned by tool survey_binary"),
                _tool_result(
                    {
                        "result": json.dumps(
                            {"metadata": {"path": "/mnt/d/CS2_VibeSignatures/bin/14141c/server/libserver.so.i64"}}
                        ),
                        "stdout": "",
                        "stderr": "",
                    }
                ),
            ]
        )

        result = await ida_analyze_bin.survey_binary_via_session(session, detail_level="minimal")

        self.assertEqual(
            {"metadata": {"path": "/mnt/d/CS2_VibeSignatures/bin/14141c/server/libserver.so.i64"}},
            result,
        )
        self.assertEqual(
            [
                call(name="survey_binary", arguments={"detail_level": "minimal"}),
                call(name="py_eval", arguments={"code": ida_analyze_bin.SURVEY_CURRENT_IDB_PATH_PY_EVAL}),
            ],
            session.call_tool.await_args_list,
        )

    async def test_survey_binary_via_session_prefers_current_idb_path_over_stale_binary_path(self) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(
            side_effect=[
                _tool_result(
                    {
                        "metadata": {
                            "path": "/old/location/bin/14141c/server/libserver.so",
                            "module": "libserver.so",
                        },
                        "statistics": {"total_functions": 123},
                    }
                ),
                _tool_result(
                    {
                        "result": json.dumps(
                            {"metadata": {"path": "/new/location/bin/14141c/server/libserver.so.i64"}}
                        ),
                        "stdout": "",
                        "stderr": "",
                    }
                ),
            ]
        )

        result = await ida_analyze_bin.survey_binary_via_session(session, detail_level="minimal")

        self.assertEqual(
            {
                "metadata": {
                    "path": "/new/location/bin/14141c/server/libserver.so.i64",
                    "module": "libserver.so",
                },
                "statistics": {"total_functions": 123},
            },
            result,
        )
        self.assertEqual(
            [
                call(name="survey_binary", arguments={"detail_level": "minimal"}),
                call(name="py_eval", arguments={"code": ida_analyze_bin.SURVEY_CURRENT_IDB_PATH_PY_EVAL}),
            ],
            session.call_tool.await_args_list,
        )


class TestMcpEntrypointRouting(unittest.IsolatedAsyncioTestCase):
    async def test_analysis_entrypoints_bind_expected_binary(self) -> None:
        expected_binary = r"D:\repo\server.dll"
        session = MagicMock()

        with (
            patch.object(
                ida_analyze_bin,
                "open_ida_mcp_session",
                side_effect=lambda *_args, **_kwargs: _async_context(session),
            ) as open_session,
            patch.object(
                ida_analyze_bin,
                "validate_expected_input_artifacts_via_session",
                new=AsyncMock(return_value=[]),
            ),
            patch.object(
                ida_analyze_bin,
                "post_process_expected_outputs_via_session",
                new=AsyncMock(return_value=True),
            ),
            patch.object(
                ida_analyze_bin,
                "export_object_xref_details_via_mcp",
                new=AsyncMock(return_value={"status": "success"}),
            ),
        ):
            validated = await ida_analyze_bin.validate_expected_input_artifacts_via_mcp(
                expected_inputs=["fixture.yaml"],
                expected_binary=expected_binary,
            )
            post_processed = await ida_analyze_bin.post_process_expected_outputs_via_mcp(
                yaml_items=[("fixture.yaml", {})],
                expected_binary=expected_binary,
            )
            vcall_result = await ida_analyze_bin.preprocess_single_vcall_object_via_mcp(
                host="127.0.0.1",
                port=13337,
                output_root="vcall",
                gamever="14168",
                module_name="server",
                platform="windows",
                object_name="g_pExample",
                expected_binary=expected_binary,
            )

        self.assertEqual([], validated)
        self.assertTrue(post_processed)
        self.assertEqual({"status": "success"}, vcall_result)
        self.assertEqual(
            [
                call("127.0.0.1", 13337, expected_binary=expected_binary),
                call("127.0.0.1", 13337, expected_binary=expected_binary),
                call("127.0.0.1", 13337, expected_binary=expected_binary),
            ],
            open_session.call_args_list,
        )


class TestOpenedBinaryIdentityValidation(unittest.TestCase):
    def test_verification_does_not_retry_an_inactive_database(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "libclient.so"
            binary_path.write_bytes(b"client-binary")

            with (
                patch.object(
                    ida_analyze_bin,
                    "survey_binary_via_mcp",
                    new=AsyncMock(side_effect=McpDatabaseUnavailableError("inactive or unreachable")),
                ) as survey_binary,
                patch.object(ida_analyze_bin.time, "sleep") as sleep,
            ):
                with self.assertRaisesRegex(McpDatabaseUnavailableError, "inactive or unreachable"):
                    ida_analyze_bin.verify_opened_binary_via_mcp(
                        str(binary_path),
                        "linux",
                        retry_interval=0.01,
                    )

        self.assertEqual(1, survey_binary.await_count)
        sleep.assert_not_called()

    def test_verification_does_not_retry_mcp_tool_error(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "server.dll"
            binary_path.write_bytes(b"fixture")

            with (
                patch.object(
                    ida_analyze_bin,
                    "survey_binary_via_mcp",
                    new=AsyncMock(side_effect=McpToolCallError("survey_binary: database is required")),
                ) as survey,
                patch.object(ida_analyze_bin.time, "sleep") as sleep,
                patch("sys.stdout", new_callable=io.StringIO) as stdout,
            ):
                verified = ida_analyze_bin.verify_opened_binary_via_mcp(str(binary_path), "windows")

        self.assertFalse(verified)
        self.assertEqual(1, survey.await_count)
        sleep.assert_not_called()
        self.assertIn("database is required", stdout.getvalue())

    def test_verification_retries_when_survey_metadata_is_not_ready(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "server.dll"
            binary_path.write_bytes(b"server-binary")
            ready_survey = {"metadata": {"path": str(binary_path)}}

            with (
                patch.object(
                    ida_analyze_bin,
                    "survey_binary_via_mcp",
                    new=AsyncMock(side_effect=[None, ready_survey]),
                ) as survey_binary,
                patch.object(ida_analyze_bin.time, "sleep") as sleep,
            ):
                verified = ida_analyze_bin.verify_opened_binary_via_mcp(
                    str(binary_path),
                    "windows",
                    verify_timeout=1.0,
                    retry_interval=0.01,
                )

        self.assertTrue(verified)
        self.assertEqual(2, survey_binary.await_count)
        sleep.assert_called_once_with(0.01)

    def test_verification_does_not_retry_a_definite_path_mismatch(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "server.dll"
            binary_path.write_bytes(b"server-binary")
            wrong_survey = {"metadata": {"path": str(Path(temp_dir) / "engine2.dll")}}

            with (
                patch.object(
                    ida_analyze_bin,
                    "survey_binary_via_mcp",
                    new=AsyncMock(return_value=wrong_survey),
                ) as survey_binary,
                patch.object(ida_analyze_bin.time, "sleep") as sleep,
                patch("sys.stdout", new_callable=io.StringIO),
            ):
                verified = ida_analyze_bin.verify_opened_binary_via_mcp(
                    str(binary_path),
                    "windows",
                    verify_timeout=1.0,
                    retry_interval=0.01,
                )

        self.assertFalse(verified)
        self.assertEqual(1, survey_binary.await_count)
        sleep.assert_not_called()


class TestOwnedMcpVerificationRecovery(unittest.TestCase):
    def test_restarts_an_unhealthy_owned_worker_once_and_reverifies(self) -> None:
        original_process = object()
        restarted_process = object()
        recovery_budget = ida_analyze_bin.McpRecoveryBudget()

        with (
            patch.object(
                ida_analyze_bin,
                "verify_opened_binary_via_mcp",
                side_effect=[McpDatabaseUnavailableError("inactive or unreachable"), True],
            ) as verify,
            patch.object(
                ida_analyze_bin,
                "ensure_mcp_available",
                return_value=(restarted_process, True),
            ) as ensure,
            patch("sys.stdout", new_callable=io.StringIO) as stdout,
        ):
            process, verified = ida_analyze_bin.verify_owned_mcp_with_single_recovery(
                original_process,
                "bin/14172/client/client.dll",
                "windows",
                "127.0.0.1",
                13337,
                "",
                False,
                recovery_budget=recovery_budget,
            )

        self.assertIs(restarted_process, process)
        self.assertTrue(verified)
        self.assertEqual(2, verify.call_count)
        self.assertNotIn("Failed:", stdout.getvalue())
        ensure.assert_called_once_with(
            original_process,
            "bin/14172/client/client.dll",
            "127.0.0.1",
            13337,
            "",
            False,
            recovery_budget=recovery_budget,
        )

    def test_reverifies_without_restart_when_health_check_recovers(self) -> None:
        process = object()
        recovery_budget = ida_analyze_bin.McpRecoveryBudget()

        with (
            patch.object(
                ida_analyze_bin,
                "verify_opened_binary_via_mcp",
                side_effect=[McpDatabaseUnavailableError("inactive or unreachable"), True],
            ) as verify,
            patch.object(
                ida_analyze_bin,
                "ensure_mcp_available",
                return_value=(process, True),
            ) as ensure,
        ):
            recovered_process, verified = ida_analyze_bin.verify_owned_mcp_with_single_recovery(
                process,
                "bin/14172/client/client.dll",
                "windows",
                "127.0.0.1",
                13337,
                "",
                False,
                recovery_budget=recovery_budget,
            )

        self.assertIs(process, recovered_process)
        self.assertTrue(verified)
        self.assertEqual(2, verify.call_count)
        ensure.assert_called_once()
        self.assertEqual(1, recovery_budget.remaining_restarts)

    def test_stops_after_one_unsuccessful_restart(self) -> None:
        original_process = object()
        restarted_process = object()
        recovery_budget = ida_analyze_bin.McpRecoveryBudget()

        with (
            patch.object(
                ida_analyze_bin,
                "verify_opened_binary_via_mcp",
                side_effect=McpDatabaseUnavailableError("inactive or unreachable"),
            ) as verify,
            patch.object(
                ida_analyze_bin,
                "ensure_mcp_available",
                return_value=(restarted_process, True),
            ) as ensure,
        ):
            process, verified = ida_analyze_bin.verify_owned_mcp_with_single_recovery(
                original_process,
                "bin/14172/client/client.dll",
                "windows",
                "127.0.0.1",
                13337,
                "",
                False,
                recovery_budget=recovery_budget,
            )

        self.assertIs(restarted_process, process)
        self.assertFalse(verified)
        self.assertEqual(2, verify.call_count)
        ensure.assert_called_once()


class TestEnsureMcpAvailableRecoveryBudget(unittest.TestCase):
    def test_only_one_restart_is_allowed_for_the_binary_lifecycle(self) -> None:
        original_process = MagicMock()
        original_process.poll.return_value = None
        restarted_process = MagicMock()
        restarted_process.poll.return_value = None
        recovery_budget = ida_analyze_bin.McpRecoveryBudget()

        with (
            patch.object(ida_analyze_bin, "check_mcp_worker_health", new=AsyncMock(return_value=False)),
            patch.object(ida_analyze_bin, "is_port_in_use", return_value=False) as port_in_use,
            patch.object(ida_analyze_bin, "quit_ida_gracefully") as quit_ida,
            patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=restarted_process) as start_ida,
        ):
            process, ok = ida_analyze_bin.ensure_mcp_available(
                original_process,
                "bin/14172/client/client.dll",
                "127.0.0.1",
                13337,
                "",
                False,
                recovery_budget=recovery_budget,
            )
            second_process, second_ok = ida_analyze_bin.ensure_mcp_available(
                process,
                "bin/14172/client/client.dll",
                "127.0.0.1",
                13337,
                "",
                False,
                recovery_budget=recovery_budget,
            )

        self.assertIs(restarted_process, process)
        self.assertTrue(ok)
        self.assertIs(restarted_process, second_process)
        self.assertFalse(second_ok)
        self.assertEqual(0, recovery_budget.remaining_restarts)
        port_in_use.assert_called_once_with("127.0.0.1", 13337)
        quit_ida.assert_called_once()
        start_ida.assert_called_once()

    def test_waits_for_a_lingering_launcher_port_before_restart(self) -> None:
        exited_process = MagicMock()
        exited_process.poll.return_value = 1
        exited_process.returncode = 1
        restarted_process = MagicMock()
        recovery_budget = ida_analyze_bin.McpRecoveryBudget()

        with (
            patch.object(ida_analyze_bin, "is_port_in_use", return_value=True),
            patch.object(ida_analyze_bin, "wait_for_port_release", return_value=True) as wait_for_release,
            patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=restarted_process) as start_ida,
        ):
            process, ok = ida_analyze_bin.ensure_mcp_available(
                exited_process,
                "bin/14172/client/client.dll",
                "127.0.0.1",
                13337,
                "",
                False,
                recovery_budget=recovery_budget,
            )

        self.assertIs(restarted_process, process)
        self.assertTrue(ok)
        self.assertEqual(0, recovery_budget.remaining_restarts)
        wait_for_release.assert_called_once_with("127.0.0.1", 13337)
        start_ida.assert_called_once()

    def test_aborts_restart_when_the_launcher_port_never_releases(self) -> None:
        exited_process = MagicMock()
        exited_process.poll.return_value = 1
        exited_process.returncode = 1
        recovery_budget = ida_analyze_bin.McpRecoveryBudget()

        with (
            patch.object(ida_analyze_bin, "is_port_in_use", return_value=True),
            patch.object(ida_analyze_bin, "wait_for_port_release", return_value=False),
            patch.object(ida_analyze_bin, "start_idalib_mcp") as start_ida,
        ):
            process, ok = ida_analyze_bin.ensure_mcp_available(
                exited_process,
                "bin/14172/client/client.dll",
                "127.0.0.1",
                13337,
                "",
                False,
                recovery_budget=recovery_budget,
            )

        self.assertIsNone(process)
        self.assertFalse(ok)
        self.assertEqual(0, recovery_budget.remaining_restarts)
        start_ida.assert_not_called()


class TestOpenedBinaryIdentityValidationHashes(unittest.TestCase):
    def test_accepts_ida_database_suffix_for_expected_binary_path(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "bin" / "14141" / "server" / "libserver.so"
            binary_path.parent.mkdir(parents=True, exist_ok=True)
            binary_path.write_bytes(b"server-binary")

            ok, reasons = ida_analyze_bin.validate_opened_binary_identity(
                str(binary_path),
                "linux",
                {"metadata": {"path": f"{binary_path}.i64", "base_address": "0x0"}},
            )

        self.assertTrue(ok, reasons)
        self.assertEqual([], reasons)

    def test_rejects_wrong_opened_module_path(self) -> None:
        with TemporaryDirectory() as temp_dir:
            expected_path = Path(temp_dir) / "bin" / "14141" / "server" / "libserver.so"
            opened_path = Path(temp_dir) / "bin" / "14141" / "engine" / "libengine2.so.i64"
            expected_path.parent.mkdir(parents=True, exist_ok=True)
            opened_path.parent.mkdir(parents=True, exist_ok=True)
            expected_path.write_bytes(b"server-binary")

            ok, reasons = ida_analyze_bin.validate_opened_binary_identity(
                str(expected_path),
                "linux",
                {"metadata": {"path": str(opened_path), "base_address": "0x0"}},
            )

        self.assertFalse(ok)
        self.assertTrue(any("path mismatch" in reason for reason in reasons), reasons)

    def test_accepts_moved_idb_when_sha256_matches(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "bin" / "14141" / "server" / "server.dll"
            binary_path.parent.mkdir(parents=True, exist_ok=True)
            binary_path.write_bytes(b"same-binary")

            ok, reasons = ida_analyze_bin.validate_opened_binary_identity(
                str(binary_path),
                "windows",
                {
                    "metadata": {
                        "path": "D:/moved/server.dll.i64",
                        "sha256": "a1f82722bc8e33aa9100d16001377c07366a779a2c42bc58fdeba9cf8fa9f1fd",
                        "base_address": "0x180000000",
                    }
                },
            )

        self.assertTrue(ok, reasons)

    def test_rejects_moved_idb_when_sha256_mismatches(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "bin" / "14141" / "server" / "server.dll"
            binary_path.parent.mkdir(parents=True, exist_ok=True)
            binary_path.write_bytes(b"same-binary")

            ok, reasons = ida_analyze_bin.validate_opened_binary_identity(
                str(binary_path),
                "windows",
                {
                    "metadata": {
                        "path": "D:/moved/server.dll.i64",
                        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                        "base_address": "0x180000000",
                    }
                },
            )

        self.assertFalse(ok)
        self.assertTrue(any("sha256 mismatch" in reason for reason in reasons), reasons)

    def test_rejects_linux_target_with_pe_style_base_address(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "bin" / "14141" / "server" / "libserver.so"
            binary_path.parent.mkdir(parents=True, exist_ok=True)
            binary_path.write_bytes(b"server-binary")

            ok, reasons = ida_analyze_bin.validate_opened_binary_identity(
                str(binary_path),
                "linux",
                {"metadata": {"path": f"{binary_path}.i64", "base_address": "0x180000000"}},
            )

        self.assertFalse(ok)
        self.assertTrue(any("PE-style base_address" in reason for reason in reasons), reasons)


class TestResolveArtifactPath(unittest.TestCase):
    def test_resolve_artifact_path_keeps_current_module_artifacts_local(self) -> None:
        binary_dir = str(Path("/tmp/bin/14141/networksystem"))

        resolved = ida_analyze_bin.resolve_artifact_path(
            binary_dir,
            "CNetChan_vtable.{platform}.yaml",
            "linux",
        )

        self.assertEqual(
            str(Path("/tmp/bin/14141/networksystem/CNetChan_vtable.linux.yaml").resolve()),
            resolved,
        )

    def test_resolve_artifact_path_supports_sibling_module_reference(self) -> None:
        binary_dir = str(Path("/tmp/bin/14141/networksystem"))

        resolved = ida_analyze_bin.resolve_artifact_path(
            binary_dir,
            "../server/CFlattenedSerializers_CreateFieldChangedEventQueue.{platform}.yaml",
            "windows",
        )

        self.assertEqual(
            str(
                Path("/tmp/bin/14141/server/CFlattenedSerializers_CreateFieldChangedEventQueue.windows.yaml").resolve()
            ),
            resolved,
        )

    def test_resolve_artifact_path_rejects_escape_outside_gamever_root(self) -> None:
        binary_dir = str(Path("/tmp/bin/14141/networksystem"))

        with self.assertRaises(ValueError):
            ida_analyze_bin.resolve_artifact_path(
                binary_dir,
                "../../outside/secret.{platform}.yaml",
                "windows",
            )


class TestResolveArtifactPathIntegration(unittest.TestCase):
    def test_expand_expected_paths_delegates_to_resolver(self) -> None:
        binary_dir = str(Path("/tmp/bin/14141/networksystem"))
        expected_paths = [
            "CNetChan_vtable.{platform}.yaml",
            "../server/CFlattenedSerializers_CreateFieldChangedEventQueue.{platform}.yaml",
        ]

        with patch.object(
            ida_analyze_bin,
            "resolve_artifact_path",
            side_effect=["/tmp/resolved-a.yaml", "/tmp/resolved-b.yaml"],
        ) as mock_resolver:
            resolved = ida_analyze_bin.expand_expected_paths(binary_dir, expected_paths, "linux")

        self.assertEqual(["/tmp/resolved-a.yaml", "/tmp/resolved-b.yaml"], resolved)
        mock_resolver.assert_has_calls(
            [
                call(binary_dir, expected_paths[0], "linux"),
                call(binary_dir, expected_paths[1], "linux"),
            ]
        )

    def test_expand_skill_output_paths_includes_platform_expected_outputs(self) -> None:
        binary_dir = str(Path("/tmp/bin/14141/engine"))
        skill = {
            "expected_output": ["Common.{platform}.yaml"],
            "expected_output_windows": ["WindowsOnly.{platform}.yaml"],
            "expected_output_linux": ["LinuxOnly.{platform}.yaml"],
            "optional_output": ["Optional.{platform}.yaml"],
        }

        required, optional, preprocess = ida_analyze_bin.expand_skill_output_paths(
            binary_dir,
            skill,
            "windows",
        )

        self.assertEqual(
            [
                str(Path("/tmp/bin/14141/engine/Common.windows.yaml").resolve()),
                str(Path("/tmp/bin/14141/engine/WindowsOnly.windows.yaml").resolve()),
            ],
            required,
        )
        self.assertEqual(
            [str(Path("/tmp/bin/14141/engine/Optional.windows.yaml").resolve())],
            optional,
        )
        self.assertEqual(required + optional, preprocess)


class TestParseConfig(unittest.TestCase):
    def test_parse_config_document_reuses_an_already_loaded_document(self) -> None:
        document = {
            "modules": [
                {
                    "name": "server",
                    "path_windows": "server.dll",
                    "path_linux": "libserver.so",
                    "skills": [],
                }
            ]
        }

        with patch.object(ida_analyze_bin, "_load_config_document") as load_document:
            modules = ida_analyze_bin.parse_config("unused.yaml", config_document=document)

        self.assertEqual("server", modules[0]["name"])
        load_document.assert_not_called()

    def test_parse_config_reads_optional_module_and_skill_descriptions(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                """
modules:
  - name: engine
    description: |
      Engine analysis stage.
      Runs before client.
    skills:
      - name: find-target
        description: "  Locate the target function.  "
      - name: find-empty
        description: "   "
      - name: find-null
        description: null
""".strip()
                + "\n",
                encoding="utf-8",
            )

            modules = ida_analyze_bin.parse_config(str(config_path))

        self.assertEqual("Engine analysis stage.\nRuns before client.", modules[0]["description"])
        self.assertEqual("Locate the target function.", modules[0]["skills"][0]["description"])
        self.assertIsNone(modules[0]["skills"][1]["description"])
        self.assertIsNone(modules[0]["skills"][2]["description"])

    def test_parse_config_rejects_non_string_descriptions_with_context(self) -> None:
        cases = (
            ("description: 42", "module 'engine'"),
            ("skills:\n      - name: find-target\n        description: [invalid]", "skill 'find-target'"),
        )
        for fragment, context in cases:
            with self.subTest(context=context), TemporaryDirectory() as temp_dir:
                config_path = Path(temp_dir) / "config.yaml"
                config_path.write_text(
                    f"modules:\n  - name: engine\n    {fragment}\n",
                    encoding="utf-8",
                )

                with self.assertRaisesRegex(ValueError, rf"Invalid description for {context}"):
                    ida_analyze_bin.parse_config(str(config_path))

    def test_parse_config_records_stable_stage_indexes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                "modules:\n  - name: engine\n  - name: client\n  - name: engine\n",
                encoding="utf-8",
            )

            modules = ida_analyze_bin.parse_config(str(config_path))

        self.assertEqual([0, 1, 2], [module["stage_index"] for module in modules])
        self.assertEqual(["engine", "client", "engine"], [module["name"] for module in modules])

    def test_parse_config_does_not_expose_legacy_vcall_finder_registration(self) -> None:
        modules = ida_analyze_bin.parse_config_document(
            {
                "modules": [
                    {
                        "name": "server",
                        "vcall_finder": ["g_pNetworkMessages"],
                    }
                ]
            }
        )

        self.assertNotIn("vcall_finder_objects", modules[0])

    def test_parse_config_reads_skip_if_exists(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                """
modules:
  - name: engine
    path_windows: game/bin/win64/engine2.dll
    path_linux: game/bin/linuxsteamrt64/libengine2.so
    skills:
      - name: find-CEngineServiceMgr_DeactivateLoop
        expected_output:
          - CEngineServiceMgr_DeactivateLoop.{platform}.yaml
        expected_input:
          - CEngineServiceMgr__MainLoop.{platform}.yaml
        skip_if_exists:
          - CLoopTypeBase_DeallocateLoopMode.{platform}.yaml
""".strip()
                + "\n",
                encoding="utf-8",
            )

            modules = ida_analyze_bin.parse_config(str(config_path))

        self.assertEqual(
            ["CLoopTypeBase_DeallocateLoopMode.{platform}.yaml"],
            modules[0]["skills"][0]["skip_if_exists"],
        )

    def test_parse_config_defaults_skip_if_exists_to_empty_list(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                """
modules:
  - name: engine
    path_windows: game/bin/win64/engine2.dll
    path_linux: game/bin/linuxsteamrt64/libengine2.so
    skills:
      - name: find-CEngineServiceMgr_DeactivateLoop
        expected_output:
          - CEngineServiceMgr_DeactivateLoop.{platform}.yaml
        expected_input:
          - CEngineServiceMgr__MainLoop.{platform}.yaml
""".strip()
                + "\n",
                encoding="utf-8",
            )

            modules = ida_analyze_bin.parse_config(str(config_path))

        self.assertEqual(
            [],
            modules[0]["skills"][0]["skip_if_exists"],
        )

    def test_parse_config_reads_optional_output(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                """
modules:
  - name: engine
    path_windows: game/bin/win64/engine2.dll
    path_linux: game/bin/linuxsteamrt64/libengine2.so
    skills:
      - name: find-CEngineServiceMgr_DeactivateLoop
        optional_output:
          - CEngineServiceMgr_DeactivateLoop.{platform}.yaml
        expected_input:
          - CEngineServiceMgr__MainLoop.{platform}.yaml
""".strip()
                + "\n",
                encoding="utf-8",
            )

            modules = ida_analyze_bin.parse_config(str(config_path))

        self.assertEqual(
            ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
            modules[0]["skills"][0]["optional_output"],
        )

    def test_parse_config_reads_optional_inputs(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                """
modules:
  - name: engine
    skills:
      - name: find-consumer
        optional_input:
          - Optional.{platform}.yaml
        optional_input_windows:
          - WindowsOptional.{platform}.yaml
        optional_input_linux:
          - LinuxOptional.{platform}.yaml
""".strip()
                + "\n",
                encoding="utf-8",
            )

            skill = ida_analyze_bin.parse_config(str(config_path))[0]["skills"][0]

        self.assertEqual(["Optional.{platform}.yaml"], skill["optional_input"])
        self.assertEqual(["WindowsOptional.{platform}.yaml"], skill["optional_input_windows"])
        self.assertEqual(["LinuxOptional.{platform}.yaml"], skill["optional_input_linux"])

    def test_parse_config_reads_platform_expected_outputs(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                """
modules:
  - name: engine
    path_windows: game/bin/win64/engine2.dll
    path_linux: game/bin/linuxsteamrt64/libengine2.so
    skills:
      - name: find-g_pInterfaceGlobals_ppGlobal
        expected_output:
          - Common.{platform}.yaml
        expected_output_windows:
          - WindowsOnly.{platform}.yaml
        expected_output_linux:
          - LinuxOnly.{platform}.yaml
""".strip()
                + "\n",
                encoding="utf-8",
            )

            modules = ida_analyze_bin.parse_config(str(config_path))

        skill = modules[0]["skills"][0]
        self.assertEqual(["Common.{platform}.yaml"], skill["expected_output"])
        self.assertEqual(
            ["WindowsOnly.{platform}.yaml"],
            skill["expected_output_windows"],
        )
        self.assertEqual(
            ["LinuxOnly.{platform}.yaml"],
            skill["expected_output_linux"],
        )

    def test_parse_config_defaults_optional_output_to_empty_list(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                """
modules:
  - name: engine
    path_windows: game/bin/win64/engine2.dll
    path_linux: game/bin/linuxsteamrt64/libengine2.so
    skills:
      - name: find-CEngineServiceMgr_DeactivateLoop
        expected_input:
          - CEngineServiceMgr__MainLoop.{platform}.yaml
""".strip()
                + "\n",
                encoding="utf-8",
            )

            modules = ida_analyze_bin.parse_config(str(config_path))

        self.assertEqual([], modules[0]["skills"][0]["optional_output"])
        self.assertEqual([], modules[0]["skills"][0]["expected_output_windows"])
        self.assertEqual([], modules[0]["skills"][0]["expected_output_linux"])


class TestIsMajorUpdateGamever(unittest.TestCase):
    _DOWNLOAD_YAML = (
        """
downloads:
  - tag: "14167"
    name: 1.41.6.7
    manifests:
      "2347771": "8344780363095656278"
  - tag: "14168"
    name: 1.41.6.8
    manifests:
      "2347771": "1966178532936074640"
    major_update: true
  - tag: "14169"
    name: 1.41.6.9
    manifests:
      "2347771": "1966178532936074641"
    major_update: false
""".strip()
        + "\n"
    )

    def _write_download_yaml(self, temp_dir):
        download_path = Path(temp_dir) / "download.yaml"
        download_path.write_text(self._DOWNLOAD_YAML, encoding="utf-8")
        return download_path

    def test_flags_major_update_version(self) -> None:
        with TemporaryDirectory() as temp_dir:
            download_path = self._write_download_yaml(temp_dir)
            self.assertTrue(ida_analyze_bin._is_major_update_gamever("14168", str(download_path)))

    def test_ignores_unflagged_version(self) -> None:
        with TemporaryDirectory() as temp_dir:
            download_path = self._write_download_yaml(temp_dir)
            self.assertFalse(ida_analyze_bin._is_major_update_gamever("14167", str(download_path)))

    def test_ignores_explicit_false_flag(self) -> None:
        with TemporaryDirectory() as temp_dir:
            download_path = self._write_download_yaml(temp_dir)
            self.assertFalse(ida_analyze_bin._is_major_update_gamever("14169", str(download_path)))

    def test_returns_false_for_unknown_tag(self) -> None:
        with TemporaryDirectory() as temp_dir:
            download_path = self._write_download_yaml(temp_dir)
            self.assertFalse(ida_analyze_bin._is_major_update_gamever("99999", str(download_path)))

    def test_returns_false_for_missing_file(self) -> None:
        with TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "does_not_exist.yaml"
            self.assertFalse(ida_analyze_bin._is_major_update_gamever("14168", str(missing_path)))

    def test_returns_false_for_empty_gamever(self) -> None:
        with TemporaryDirectory() as temp_dir:
            download_path = self._write_download_yaml(temp_dir)
            self.assertFalse(ida_analyze_bin._is_major_update_gamever("", str(download_path)))


class TestSkillOrdering(unittest.TestCase):
    def test_build_skill_graph_matches_topological_sort_order(self) -> None:
        skills = [
            {"name": "consumer", "expected_input": ["Shared.{platform}.yaml"]},
            {"name": "producer", "expected_output": ["Shared.{platform}.yaml"]},
            {"name": "independent"},
        ]

        graph = ida_analyze_bin.build_skill_graph(skills)

        self.assertEqual(ida_analyze_bin.topological_sort_skills(skills), graph.order)

    def test_build_skill_graph_preserves_multiple_artifact_parents(self) -> None:
        skills = [
            {"name": "producer-a", "expected_output": ["A.{platform}.yaml"]},
            {"name": "producer-b", "expected_output": ["B.{platform}.yaml"]},
            {
                "name": "consumer",
                "expected_input": ["A.{platform}.yaml", "B.{platform}.yaml"],
            },
        ]

        graph = ida_analyze_bin.build_skill_graph(skills)

        artifact_edges = {
            (edge.source, edge.target, edge.artifact) for edge in graph.edges if edge.edge_type == EdgeType.ARTIFACT
        }
        self.assertEqual(
            {
                ("producer-a", "consumer", "A.{platform}.yaml"),
                ("producer-b", "consumer", "B.{platform}.yaml"),
            },
            artifact_edges,
        )
        self.assertEqual(1, graph.layers["consumer"])

    def test_build_skill_graph_includes_platform_specific_dependencies(self) -> None:
        skills = [
            {"name": "windows-producer", "expected_output_windows": ["Windows.windows.yaml"]},
            {"name": "linux-producer", "expected_output_linux": ["Linux.linux.yaml"]},
            {
                "name": "consumer",
                "expected_input_windows": ["Windows.windows.yaml"],
                "expected_input_linux": ["Linux.linux.yaml"],
            },
        ]

        graph = ida_analyze_bin.build_skill_graph(skills)

        self.assertEqual(
            {("windows-producer", "consumer"), ("linux-producer", "consumer")},
            {(edge.source, edge.target) for edge in graph.edges if edge.edge_type == EdgeType.ARTIFACT},
        )

    def test_build_skill_graph_keeps_prerequisite_edge_type(self) -> None:
        graph = ida_analyze_bin.build_skill_graph(
            [
                {"name": "producer"},
                {"name": "consumer", "prerequisite": ["producer"]},
            ]
        )

        self.assertIn(
            ("producer", "consumer", EdgeType.PREREQUISITE),
            {(edge.source, edge.target, edge.edge_type) for edge in graph.edges},
        )

    def test_build_skill_graph_records_cycles_and_fallback_order(self) -> None:
        skills = [
            {"name": "second", "prerequisite": ["first"]},
            {"name": "first", "prerequisite": ["second"]},
        ]

        graph = ida_analyze_bin.build_skill_graph(skills)

        self.assertEqual(["second", "first"], graph.order)
        self.assertEqual([["first", "second"]], graph.cycles)
        self.assertEqual(1, len(graph.warnings))

    def test_topological_sort_rejects_required_input_cycle(self) -> None:
        skills = [
            {
                "name": "first",
                "expected_output": ["First.{platform}.yaml"],
                "expected_input": ["Second.{platform}.yaml"],
            },
            {
                "name": "second",
                "expected_output": ["Second.{platform}.yaml"],
                "expected_input": ["First.{platform}.yaml"],
            },
        ]

        with self.assertRaisesRegex(ValueError, "Artifact dependency cycle"):
            ida_analyze_bin.topological_sort_skills(skills)

    def test_topological_sort_rejects_optional_input_cycle(self) -> None:
        skills = [
            {
                "name": "first",
                "optional_output": ["First.{platform}.yaml"],
                "optional_input": ["Second.{platform}.yaml"],
            },
            {
                "name": "second",
                "optional_output": ["Second.{platform}.yaml"],
                "optional_input": ["First.{platform}.yaml"],
            },
        ]

        with self.assertRaisesRegex(ValueError, "Artifact dependency cycle"):
            ida_analyze_bin.topological_sort_skills(skills)

    def test_topological_sort_rejects_self_dependency(self) -> None:
        skills = [
            {
                "name": "self-dependent",
                "expected_output": ["Self.{platform}.yaml"],
                "expected_input": ["Self.{platform}.yaml"],
            }
        ]

        with self.assertRaisesRegex(ValueError, "Artifact dependency cycle"):
            ida_analyze_bin.topological_sort_skills(skills)

    def test_topological_sort_skills_keeps_ilooptype_after_deactivateloop(
        self,
    ) -> None:
        skills = [
            {
                "name": "find-CLoopTypeBase_DeallocateLoopMode",
                "expected_output": ["CLoopTypeBase_DeallocateLoopMode.{platform}.yaml"],
                "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                "prerequisite": ["find-CEngineServiceMgr_DeactivateLoop"],
            },
            {
                "name": "find-CEngineServiceMgr_DeactivateLoop",
                "expected_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                "skip_if_exists": ["CLoopTypeBase_DeallocateLoopMode.{platform}.yaml"],
            },
            {
                "name": "find-CEngineServiceMgr__MainLoop",
                "expected_output": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
            },
        ]

        ordered = ida_analyze_bin.topological_sort_skills(skills)

        self.assertLess(
            ordered.index("find-CEngineServiceMgr_DeactivateLoop"),
            ordered.index("find-CLoopTypeBase_DeallocateLoopMode"),
        )

    def test_topological_sort_skills_orders_optional_producer_before_consumer(self) -> None:
        skills = [
            {
                "name": "consumer",
                "expected_output": ["Consumer.{platform}.yaml"],
                "optional_input": ["OptionalOnly.{platform}.yaml"],
            },
            {
                "name": "optional_producer",
                "optional_output": ["OptionalOnly.{platform}.yaml"],
            },
        ]

        ordered = ida_analyze_bin.topological_sort_skills(skills)

        self.assertEqual(["optional_producer", "consumer"], ordered)
        graph = ida_analyze_bin.build_skill_graph(skills)
        self.assertIn(
            ("optional_producer", "consumer", EdgeType.OPTIONAL_INPUT),
            {(edge.source, edge.target, edge.edge_type) for edge in graph.edges},
        )


class TestExecutionPlan(unittest.TestCase):
    def test_execution_plan_carries_descriptions_without_changing_dependencies(self) -> None:
        base_module = {
            "stage_index": 2,
            "name": "engine",
            "path_windows": "game/bin/win64/engine2.dll",
            "skills": [
                {"name": "producer", "expected_output": ["Shared.{platform}.yaml"]},
                {"name": "consumer", "expected_input": ["Shared.{platform}.yaml"]},
            ],
        }
        described_module = {
            **base_module,
            "description": "Engine stage",
            "skills": [
                {**base_module["skills"][0], "description": "Produces the shared artifact"},
                {**base_module["skills"][1], "description": "Consumes the shared artifact"},
            ],
        }

        plain = ida_analyze_bin.build_execution_plan(
            [base_module], platforms=["windows"], bin_dir="bin", gamever="14141"
        )
        described = ida_analyze_bin.build_execution_plan(
            [described_module], platforms=["windows"], bin_dir="bin", gamever="14141"
        )

        self.assertEqual("Engine stage", described.stages[0].description)
        self.assertEqual(
            ["Produces the shared artifact", "Consumes the shared artifact"],
            [node.description for node in described.nodes],
        )
        self.assertNotIn("description", described.nodes[0].data)
        self.assertEqual(
            [(edge.source, edge.target, edge.edge_type) for edge in plain.edges],
            [(edge.source, edge.target, edge.edge_type) for edge in described.edges],
        )
        self.assertEqual([node.name for node in plain.nodes], [node.name for node in described.nodes])

    def test_duplicate_module_names_get_distinct_stable_stage_ids(self) -> None:
        modules = [
            {
                "stage_index": 5,
                "name": "engine",
                "path_windows": "game/bin/win64/engine2.dll",
                "skills": [{"name": "producer", "expected_output": ["Shared.{platform}.yaml"]}],
            },
            {
                "stage_index": 8,
                "name": "engine",
                "path_windows": "game/bin/win64/engine2.dll",
                "skills": [{"name": "consumer", "expected_input": ["Shared.{platform}.yaml"]}],
            },
        ]

        plan = ida_analyze_bin.build_execution_plan(
            modules,
            platforms=["windows"],
            bin_dir="bin",
            gamever="14141",
        )

        self.assertEqual(
            ["stage-0005-engine", "stage-0008-engine"],
            [stage.id for stage in plan.stages],
        )
        self.assertEqual(
            ["stage-0005-engine-windows", "stage-0008-engine-windows"],
            [job.id for job in plan.jobs],
        )

    def test_cross_stage_artifact_edges_use_resolved_full_paths(self) -> None:
        modules = [
            {
                "stage_index": 1,
                "name": "client",
                "path_windows": "game/csgo/bin/win64/client.dll",
                "skills": [{"name": "producer", "expected_output": ["Shared.{platform}.yaml"]}],
            },
            {
                "stage_index": 2,
                "name": "server",
                "path_windows": "game/csgo/bin/win64/server.dll",
                "skills": [
                    {
                        "name": "consumer",
                        "expected_input": ["../client/Shared.{platform}.yaml"],
                    }
                ],
            },
        ]

        plan = ida_analyze_bin.build_execution_plan(
            modules,
            platforms=["windows"],
            bin_dir="bin",
            gamever="14141",
        )

        edge = next(edge for edge in plan.edges if edge.edge_type == EdgeType.CROSS_STAGE_ARTIFACT)
        self.assertEqual("stage-0001-client-windows/producer", edge.source)
        self.assertEqual("stage-0002-server-windows/consumer", edge.target)
        self.assertTrue(edge.artifact.endswith("client\\Shared.windows.yaml"))

    def test_execution_plan_contains_skill_vcall_and_post_process_nodes(self) -> None:
        modules = [
            {
                "name": "engine",
                "path_windows": "game/bin/win64/engine2.dll",
                "skills": [{"name": "find-target"}],
            }
        ]

        plan = ida_analyze_bin.build_execution_plan(
            modules,
            platforms=["windows"],
            bin_dir="bin",
            gamever="14141",
            vcall_finder_selector={"names": ["g_pTarget"]},
            include_post_process=True,
        )

        self.assertEqual(
            [PlanNodeType.SKILL, PlanNodeType.VCALL_TARGET, PlanNodeType.POST_PROCESS],
            [node.node_type for node in plan.nodes],
        )
        self.assertEqual(
            [
                "stage-0000-engine-windows/find-target",
                "stage-0000-engine-windows/vcall/g_pTarget",
                "stage-0000-engine-windows/post-process",
            ],
            [node.id for node in plan.nodes],
        )

    def test_execution_plan_omits_disabled_post_process_node(self) -> None:
        plan = ida_analyze_bin.build_execution_plan(
            [
                {
                    "name": "engine",
                    "path_windows": "game/bin/win64/engine2.dll",
                    "skills": [{"name": "find-target"}],
                }
            ],
            platforms=["windows"],
            bin_dir="bin",
            gamever="14141",
        )

        self.assertEqual([PlanNodeType.SKILL], [node.node_type for node in plan.nodes])


class TestConfigSkillDependencyGraph(unittest.TestCase):
    def test_finds_expected_input_produced_by_later_module(self) -> None:
        modules = [
            {
                "name": "client",
                "skills": [
                    {
                        "name": "consumer",
                        "expected_input": ["../engine/Late.{platform}.yaml"],
                    },
                ],
            },
            {
                "name": "engine",
                "skills": [
                    {
                        "name": "producer",
                        "expected_output": ["Late.{platform}.yaml"],
                    },
                ],
            },
        ]

        gaps = ida_analyze_bin.find_module_skill_dependency_gaps(modules, "windows")

        self.assertEqual(
            ["windows module[0] client/consumer missing: _artifacts/engine/Late.windows.yaml"],
            gaps,
        )
        with self.assertRaisesRegex(ValueError, "client/consumer missing"):
            ida_analyze_bin.validate_module_skill_dependencies(modules)


class TestSkillSelection(unittest.TestCase):
    def test_select_skills_by_name_uses_exact_match(self) -> None:
        skills = [{"name": "find-target"}, {"name": "find-target-extra"}]

        selected = ida_analyze_bin._select_skills_by_name(skills, "find-target")

        self.assertEqual([{"name": "find-target"}], selected)

    def test_select_modules_by_skill_keeps_all_exact_matches(self) -> None:
        modules = [
            {"name": "client", "skills": [{"name": "find-target"}, {"name": "find-client-only"}]},
            {"name": "server", "skills": [{"name": "find-target"}, {"name": "find-server-only"}]},
        ]

        selected = ida_analyze_bin._select_modules_by_skill(modules, "find-target")

        self.assertEqual(["client", "server"], [module["name"] for module in selected])
        self.assertEqual([[{"name": "find-target"}], [{"name": "find-target"}]], [m["skills"] for m in selected])

    def test_select_modules_by_skill_respects_module_filter(self) -> None:
        modules = [
            {"name": "client", "skills": [{"name": "find-client-only"}]},
            {"name": "server", "skills": [{"name": "find-server-only"}]},
        ]

        with self.assertRaisesRegex(ValueError, "find-client-only"):
            ida_analyze_bin._select_modules_by_skill(modules, "missing", ["client"])


class TestPostProcessActionCollection(unittest.TestCase):
    def test_collect_post_process_yaml_mappings_skips_missing_invalid_and_duplicates(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            valid_path = binary_dir / "Valid.windows.yaml"
            invalid_path = binary_dir / "Invalid.windows.yaml"
            scalar_path = binary_dir / "Scalar.windows.yaml"
            valid_path.write_text("func_name: Valid\nfunc_va: '0x180100000'\n", encoding="utf-8")
            invalid_path.write_text("func_name: [\n", encoding="utf-8")
            scalar_path.write_text("- item\n", encoding="utf-8")

            result = ida_analyze_bin._collect_post_process_yaml_mappings(
                str(binary_dir),
                ["skill-a", "skill-b"],
                {
                    "skill-a": {
                        "name": "skill-a",
                        "expected_output": [
                            "Valid.{platform}.yaml",
                            "Missing.{platform}.yaml",
                            "Invalid.{platform}.yaml",
                            "Scalar.{platform}.yaml",
                        ],
                    },
                    "skill-b": {
                        "name": "skill-b",
                        "expected_output": ["Valid.{platform}.yaml"],
                    },
                },
                "windows",
                debug=False,
            )

        expected_path = ida_analyze_bin._absolute_path_preserve_spelling(valid_path)
        self.assertEqual(
            [(expected_path, {"func_name": "Valid", "func_va": "0x180100000"})],
            result,
        )

    def test_collect_post_process_yaml_mappings_skips_paths_outside_current_binary_dir(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            gamever_dir = Path(temp_dir) / "bin" / "14141"
            binary_dir = gamever_dir / "server"
            sibling_dir = gamever_dir / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            sibling_dir.mkdir(parents=True, exist_ok=True)
            (sibling_dir / "CrossModule.windows.yaml").write_text(
                "func_name: CrossModule\nfunc_va: '0x180200000'\n",
                encoding="utf-8",
            )

            result = ida_analyze_bin._collect_post_process_yaml_mappings(
                str(binary_dir),
                ["skill-a"],
                {
                    "skill-a": {
                        "name": "skill-a",
                        "expected_output": ["../engine/CrossModule.{platform}.yaml"],
                    },
                },
                "windows",
                debug=False,
            )

        self.assertEqual([], result)

    def test_build_post_process_actions_supports_all_yaml_action_types(self) -> None:
        actions = ida_analyze_bin._build_post_process_actions_from_yaml(
            {
                "vtable_class": "CEntFireOutputAutoCompletionFunctor",
                "vtable_va": "0x1817617a8",
                "func_name": "CEntFireOutputAutoCompletionFunctor_FireOutput",
                "func_va": "0x180c165c0",
                "gv_name": "CCSGameRules__sm_mapGcBanInformation",
                "gv_va": "0x181eff6a8",
                "vfunc_offset": "0xb8",
                "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                "vfunc_sig_disp": 2,
                "struct_name": "CCheckTransmitInfo",
                "member_name": "m_nPlayerSlot",
                "offset": "0x240",
                "offset_sig": "8B 8F ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B F0",
                "offset_sig_disp": 0,
            },
            "fixture.yaml",
            debug=False,
        )

        self.assertEqual(
            [{"addr": "0x180c165c0", "name": "CEntFireOutputAutoCompletionFunctor_FireOutput"}],
            actions["func_renames"],
        )
        self.assertEqual(
            [
                {
                    "addr": "0x1817617a8",
                    "name": "CEntFireOutputAutoCompletionFunctor_vtable",
                    "kind": "vtable",
                },
                {
                    "addr": "0x181eff6a8",
                    "name": "CCSGameRules__sm_mapGcBanInformation",
                    "kind": "global",
                },
            ],
            actions["data_renames"],
        )
        self.assertEqual(
            [
                {
                    "pattern": "48 FF A0 B8 00 00 00 C3",
                    "disp": 2,
                    "comment": "0xB8 = 184LL = CEntFireOutputAutoCompletionFunctor_FireOutput",
                    "source_path": "fixture.yaml",
                    "kind": "vfunc_sig",
                },
                {
                    "pattern": "8B 8F ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B F0",
                    "disp": 0,
                    "comment": "0x240 = 576LL = CCheckTransmitInfo::m_nPlayerSlot",
                    "source_path": "fixture.yaml",
                    "kind": "offset_sig",
                },
            ],
            actions["sig_comments"],
        )

    def test_build_post_process_actions_skips_invalid_fields_without_blocking_valid_actions(
        self,
    ) -> None:
        actions = ida_analyze_bin._build_post_process_actions_from_yaml(
            {
                "func_name": "ValidFunction",
                "func_va": "0x180111000",
                "gv_name": "InvalidGlobal",
                "gv_va": "not-an-address",
                "vfunc_offset": "not-an-offset",
                "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
            },
            "invalid-fields.yaml",
            debug=False,
        )

        self.assertEqual(
            [{"addr": "0x180111000", "name": "ValidFunction"}],
            actions["func_renames"],
        )
        self.assertEqual([], actions["data_renames"])
        self.assertEqual([], actions["sig_comments"])

    def test_build_post_process_actions_skips_invalid_sig_disp_fields(self) -> None:
        actions = ida_analyze_bin._build_post_process_actions_from_yaml(
            {
                "func_name": "ValidFunction",
                "func_va": "0x180111000",
                "vfunc_offset": "0xb8",
                "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                "vfunc_sig_disp": None,
                "struct_name": "CCheckTransmitInfo",
                "member_name": "m_nPlayerSlot",
                "offset": "0x240",
                "offset_sig": "8B 8F ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B F0",
                "offset_sig_disp": None,
            },
            "invalid-disp.yaml",
            debug=False,
        )

        self.assertEqual(
            [{"addr": "0x180111000", "name": "ValidFunction"}],
            actions["func_renames"],
        )
        self.assertEqual([], actions["data_renames"])
        self.assertEqual([], actions["sig_comments"])


class TestPostProcessMcpExecution(unittest.IsolatedAsyncioTestCase):
    async def test_post_process_expected_outputs_via_session_executes_renames_and_comments(
        self,
    ) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(
            side_effect=[
                _tool_result(
                    [
                        {
                            "pattern": "48 FF A0 B8 00 00 00 C3",
                            "matches": ["0x180a32c60"],
                            "n": 1,
                        }
                    ]
                ),
                _tool_result({"items": [{"addr": "0x180a32c62", "ok": True}]}),
                _tool_result({"renamed": True}),
                _tool_result({"result": ""}),
            ]
        )

        ok = await ida_analyze_bin.post_process_expected_outputs_via_session(
            session,
            [
                (
                    "fixture.yaml",
                    {
                        "func_name": "CCSPlayer_ItemServices_DropActivePlayerWeapon",
                        "func_va": "0x180c165c0",
                        "vfunc_offset": "0xb8",
                        "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                        "vfunc_sig_disp": 2,
                        "gv_name": "CCSGameRules__sm_mapGcBanInformation",
                        "gv_va": "0x181eff6a8",
                    },
                )
            ],
            debug=False,
        )

        self.assertTrue(ok)
        self.assertEqual(
            [
                call(
                    name="find_bytes",
                    arguments={"patterns": ["48 FF A0 B8 00 00 00 C3"], "limit": 2},
                ),
                call(
                    name="set_comments",
                    arguments={
                        "items": [
                            {
                                "addr": "0x180a32c62",
                                "comment": "0xB8 = 184LL = CCSPlayer_ItemServices_DropActivePlayerWeapon",
                            }
                        ]
                    },
                ),
                call(
                    name="rename",
                    arguments={
                        "batch": {
                            "func": [
                                {
                                    "addr": "0x180c165c0",
                                    "name": "CCSPlayer_ItemServices_DropActivePlayerWeapon",
                                }
                            ]
                        }
                    },
                ),
                call(
                    name="py_eval",
                    arguments={
                        "code": (
                            "import idc\n"
                            "idc.set_name(6474954408, "
                            '"CCSGameRules__sm_mapGcBanInformation", idc.SN_NOWARN)\n'
                        )
                    },
                ),
            ],
            session.call_tool.await_args_list,
        )

    async def test_post_process_expected_outputs_via_session_skips_non_unique_signature_matches(
        self,
    ) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(
            side_effect=[
                _tool_result(
                    [
                        {
                            "pattern": "8B 8F ?? ?? ?? ??",
                            "matches": [],
                            "n": 0,
                        }
                    ]
                ),
                _tool_result(
                    [
                        {
                            "pattern": "48 FF A0 B8 00 00 00 C3",
                            "matches": ["0x1801", "0x1802"],
                            "n": 2,
                        }
                    ]
                ),
            ]
        )

        ok = await ida_analyze_bin.post_process_expected_outputs_via_session(
            session,
            [
                (
                    "fixture.yaml",
                    {
                        "struct_name": "CCheckTransmitInfo",
                        "member_name": "m_nPlayerSlot",
                        "offset": "0x240",
                        "offset_sig": "8B 8F ?? ?? ?? ??",
                        "func_name": "CCSPlayer_ItemServices_DropActivePlayerWeapon",
                        "vfunc_offset": "0xb8",
                        "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                    },
                )
            ],
            debug=False,
        )

        self.assertTrue(ok)
        self.assertEqual(2, session.call_tool.await_count)
        self.assertNotIn(
            "set_comments",
            [call_item.kwargs["name"] for call_item in session.call_tool.await_args_list],
        )

    async def test_post_process_expected_outputs_via_session_falls_back_to_py_eval_comments(
        self,
    ) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(
            side_effect=[
                _tool_result(
                    [
                        {
                            "pattern": "48 FF A0 B8 00 00 00 C3",
                            "matches": [6453142112],
                            "n": 1,
                        }
                    ]
                ),
                RuntimeError("Unknown tool: set_comments"),
                _tool_result({"result": ""}),
            ]
        )

        ok = await ida_analyze_bin.post_process_expected_outputs_via_session(
            session,
            [
                (
                    "fixture.yaml",
                    {
                        "func_name": "CCSPlayer_ItemServices_DropActivePlayerWeapon",
                        "vfunc_offset": "0xb8",
                        "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                    },
                )
            ],
            debug=False,
        )

        self.assertTrue(ok)
        self.assertEqual("py_eval", session.call_tool.await_args_list[-1].kwargs["name"])
        self.assertIn(
            'idc.set_cmt(6453142112, "0xB8 = 184LL = CCSPlayer_ItemServices_DropActivePlayerWeapon", 0)',
            session.call_tool.await_args_list[-1].kwargs["arguments"]["code"],
        )

    async def test_post_process_expected_outputs_via_session_ignores_set_comments_item_errors(
        self,
    ) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(
            side_effect=[
                _tool_result(
                    [
                        {
                            "pattern": "48 FF A0 B8 00 00 00 C3",
                            "matches": ["0x180a32c60"],
                            "n": 1,
                        }
                    ]
                ),
                _tool_result(
                    {
                        "items": [
                            {
                                "addr": "0x180a32c60",
                                "error": "Decompiler comment failed",
                            }
                        ]
                    }
                ),
                _tool_result({"renamed": True}),
            ]
        )

        ok = await ida_analyze_bin.post_process_expected_outputs_via_session(
            session,
            [
                (
                    "fixture.yaml",
                    {
                        "func_name": "CCSPlayer_ItemServices_DropActivePlayerWeapon",
                        "func_va": "0x180c165c0",
                        "vfunc_offset": "0xb8",
                        "vfunc_sig": "48 FF A0 B8 00 00 00 C3",
                    },
                )
            ],
            debug=True,
        )

        self.assertTrue(ok)
        self.assertEqual("rename", session.call_tool.await_args_list[-1].kwargs["name"])
        self.assertNotIn(
            "py_eval",
            [call_item.kwargs["name"] for call_item in session.call_tool.await_args_list],
        )

    async def test_post_process_func_renames_splits_large_batches(self) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(return_value=_tool_result({"func": []}))
        func_renames = [{"addr": f"0x{index:x}", "name": f"Func_{index}"} for index in range(101)]

        await ida_analyze_bin._post_process_func_renames(
            session,
            func_renames,
            debug=False,
        )

        self.assertEqual(3, session.call_tool.await_count)
        self.assertEqual(
            [50, 50, 1],
            [len(call_item.kwargs["arguments"]["batch"]["func"]) for call_item in session.call_tool.await_args_list],
        )

    async def test_post_process_func_renames_debug_logs_failed_batch_items(self) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(side_effect=RuntimeError("Invalid structured content returned by tool rename"))
        func_renames = [
            {"addr": "0x180001000", "name": "FirstFunc"},
            {"addr": "0x180002000", "name": "SecondFunc"},
        ]

        with patch("sys.stdout", new_callable=io.StringIO) as fake_stdout:
            await ida_analyze_bin._post_process_func_renames(
                session,
                func_renames,
                debug=True,
            )

        output = fake_stdout.getvalue()
        self.assertIn("Post-process: function rename total=2 batch_size=50", output)
        self.assertIn("Post-process: function rename batch 1/1 failed", output)
        self.assertIn("0x180001000 -> FirstFunc", output)
        self.assertIn("0x180002000 -> SecondFunc", output)


class TestStartIdalibMcp(unittest.TestCase):
    @patch.object(ida_analyze_bin, "wait_for_port", return_value=True)
    @patch("ida_analyze_bin.subprocess.Popen")
    def test_start_idalib_mcp_non_debug_discards_server_output(
        self,
        mock_popen,
        _mock_wait_for_port,
    ) -> None:
        fake_process = MagicMock()
        mock_popen.return_value = fake_process

        with patch.object(ida_analyze_bin, "is_port_in_use", return_value=False) as port_in_use:
            process = ida_analyze_bin.start_idalib_mcp(
                "bin/14160/client/client.dll",
                host="127.0.0.1",
                port=13337,
                debug=False,
            )

        self.assertIs(fake_process, process)
        port_in_use.assert_called_once_with("127.0.0.1", 13337)
        mock_popen.assert_called_once()
        args, kwargs = mock_popen.call_args
        self.assertEqual(
            [
                "idalib-mcp",
                "--unsafe",
                "--host",
                "127.0.0.1",
                "--port",
                "13337",
                "bin/14160/client/client.dll",
            ],
            args[0],
        )
        self.assertEqual(ida_analyze_bin.subprocess.DEVNULL, kwargs["stdout"])
        self.assertEqual(ida_analyze_bin.subprocess.DEVNULL, kwargs["stderr"])

    @patch.object(ida_analyze_bin, "is_port_in_use", return_value=True, create=True)
    @patch("ida_analyze_bin.subprocess.Popen")
    @patch.object(ida_analyze_bin, "wait_for_port", return_value=True)
    def test_start_idalib_mcp_refuses_an_in_use_port(
        self,
        _mock_wait_for_port,
        mock_popen,
        _is_port_in_use,
    ) -> None:
        process = ida_analyze_bin.start_idalib_mcp(
            "bin/14160/client/client.dll",
            host="127.0.0.1",
            port=13337,
            debug=False,
        )

        self.assertIsNone(process)
        mock_popen.assert_not_called()


class TestProcessBinary(unittest.TestCase):
    def setUp(self) -> None:
        verify_patcher = patch.object(
            ida_analyze_bin,
            "verify_opened_binary_via_mcp",
            return_value=True,
        )
        self.mock_verify_opened_binary = verify_patcher.start()
        self.addCleanup(verify_patcher.stop)

    def test_process_binary_treats_absent_ok_as_skip_and_continues(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            (binary_dir / "CEngineServiceMgr__MainLoop.windows.yaml").write_text(
                "func_name: CEngineServiceMgr__MainLoop\n",
                encoding="utf-8",
            )

            def _fake_preprocess(*, skill_name, expected_outputs, **_kwargs):
                if skill_name == "find-CEngineServiceMgr_DeactivateLoop":
                    return "absent_ok"
                Path(expected_outputs[0]).write_text(
                    "func_name: CLoopTypeBase_DeallocateLoopMode\n",
                    encoding="utf-8",
                )
                return "success"

            with (
                patch.object(
                    ida_analyze_bin,
                    "start_idalib_mcp",
                    return_value=object(),
                ),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    side_effect=lambda process, *_args, **_kwargs: (process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    side_effect=_fake_preprocess,
                ),
                patch.object(
                    ida_analyze_bin,
                    "run_skill",
                    return_value=False,
                ) as mock_run_skill,
                patch.object(
                    ida_analyze_bin,
                    "quit_ida_gracefully",
                    return_value=None,
                ),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEngineServiceMgr_DeactivateLoop",
                            "expected_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                            "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                        },
                        {
                            "name": "find-CLoopTypeBase_DeallocateLoopMode",
                            "expected_output": ["CLoopTypeBase_DeallocateLoopMode.{platform}.yaml"],
                            "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                            "prerequisite": ["find-CEngineServiceMgr_DeactivateLoop"],
                        },
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    llm_model="gpt-5.4",
                    llm_apikey=None,
                    llm_baseurl=None,
                    llm_temperature=None,
                    llm_effort="high",
                    llm_fake_as="codex",
                )

        self.assertEqual((1, 0, 1), (success, fail, skip))
        mock_run_skill.assert_not_called()

    def test_process_binary_allows_missing_optional_input_and_passes_declaration(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "engine2.dll")
            optional_path = binary_dir / "Optional.windows.yaml"

            def _fake_preprocess(*, expected_outputs, optional_inputs, **_kwargs):
                self.assertEqual([str(optional_path)], optional_inputs)
                Path(expected_outputs[0]).write_text("func_name: Consumer\n", encoding="utf-8")
                return "success"

            fake_process = object()
            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(ida_analyze_bin, "ensure_mcp_available", return_value=(fake_process, True)),
                patch.object(ida_analyze_bin, "_run_validate_expected_input_artifacts_via_mcp", return_value=[]),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    side_effect=_fake_preprocess,
                ),
                patch.object(ida_analyze_bin, "run_skill", return_value=False),
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                result = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-consumer",
                            "expected_output": ["Consumer.{platform}.yaml"],
                            "optional_input": ["Optional.{platform}.yaml"],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    max_retries=1,
                )

        self.assertEqual((1, 0, 0), result)

    def test_process_binary_rejects_existing_invalid_optional_input(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "engine2.dll")
            optional_path = binary_dir / "Optional.windows.yaml"
            optional_path.write_text("func_name: Optional\n", encoding="utf-8")
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(ida_analyze_bin, "ensure_mcp_available", return_value=(fake_process, True)),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    side_effect=[[], [f"{optional_path}: invalid"]],
                ),
                patch.object(ida_analyze_bin, "_run_preprocess_single_skill_via_mcp") as preprocess,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                result = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-consumer",
                            "expected_output": ["Consumer.{platform}.yaml"],
                            "optional_input": ["Optional.{platform}.yaml"],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    max_retries=1,
                )

        self.assertEqual((0, 1, 0), result)
        preprocess.assert_not_called()

    def test_process_binary_skips_preprocessor_and_runs_agent_skill_when_skip_pp_enabled(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(ida_analyze_bin, "ensure_mcp_available", return_value=(fake_process, True)),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(ida_analyze_bin, "_run_preprocess_single_skill_via_mcp") as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill", return_value=True) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-direct-agent-skill",
                            "expected_output": ["DirectAgentSkill.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    max_retries=1,
                    skip_pp=True,
                )

        self.assertEqual((1, 0, 0), (success, fail, skip))
        mock_preprocess.assert_not_called()
        mock_run_skill.assert_called_once()

    def test_process_binary_skip_pp_skips_optional_only_skill_when_agent_writes_no_output(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            fake_process = object()
            skill_name = "find-optional-agent-skill"

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(ida_analyze_bin, "ensure_mcp_available", return_value=(fake_process, True)),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(ida_analyze_bin, "_run_preprocess_single_skill_via_mcp") as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill", return_value=True) as mock_run_skill,
                patch.object(ida_analyze_bin, "_report_skill_status") as mock_report_skill_status,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                counts = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": skill_name,
                            "optional_output": ["OptionalAgentSkill.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    max_retries=1,
                    skip_pp=True,
                )

        self.assertEqual((0, 0, 1), counts)
        mock_preprocess.assert_not_called()
        self.assertEqual([], mock_run_skill.call_args.kwargs["expected_yaml_paths"])
        mock_report_skill_status.assert_any_call(
            None,
            None,
            skill_name,
            TaskStatus.SKIPPED,
            ProcessPhase.FINISHED,
            reason=ProcessReason.OPTIONAL_OUTPUT_ABSENT,
        )

    def test_process_binary_skip_pp_succeeds_optional_only_skill_when_agent_writes_output(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            optional_output = binary_dir / "OptionalAgentSkill.windows.yaml"
            fake_process = object()

            def write_optional_output(*_args, **_kwargs):
                optional_output.write_text("func_name: OptionalAgentSkill\n", encoding="utf-8")
                return True

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(ida_analyze_bin, "ensure_mcp_available", return_value=(fake_process, True)),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(ida_analyze_bin, "_run_preprocess_single_skill_via_mcp") as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill", side_effect=write_optional_output),
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                counts = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-optional-agent-skill",
                            "optional_output": ["OptionalAgentSkill.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    max_retries=1,
                    skip_pp=True,
                )

        self.assertEqual((1, 0, 0), counts)
        mock_preprocess.assert_not_called()

    def test_process_binary_skips_when_all_skip_if_exists_artifacts_exist_before_ida_start(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            (binary_dir / "CLoopTypeBase_DeallocateLoopMode.windows.yaml").write_text(
                "func_name: CLoopTypeBase_DeallocateLoopMode\n",
                encoding="utf-8",
            )

            with patch.object(
                ida_analyze_bin,
                "start_idalib_mcp",
                return_value=None,
            ) as mock_start_ida:
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEngineServiceMgr_DeactivateLoop",
                            "expected_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                            "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                            "skip_if_exists": ["CLoopTypeBase_DeallocateLoopMode.{platform}.yaml"],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                )

        self.assertEqual((0, 0, 1), (success, fail, skip))
        mock_start_ida.assert_not_called()

    def test_process_binary_skips_optional_only_skill_when_optional_output_exists_before_ida_start(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            (binary_dir / "CEngineServiceMgr_DeactivateLoop.windows.yaml").write_text(
                "func_name: CEngineServiceMgr_DeactivateLoop\n",
                encoding="utf-8",
            )

            with patch.object(
                ida_analyze_bin,
                "start_idalib_mcp",
                return_value=None,
            ) as mock_start_ida:
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEngineServiceMgr_DeactivateLoop",
                            "optional_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                            "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                )

        self.assertEqual((0, 0, 1), (success, fail, skip))
        mock_start_ida.assert_not_called()

    def test_process_binary_rejects_illegal_optional_output_before_ida_start(
        self,
    ) -> None:
        binary_path = str(Path("/tmp/bin/14141/engine/libengine2.so"))

        with patch.object(
            ida_analyze_bin,
            "start_idalib_mcp",
            return_value=None,
        ) as mock_start_ida:
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path=binary_path,
                skills=[
                    {
                        "name": "find-CEngineServiceMgr_DeactivateLoop",
                        "optional_output": ["../../outside/secret.{platform}.yaml"],
                        "expected_input": [],
                    }
                ],
                agent="codex",
                host="127.0.0.1",
                port=13337,
                ida_args="",
                platform="windows",
                debug=False,
                max_retries=1,
            )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        mock_start_ida.assert_not_called()

    def test_process_binary_does_not_skip_when_skip_if_exists_artifacts_are_partial(
        self,
    ) -> None:
        skills = [
            {
                "name": "find-CEngineServiceMgr_DeactivateLoop",
                "expected_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                "expected_input": [],
                "skip_if_exists": [
                    "CLoopTypeBase_DeallocateLoopMode.{platform}.yaml",
                    "ILoopType_OtherMode.{platform}.yaml",
                ],
            }
        ]

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            (binary_dir / "CLoopTypeBase_DeallocateLoopMode.windows.yaml").write_text(
                "func_name: CLoopTypeBase_DeallocateLoopMode\n",
                encoding="utf-8",
            )

            fake_process = object()

            with (
                patch.object(
                    ida_analyze_bin,
                    "start_idalib_mcp",
                    return_value=fake_process,
                ) as mock_start_ida,
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    return_value="no_script",
                ) as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill", return_value=False) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=skills,
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        mock_start_ida.assert_called_once()
        mock_preprocess.assert_called_once()
        mock_run_skill.assert_called_once()

    def test_process_binary_rechecks_skip_if_exists_before_running_skill(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            (binary_dir / "CEngineServiceMgr__MainLoop.windows.yaml").write_text(
                "func_name: CEngineServiceMgr__MainLoop\n",
                encoding="utf-8",
            )

            def _fake_preprocess(*, skill_name, expected_outputs, **_kwargs):
                if skill_name == "produce-ilooptype":
                    Path(expected_outputs[0]).write_text(
                        "func_name: CLoopTypeBase_DeallocateLoopMode\n",
                        encoding="utf-8",
                    )
                    return "success"
                return "failed"

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=object()),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    side_effect=lambda process, *_args, **_kwargs: (process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    side_effect=_fake_preprocess,
                ) as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill", return_value=False) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "produce-ilooptype",
                            "expected_output": ["CLoopTypeBase_DeallocateLoopMode.{platform}.yaml"],
                            "expected_input": [],
                        },
                        {
                            "name": "find-CEngineServiceMgr_DeactivateLoop",
                            "expected_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                            "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                            "skip_if_exists": ["CLoopTypeBase_DeallocateLoopMode.{platform}.yaml"],
                            "prerequisite": ["produce-ilooptype"],
                        },
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    llm_model="gpt-5.4",
                    llm_apikey=None,
                    llm_baseurl=None,
                    llm_temperature=None,
                    llm_effort="high",
                    llm_fake_as="codex",
                )

        self.assertEqual((1, 0, 1), (success, fail, skip))
        self.assertEqual(1, mock_preprocess.call_count)
        mock_run_skill.assert_not_called()

    def test_process_binary_runs_fallback_skill_when_preprocess_script_fails(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    return_value="failed",
                ) as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill", return_value=True) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "a_preprocess_fails",
                            "expected_output": ["A.{platform}.yaml"],
                            "expected_input": [],
                        },
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                )

        self.assertEqual((1, 0, 0), (success, fail, skip))
        self.assertEqual(1, mock_preprocess.call_count)
        self.assertEqual(
            "a_preprocess_fails",
            mock_preprocess.call_args.kwargs["skill_name"],
        )
        mock_run_skill.assert_called_once()

    def test_process_binary_reports_unexpected_preprocess_exception_before_fallback(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    side_effect=RuntimeError("runner exploded"),
                ),
                patch.object(ida_analyze_bin, "report_preprocess_exception") as mock_report_exception,
                patch.object(ida_analyze_bin, "run_skill", return_value=True) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "a_preprocess_raises",
                            "expected_output": ["A.{platform}.yaml"],
                            "expected_input": [],
                        },
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=False,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                )

        self.assertEqual((1, 0, 0), (success, fail, skip))
        mock_report_exception.assert_called_once()
        self.assertEqual("a_preprocess_raises", mock_report_exception.call_args.args[0])
        self.assertEqual("runner dispatch", mock_report_exception.call_args.args[1])
        self.assertIsInstance(mock_report_exception.call_args.args[2], RuntimeError)
        self.assertFalse(mock_report_exception.call_args.kwargs["debug"])
        mock_run_skill.assert_called_once()

    def test_process_binary_skips_vcall_targets_after_preprocess_fallback_failure(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    return_value="failed",
                ),
                patch.object(ida_analyze_bin, "run_skill", return_value=False) as mock_run_skill,
                patch.object(
                    ida_analyze_bin,
                    "preprocess_single_vcall_object_via_mcp",
                    new_callable=AsyncMock,
                    return_value={
                        "status": "success",
                        "exported_functions": 1,
                        "failed_functions": 0,
                        "skipped_functions": 0,
                    },
                ) as mock_vcall,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "a_preprocess_fails",
                            "expected_output": ["A.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    vcall_targets=["g_pShouldNotRun"],
                )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        mock_run_skill.assert_called_once()
        mock_vcall.assert_not_called()

    def test_process_binary_runs_fallback_skill_only_when_preprocess_has_no_script(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    return_value="no_script",
                ) as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill", return_value=True) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-fallback-only",
                            "expected_output": ["FallbackOnly.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                )

        self.assertEqual((1, 0, 0), (success, fail, skip))
        mock_preprocess.assert_called_once()
        mock_run_skill.assert_called_once()

    def test_process_binary_aborts_when_fallback_skill_fails(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    return_value="no_script",
                ) as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill", return_value=False) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "a_fallback_fails",
                            "expected_output": ["A.{platform}.yaml"],
                            "expected_input": [],
                        },
                        {
                            "name": "b_should_not_run",
                            "expected_output": ["B.{platform}.yaml"],
                            "expected_input": [],
                        },
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        self.assertEqual(1, mock_preprocess.call_count)
        self.assertEqual(1, mock_run_skill.call_count)

    def test_process_binary_continues_after_fallback_skill_failure_when_skip_error_enabled(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    return_value="no_script",
                ) as mock_preprocess,
                patch.object(
                    ida_analyze_bin,
                    "run_skill",
                    side_effect=[False, True],
                ) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "a_fallback_fails",
                            "expected_output": ["A.{platform}.yaml"],
                            "expected_input": [],
                        },
                        {
                            "name": "b_should_run",
                            "expected_output": ["B.{platform}.yaml"],
                            "expected_input": [],
                        },
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    skip_error=True,
                )

        self.assertEqual((1, 1, 0), (success, fail, skip))
        self.assertEqual(2, mock_preprocess.call_count)
        self.assertEqual(2, mock_run_skill.call_count)

    def test_process_binary_continues_after_preprocess_output_failure_when_skip_error_enabled(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    side_effect=["success", "absent_ok"],
                ) as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill") as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "a_preprocess_output_fails",
                            "expected_output": ["A.{platform}.yaml"],
                            "expected_input": [],
                        },
                        {
                            "name": "b_should_run",
                            "expected_output": ["B.{platform}.yaml"],
                            "expected_input": [],
                        },
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    skip_error=True,
                )

        self.assertEqual((0, 1, 1), (success, fail, skip))
        self.assertEqual(2, mock_preprocess.call_count)
        mock_run_skill.assert_not_called()

    def test_process_binary_skips_optional_only_skill_when_no_preprocess_script_and_no_output(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            (binary_dir / "CEngineServiceMgr__MainLoop.windows.yaml").write_text(
                "func_name: CEngineServiceMgr__MainLoop\n",
                encoding="utf-8",
            )
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    return_value="no_script",
                ) as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill", return_value=False) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEngineServiceMgr_DeactivateLoop",
                            "optional_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                            "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                        }
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    llm_model="gpt-5.4",
                    llm_apikey=None,
                    llm_baseurl=None,
                    llm_temperature=None,
                    llm_effort="high",
                    llm_fake_as="codex",
                )

        self.assertEqual((0, 0, 1), (success, fail, skip))
        mock_preprocess.assert_called_once()
        self.assertEqual(
            [
                str(binary_dir / "CEngineServiceMgr_DeactivateLoop.windows.yaml"),
            ],
            mock_preprocess.call_args.kwargs["expected_outputs"],
        )
        self.assertEqual(
            [str(binary_dir / "CEngineServiceMgr__MainLoop.windows.yaml")],
            mock_preprocess.call_args.kwargs["expected_inputs"],
        )
        mock_run_skill.assert_not_called()

    def test_process_binary_counts_optional_only_skill_success_when_preprocess_writes_output(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            (binary_dir / "CEngineServiceMgr__MainLoop.windows.yaml").write_text(
                "func_name: CEngineServiceMgr__MainLoop\n",
                encoding="utf-8",
            )

            def _fake_preprocess(*, expected_outputs, **_kwargs):
                Path(expected_outputs[0]).write_text(
                    "func_name: CEngineServiceMgr_DeactivateLoop\n",
                    encoding="utf-8",
                )
                return "success"

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=object()),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    side_effect=lambda process, *_args, **_kwargs: (process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    side_effect=_fake_preprocess,
                ),
                patch.object(ida_analyze_bin, "run_skill", return_value=False) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEngineServiceMgr_DeactivateLoop",
                            "optional_output": ["CEngineServiceMgr_DeactivateLoop.{platform}.yaml"],
                            "expected_input": ["CEngineServiceMgr__MainLoop.{platform}.yaml"],
                        }
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    llm_model="gpt-5.4",
                    llm_apikey=None,
                    llm_baseurl=None,
                    llm_temperature=None,
                    llm_effort="high",
                    llm_fake_as="codex",
                )

        self.assertEqual((1, 0, 0), (success, fail, skip))
        mock_run_skill.assert_not_called()

    def test_process_binary_passes_required_plus_optional_to_preprocess_but_only_requires_expected_output(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")

            def _fake_preprocess(*, expected_outputs, **_kwargs):
                self.assertEqual(
                    [
                        str(binary_dir / "Required.windows.yaml"),
                        str(binary_dir / "Optional.windows.yaml"),
                    ],
                    expected_outputs,
                )
                Path(expected_outputs[0]).write_text(
                    "func_name: Required\n",
                    encoding="utf-8",
                )
                return "success"

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=object()),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    side_effect=lambda process, *_args, **_kwargs: (process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    side_effect=_fake_preprocess,
                ),
                patch.object(ida_analyze_bin, "run_skill", return_value=False) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-required-and-optional",
                            "expected_output": ["Required.{platform}.yaml"],
                            "optional_output": ["Optional.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    llm_model="gpt-5.4",
                    llm_apikey=None,
                    llm_baseurl=None,
                    llm_temperature=None,
                    llm_effort="high",
                    llm_fake_as="codex",
                )

        self.assertEqual((1, 0, 0), (success, fail, skip))
        mock_run_skill.assert_not_called()

    def test_process_binary_agent_skill_validates_only_required_outputs(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            fake_process = object()

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    return_value="no_script",
                ),
                patch.object(ida_analyze_bin, "run_skill", return_value=True) as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully", return_value=None),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-required-and-optional",
                            "expected_output": ["Required.{platform}.yaml"],
                            "optional_output": ["Optional.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    old_binary_dir=None,
                    platform="windows",
                    agent="codex",
                    max_retries=1,
                    debug=True,
                    host="127.0.0.1",
                    port=39091,
                    ida_args=None,
                    llm_model="gpt-5.4",
                    llm_apikey=None,
                    llm_baseurl=None,
                    llm_temperature=None,
                    llm_effort="high",
                    llm_fake_as="codex",
                )

        self.assertEqual((1, 0, 0), (success, fail, skip))
        self.assertEqual(
            [str(binary_dir / "Required.windows.yaml")],
            mock_run_skill.call_args.kwargs["expected_yaml_paths"],
        )

    def test_process_binary_rejects_illegal_expected_input_without_crash(self) -> None:
        binary_path = str(Path("/tmp/bin/14141/networksystem/networksystem.dll"))
        skills = [
            {
                "name": "skill_illegal_expected_input",
                "expected_output": ["CNetChan_vtable.{platform}.yaml"],
                "expected_input": ["../../outside/secret.{platform}.yaml"],
            }
        ]
        fake_process = object()

        with (
            patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
            patch.object(ida_analyze_bin, "ensure_mcp_available", return_value=(fake_process, True)),
            patch.object(ida_analyze_bin, "quit_ida_gracefully") as mock_quit_ida,
            patch.object(ida_analyze_bin, "run_skill") as mock_run_skill,
        ):
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path=binary_path,
                skills=skills,
                agent="codex",
                host="127.0.0.1",
                port=13337,
                ida_args="",
                platform="windows",
                debug=False,
                max_retries=1,
            )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        mock_run_skill.assert_not_called()
        mock_quit_ida.assert_called_once_with(
            fake_process,
            "127.0.0.1",
            13337,
            expected_binary=binary_path,
            debug=False,
        )

    def test_process_binary_preserves_prefilter_failures_when_mcp_startup_fails(self) -> None:
        binary_path = str(Path("/tmp/bin/14141/networksystem/networksystem.dll"))
        skills = [
            {
                "name": "a_illegal_output",
                "expected_output": ["../../outside/secret.{platform}.yaml"],
                "expected_input": [],
            },
            {
                "name": "b_valid_output",
                "expected_output": ["CNetChan_vtable.{platform}.yaml"],
                "expected_input": [],
            },
        ]

        with patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=None):
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path=binary_path,
                skills=skills,
                agent="codex",
                host="127.0.0.1",
                port=13337,
                ida_args="",
                platform="windows",
                debug=False,
                max_retries=1,
            )

        self.assertEqual((0, 2, 0), (success, fail, skip))

    def test_process_binary_rejects_invalid_expected_input_artifact_before_preprocess(self) -> None:
        fake_process = object()

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141b" / "engine"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "libengine2.so")
            expected_input_path = binary_dir / "CDemoRecorder_WriteSpawnGroups.linux.yaml"
            expected_input_path.write_text("func_name: CDemoRecorder_WriteSpawnGroups\n", encoding="utf-8")

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(ida_analyze_bin, "ensure_mcp_available", return_value=(fake_process, True)),
                patch.object(ida_analyze_bin, "quit_ida_gracefully") as mock_quit_ida,
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[
                        (f"{expected_input_path}: func_va=0x616050 resolves to segment '.data' instead of '.text'")
                    ],
                ),
                patch.object(ida_analyze_bin, "_run_preprocess_single_skill_via_mcp") as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill") as mock_run_skill,
                patch("sys.stdout", new_callable=io.StringIO) as stdout,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-INetworkMessages_FindNetworkMessageById",
                            "expected_output": ["INetworkMessages_FindNetworkMessageById.{platform}.yaml"],
                            "expected_input": ["CDemoRecorder_WriteSpawnGroups.{platform}.yaml"],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="linux",
                    debug=False,
                    max_retries=1,
                )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        mock_preprocess.assert_not_called()
        mock_run_skill.assert_not_called()
        self.assertIn("invalid expected_input artifact", stdout.getvalue())
        mock_quit_ida.assert_called_once_with(
            fake_process,
            "127.0.0.1",
            13337,
            expected_binary=binary_path,
            debug=False,
        )

    def test_process_binary_does_not_start_ida_for_post_process_when_rename_is_false(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")
            (binary_dir / "CEntFireOutputAutoCompletionFunctor_FireOutput.windows.yaml").write_text(
                "func_name: CEntFireOutputAutoCompletionFunctor_FireOutput\nfunc_va: '0x180c165c0'\n",
                encoding="utf-8",
            )

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp") as mock_start_ida,
                patch.object(
                    ida_analyze_bin,
                    "_run_post_process_expected_outputs_via_mcp",
                    create=True,
                ) as mock_post_process,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                            "expected_output": ["CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                )

        self.assertEqual((0, 0, 1), (success, fail, skip))
        mock_start_ida.assert_not_called()
        mock_post_process.assert_not_called()

    def test_process_binary_runs_post_process_when_rename_true_and_outputs_exist(
        self,
    ) -> None:
        fake_process = object()

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")
            (binary_dir / "CEntFireOutputAutoCompletionFunctor_FireOutput.windows.yaml").write_text(
                "func_name: CEntFireOutputAutoCompletionFunctor_FireOutput\nfunc_va: '0x180c165c0'\n",
                encoding="utf-8",
            )

            with (
                patch.object(
                    ida_analyze_bin,
                    "start_idalib_mcp",
                    return_value=fake_process,
                ) as mock_start_ida,
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_post_process_expected_outputs_via_mcp",
                    return_value=True,
                    create=True,
                ) as mock_post_process,
                patch.object(
                    ida_analyze_bin,
                    "quit_ida_gracefully",
                    return_value=None,
                ) as mock_quit_ida,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                            "expected_output": ["CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                    rename=True,
                )

        self.assertEqual((0, 0, 1), (success, fail, skip))
        mock_start_ida.assert_called_once_with(binary_path, "127.0.0.1", 13337, "", False)
        mock_post_process.assert_called_once()
        mock_quit_ida.assert_called_once_with(
            fake_process,
            "127.0.0.1",
            13337,
            expected_binary=binary_path,
            debug=False,
        )

    def test_process_binary_counts_post_process_failure_once(
        self,
    ) -> None:
        fake_process = object()

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")
            (binary_dir / "CEntFireOutputAutoCompletionFunctor_FireOutput.windows.yaml").write_text(
                "func_name: CEntFireOutputAutoCompletionFunctor_FireOutput\nfunc_va: '0x180c165c0'\n",
                encoding="utf-8",
            )

            with (
                patch.object(
                    ida_analyze_bin,
                    "start_idalib_mcp",
                    return_value=fake_process,
                ),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_post_process_expected_outputs_via_mcp",
                    side_effect=RuntimeError("boom"),
                ),
                patch.object(
                    ida_analyze_bin,
                    "quit_ida_gracefully",
                    return_value=None,
                ),
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                            "expected_output": ["CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                    rename=True,
                )

        self.assertEqual((0, 1, 1), (success, fail, skip))

    def test_process_binary_counts_post_process_preflight_collection_failure_once(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")
            (binary_dir / "CEntFireOutputAutoCompletionFunctor_FireOutput.windows.yaml").write_text(
                "func_name: CEntFireOutputAutoCompletionFunctor_FireOutput\nfunc_va: '0x180c165c0'\n",
                encoding="utf-8",
            )

            with (
                patch.object(
                    ida_analyze_bin,
                    "_collect_post_process_yaml_mappings",
                    side_effect=RuntimeError("collect boom"),
                ),
                patch.object(
                    ida_analyze_bin,
                    "start_idalib_mcp",
                ) as mock_start_ida,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                            "expected_output": ["CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                    rename=True,
                )

        self.assertEqual((0, 1, 1), (success, fail, skip))
        mock_start_ida.assert_not_called()

    def test_process_binary_counts_startup_failure_for_rename_only_work(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")
            (binary_dir / "CEntFireOutputAutoCompletionFunctor_FireOutput.windows.yaml").write_text(
                "func_name: CEntFireOutputAutoCompletionFunctor_FireOutput\nfunc_va: '0x180c165c0'\n",
                encoding="utf-8",
            )

            with patch.object(
                ida_analyze_bin,
                "start_idalib_mcp",
                return_value=None,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                            "expected_output": ["CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                    rename=True,
                )

        self.assertEqual((0, 1, 1), (success, fail, skip))


class TestProcessBinaryReporting(unittest.TestCase):
    def _build_reporting(self, binary_root, skills):
        module = {
            "stage_index": 0,
            "name": "engine",
            "path_windows": "game/bin/win64/engine2.dll",
            "skills": skills,
        }
        plan = ida_analyze_bin.build_execution_plan(
            [module],
            platforms=["windows"],
            bin_dir=str(binary_root),
            gamever="14141",
        )
        reporter = MagicMock()
        reporting = ida_analyze_bin.AnalysisReporting(reporter, "run-1", plan)
        return reporter, reporting, plan.jobs[0].id

    def test_reports_existing_output_as_skipped(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_root = Path(temp_dir) / "bin"
            binary_dir = binary_root / "14141" / "engine"
            binary_dir.mkdir(parents=True)
            binary_path = str(binary_dir / "engine2.dll")
            (binary_dir / "Existing.windows.yaml").write_text("func_name: Existing\n", encoding="utf-8")
            skills = [{"name": "existing", "expected_output": ["Existing.{platform}.yaml"], "expected_input": []}]
            reporter, reporting, job_id = self._build_reporting(binary_root, skills)

            with patch.object(ida_analyze_bin, "start_idalib_mcp") as mock_start:
                counts = ida_analyze_bin.process_binary(
                    binary_path,
                    skills,
                    "codex",
                    "127.0.0.1",
                    13337,
                    "",
                    "windows",
                    reporting=reporting,
                    job_id=job_id,
                )

        task_id = f"{job_id}/existing"
        events = [report_call.args[0] for report_call in reporter.emit.call_args_list]
        skipped_event = next(event for event in events if event.task_id == task_id)
        self.assertEqual((0, 0, 1), counts)
        self.assertEqual(TaskStatus.SKIPPED, skipped_event.status)
        self.assertEqual(ProcessReason.EXISTING_OUTPUTS, skipped_event.reason)
        mock_start.assert_not_called()

    def test_reports_failed_skill_progress_and_aborts_remaining_skill(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_root = Path(temp_dir) / "bin"
            binary_dir = binary_root / "14141" / "engine"
            binary_dir.mkdir(parents=True)
            binary_path = str(binary_dir / "engine2.dll")
            skills = [
                {"name": "first", "expected_output": ["First.{platform}.yaml"], "expected_input": []},
                {"name": "second", "expected_output": ["Second.{platform}.yaml"], "expected_input": []},
            ]
            reporter, reporting, job_id = self._build_reporting(binary_root, skills)

            def fail_agent(*_args, progress_callback=None, **_kwargs):
                progress_callback(event="attempt_started", attempt=1, max_attempts=1)
                return False

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=object()),
                patch.object(
                    ida_analyze_bin, "ensure_mcp_available", side_effect=lambda process, *_a, **_k: (process, True)
                ),
                patch.object(ida_analyze_bin, "verify_opened_binary_via_mcp", return_value=True),
                patch.object(ida_analyze_bin, "_run_validate_expected_input_artifacts_via_mcp", return_value=[]),
                patch.object(ida_analyze_bin, "_run_preprocess_single_skill_via_mcp", return_value="no_script"),
                patch.object(ida_analyze_bin, "run_skill", side_effect=fail_agent),
                patch.object(ida_analyze_bin, "quit_ida_gracefully"),
            ):
                counts = ida_analyze_bin.process_binary(
                    binary_path,
                    skills,
                    "codex",
                    "127.0.0.1",
                    13337,
                    "",
                    "windows",
                    max_retries=1,
                    reporting=reporting,
                    job_id=job_id,
                )

        events = [report_call.args[0] for report_call in reporter.emit.call_args_list]
        first_id = f"{job_id}/first"
        second_id = f"{job_id}/second"
        self.assertEqual((0, 1, 0), counts)
        self.assertTrue(
            any(event.event_type == ProcessEventType.SKILL_PROGRESS and event.task_id == first_id for event in events)
        )
        self.assertTrue(
            any(
                event.task_id == first_id
                and event.status == TaskStatus.FAILED
                and event.reason == ProcessReason.AGENT_FAILED
                for event in events
            )
        )
        self.assertTrue(
            any(
                event.task_id == second_id
                and event.status == TaskStatus.ABORTED
                and event.reason == ProcessReason.UPSTREAM_ABORTED
                for event in events
            )
        )

    def test_reports_missing_input_as_failed(self) -> None:
        with TemporaryDirectory() as temp_dir:
            binary_root = Path(temp_dir) / "bin"
            binary_dir = binary_root / "14141" / "engine"
            binary_dir.mkdir(parents=True)
            binary_path = str(binary_dir / "engine2.dll")
            skills = [
                {
                    "name": "consumer",
                    "expected_output": ["Consumer.{platform}.yaml"],
                    "expected_input": ["Missing.{platform}.yaml"],
                }
            ]
            reporter, reporting, job_id = self._build_reporting(binary_root, skills)

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=object()),
                patch.object(
                    ida_analyze_bin, "ensure_mcp_available", side_effect=lambda process, *_a, **_k: (process, True)
                ),
                patch.object(ida_analyze_bin, "verify_opened_binary_via_mcp", return_value=True),
                patch.object(ida_analyze_bin, "quit_ida_gracefully"),
            ):
                counts = ida_analyze_bin.process_binary(
                    binary_path,
                    skills,
                    "codex",
                    "127.0.0.1",
                    13337,
                    "",
                    "windows",
                    reporting=reporting,
                    job_id=job_id,
                )

        task_id = f"{job_id}/consumer"
        events = [report_call.args[0] for report_call in reporter.emit.call_args_list]
        failed_event = next(event for event in events if event.task_id == task_id and event.status == TaskStatus.FAILED)
        self.assertEqual((0, 1, 0), counts)
        self.assertEqual(ProcessReason.MISSING_INPUT, failed_event.reason)
        self.assertIn(ProcessPhase.VALIDATING_INPUTS, [event.phase for event in events if event.task_id == task_id])


class TestProcessBinaryOpenedBinaryVerification(unittest.TestCase):
    def setUp(self) -> None:
        stop_patcher = patch.object(ida_analyze_bin, "stop_idalib_mcp_process")
        self.mock_stop_ida = stop_patcher.start()
        self.addCleanup(stop_patcher.stop)
        wait_patcher = patch.object(ida_analyze_bin, "wait_for_port_release", return_value=True)
        self.mock_wait_for_release = wait_patcher.start()
        self.addCleanup(wait_patcher.stop)

    def test_process_binary_aborts_before_preprocess_when_opened_binary_mismatches(self) -> None:
        fake_process = object()

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(ida_analyze_bin, "verify_opened_binary_via_mcp", return_value=False),
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    return_value=(fake_process, True),
                ) as mock_ensure,
                patch.object(ida_analyze_bin, "_run_validate_expected_input_artifacts_via_mcp") as mock_validate,
                patch.object(ida_analyze_bin, "_run_preprocess_single_skill_via_mcp") as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill") as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully") as mock_quit_ida,
                patch("sys.stdout", new_callable=io.StringIO) as stdout,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CBaseEntity_vtable",
                            "expected_output": ["CBaseEntity_vtable.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        self.assertIn("opened binary verification failure", stdout.getvalue())
        mock_ensure.assert_not_called()
        mock_validate.assert_not_called()
        mock_preprocess.assert_not_called()
        mock_run_skill.assert_not_called()
        mock_quit_ida.assert_not_called()
        self.mock_stop_ida.assert_called_once_with(fake_process, debug=False)
        self.mock_wait_for_release.assert_called_once_with("127.0.0.1", 13337)

    def test_process_binary_recovers_initial_inactive_worker_once(self) -> None:
        original_process = object()
        restarted_process = object()

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14172" / "client"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "client.dll")
            Path(binary_path).write_bytes(b"client-binary")

            def _fake_preprocess(*, expected_outputs, **_kwargs):
                Path(expected_outputs[0]).write_text("func_name: Recovered\n", encoding="utf-8")
                return "success"

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=original_process) as start_ida,
                patch.object(
                    ida_analyze_bin,
                    "verify_opened_binary_via_mcp",
                    side_effect=[McpDatabaseUnavailableError("inactive or unreachable"), True, True, True],
                ) as verify,
                patch.object(
                    ida_analyze_bin,
                    "ensure_mcp_available",
                    side_effect=[(restarted_process, True), (restarted_process, True)],
                ) as ensure,
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    side_effect=_fake_preprocess,
                ),
                patch.object(ida_analyze_bin, "run_skill", return_value=False),
                patch.object(ida_analyze_bin, "quit_ida_gracefully") as quit_ida,
            ):
                result = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-recovered",
                            "expected_output": ["Recovered.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    max_retries=1,
                )

        self.assertEqual((1, 0, 0), result)
        start_ida.assert_called_once()
        self.assertEqual(2, ensure.call_count)
        self.assertEqual(4, verify.call_count)
        quit_ida.assert_called_once_with(
            restarted_process,
            "127.0.0.1",
            13337,
            expected_binary=binary_path,
            debug=False,
        )
        self.mock_stop_ida.assert_not_called()

    def test_process_binary_shares_one_restart_budget_across_later_work(self) -> None:
        original_process = MagicMock()
        original_process.poll.return_value = None
        restarted_process = MagicMock()
        restarted_process.poll.return_value = None

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14172" / "client"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "client.dll")
            Path(binary_path).write_bytes(b"client-binary")

            with (
                patch.object(
                    ida_analyze_bin,
                    "start_idalib_mcp",
                    side_effect=[original_process, restarted_process],
                ) as start_ida,
                patch.object(
                    ida_analyze_bin,
                    "verify_opened_binary_via_mcp",
                    side_effect=[McpDatabaseUnavailableError("inactive or unreachable"), True],
                ),
                patch.object(
                    ida_analyze_bin,
                    "check_mcp_worker_health",
                    new=AsyncMock(return_value=False),
                ),
                patch.object(ida_analyze_bin, "is_port_in_use", return_value=False),
                patch.object(ida_analyze_bin, "quit_ida_gracefully") as quit_ida,
                patch.object(ida_analyze_bin, "_run_preprocess_single_skill_via_mcp") as preprocess,
                patch.object(ida_analyze_bin, "preprocess_single_vcall_object_via_mcp") as preprocess_vcall,
            ):
                result = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-budget-consumer",
                            "expected_output": ["BudgetConsumer.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    max_retries=1,
                    vcall_targets=["g_pBudgetTarget"],
                )

        self.assertEqual((0, 2, 0), result)
        self.assertEqual(2, start_ida.call_count)
        self.assertEqual(2, quit_ida.call_count)
        preprocess.assert_not_called()
        preprocess_vcall.assert_not_called()

    def test_process_binary_aborts_before_skill_mcp_work_when_recheck_mismatches(self) -> None:
        fake_process = object()

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "verify_opened_binary_via_mcp",
                    side_effect=[True, False],
                ),
                patch.object(ida_analyze_bin, "ensure_mcp_available", return_value=(fake_process, True)),
                patch.object(ida_analyze_bin, "_run_validate_expected_input_artifacts_via_mcp") as mock_validate,
                patch.object(ida_analyze_bin, "_run_preprocess_single_skill_via_mcp") as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill") as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully") as mock_quit_ida,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CBaseEntity_vtable",
                            "expected_output": ["CBaseEntity_vtable.{platform}.yaml"],
                            "expected_input": [],
                        },
                        {
                            "name": "find-CBaseEntity_dtor",
                            "expected_output": ["CBaseEntity_dtor.{platform}.yaml"],
                            "expected_input": [],
                        },
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                )

        self.assertEqual((0, 2, 0), (success, fail, skip))
        mock_validate.assert_not_called()
        mock_preprocess.assert_not_called()
        mock_run_skill.assert_not_called()
        mock_quit_ida.assert_not_called()
        self.mock_stop_ida.assert_called_once_with(fake_process, debug=False)
        self.mock_wait_for_release.assert_called_once_with("127.0.0.1", 13337)

    def test_process_binary_aborts_before_agent_fallback_when_recheck_mismatches(self) -> None:
        fake_process = object()

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "verify_opened_binary_via_mcp",
                    side_effect=[True, True, True, False],
                ),
                patch.object(ida_analyze_bin, "ensure_mcp_available", return_value=(fake_process, True)),
                patch.object(
                    ida_analyze_bin,
                    "_run_validate_expected_input_artifacts_via_mcp",
                    return_value=[],
                ),
                patch.object(
                    ida_analyze_bin,
                    "_run_preprocess_single_skill_via_mcp",
                    return_value=ida_analyze_bin.PREPROCESS_STATUS_NO_SCRIPT,
                ) as mock_preprocess,
                patch.object(ida_analyze_bin, "run_skill") as mock_run_skill,
                patch.object(ida_analyze_bin, "quit_ida_gracefully") as mock_quit_ida,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CBaseEntity_vtable",
                            "expected_output": ["CBaseEntity_vtable.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        mock_preprocess.assert_called_once()
        mock_run_skill.assert_not_called()
        mock_quit_ida.assert_not_called()
        self.mock_stop_ida.assert_called_once_with(fake_process, debug=False)
        self.mock_wait_for_release.assert_called_once_with("127.0.0.1", 13337)

    def test_process_binary_aborts_before_vcall_export_when_recheck_mismatches(self) -> None:
        fake_process = object()

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "networksystem"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "networksystem.dll")

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "verify_opened_binary_via_mcp",
                    side_effect=[True, False],
                ),
                patch.object(ida_analyze_bin, "ensure_mcp_available", return_value=(fake_process, True)),
                patch.object(ida_analyze_bin, "preprocess_single_vcall_object_via_mcp") as mock_vcall,
                patch.object(ida_analyze_bin, "quit_ida_gracefully") as mock_quit_ida,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                    gamever="14141",
                    module_name="networksystem",
                    vcall_targets=["g_pNetworkMessages"],
                )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        mock_vcall.assert_not_called()
        mock_quit_ida.assert_not_called()
        self.mock_stop_ida.assert_called_once_with(fake_process, debug=False)
        self.mock_wait_for_release.assert_called_once_with("127.0.0.1", 13337)

    def test_process_binary_aborts_before_post_process_when_recheck_mismatches(self) -> None:
        fake_process = object()

        with TemporaryDirectory() as temp_dir:
            binary_dir = Path(temp_dir) / "bin" / "14141" / "server"
            binary_dir.mkdir(parents=True, exist_ok=True)
            binary_path = str(binary_dir / "server.dll")
            (binary_dir / "CEntFireOutputAutoCompletionFunctor_FireOutput.windows.yaml").write_text(
                "func_name: CEntFireOutputAutoCompletionFunctor_FireOutput\nfunc_va: '0x180c165c0'\n",
                encoding="utf-8",
            )

            with (
                patch.object(ida_analyze_bin, "start_idalib_mcp", return_value=fake_process),
                patch.object(
                    ida_analyze_bin,
                    "verify_opened_binary_via_mcp",
                    side_effect=[True, False],
                ),
                patch.object(ida_analyze_bin, "ensure_mcp_available", return_value=(fake_process, True)),
                patch.object(ida_analyze_bin, "_run_post_process_expected_outputs_via_mcp") as mock_post_process,
                patch.object(ida_analyze_bin, "quit_ida_gracefully") as mock_quit_ida,
            ):
                success, fail, skip = ida_analyze_bin.process_binary(
                    binary_path=binary_path,
                    skills=[
                        {
                            "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                            "expected_output": ["CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"],
                            "expected_input": [],
                        }
                    ],
                    agent="codex",
                    host="127.0.0.1",
                    port=13337,
                    ida_args="",
                    platform="windows",
                    debug=False,
                    max_retries=1,
                    rename=True,
                )

        self.assertEqual((0, 1, 1), (success, fail, skip))
        mock_post_process.assert_not_called()
        mock_quit_ida.assert_not_called()
        self.mock_stop_ida.assert_called_once_with(fake_process, debug=False)
        self.mock_wait_for_release.assert_called_once_with("127.0.0.1", 13337)


class TestExpectedInputArtifactValidation(unittest.IsolatedAsyncioTestCase):
    async def test_validate_expected_input_artifacts_reports_invalid_func_va_segment(self) -> None:
        with TemporaryDirectory() as temp_dir:
            artifact_path = Path(temp_dir) / "CDemoRecorder_WriteSpawnGroups.linux.yaml"
            artifact_path.write_text(
                "\n".join(
                    [
                        "func_name: CDemoRecorder_WriteSpawnGroups",
                        "func_va: '0x616050'",
                        "func_rva: '0x616050'",
                        "func_size: '0x3263'",
                    ]
                ),
                encoding="utf-8",
            )

            with (
                patch.object(
                    ida_analyze_bin,
                    "_lookup_expected_input_artifact_category",
                    return_value="func",
                ),
                patch.object(
                    ida_analyze_bin,
                    "_inspect_func_va_via_session",
                    AsyncMock(
                        return_value={
                            "has_segment": True,
                            "segment_name": ".data",
                            "has_function": False,
                            "function_start": "",
                            "is_function_start": False,
                        }
                    ),
                ),
            ):
                issues = await ida_analyze_bin.validate_expected_input_artifacts_via_session(
                    session=MagicMock(),
                    expected_inputs=[str(artifact_path)],
                    platform="linux",
                    debug=False,
                )

        self.assertEqual(1, len(issues))
        self.assertIn(str(artifact_path), issues[0])
        self.assertIn(
            "func_va=0x616050 resolves to segment '.data' instead of '.text'",
            issues[0],
        )
        # func_sig is no longer required for category:func artifacts, so a sig-less
        # payload must NOT produce a "missing required field func_sig" issue.
        self.assertNotIn("missing required field func_sig", issues[0])

    async def test_validate_expected_input_artifacts_skips_func_va_mapping_for_sibling_module_artifact(
        self,
    ) -> None:
        with TemporaryDirectory() as temp_dir:
            gamever_dir = Path(temp_dir) / "bin" / "14155"
            engine_dir = gamever_dir / "engine"
            server_dir = gamever_dir / "server"
            engine_dir.mkdir(parents=True, exist_ok=True)
            server_dir.mkdir(parents=True, exist_ok=True)
            artifact_path = server_dir / "CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName.linux.yaml"
            artifact_path.write_text(
                "\n".join(
                    [
                        "func_name: CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName",
                        "func_va: '0x1527d60'",
                        "func_rva: '0x1527d60'",
                        "func_size: '0x11b'",
                        "func_sig: AA BB",
                        "vtable_name: CGameEntitySystem",
                        "vfunc_offset: '0x18'",
                        "vfunc_index: 3",
                    ]
                ),
                encoding="utf-8",
            )

            with (
                patch.object(
                    ida_analyze_bin,
                    "_lookup_expected_input_artifact_category",
                    return_value="vfunc",
                ),
                patch.object(
                    ida_analyze_bin,
                    "_inspect_func_va_via_session",
                    AsyncMock(
                        return_value={
                            "has_segment": False,
                            "segment_name": "",
                            "has_function": False,
                            "function_start": "",
                            "is_function_start": False,
                        }
                    ),
                ) as mock_inspect_func_va,
            ):
                issues = await ida_analyze_bin.validate_expected_input_artifacts_via_session(
                    session=MagicMock(),
                    expected_inputs=[str(artifact_path)],
                    platform="linux",
                    binary_dir=str(engine_dir),
                    debug=False,
                )

        self.assertEqual([], issues)
        mock_inspect_func_va.assert_not_awaited()


class TestInspectFuncVaPyEvalSelfHeal(unittest.IsolatedAsyncioTestCase):
    """The expected_input validator promotes an un-analyzed .text thunk (a bare
    loc_, code but not a function) to a function via idaapi.add_func before
    deciding func_va does not resolve to a function."""

    async def _capture_inspect_py_eval(self, func_va_text: str) -> str:
        captured: dict[str, object] = {}

        class _CapturingSession:
            async def call_tool(self, name, arguments):
                captured["name"] = name
                captured["code"] = arguments["code"]
                # Stop after capturing; the helper swallows the exception and
                # returns None, so we get the exact py_eval string it built.
                raise RuntimeError("stop after capturing py_eval code")

        result = await ida_analyze_bin._inspect_func_va_via_session(
            _CapturingSession(),
            func_va_text,
        )
        self.assertIsNone(result)
        self.assertEqual("py_eval", captured["name"])
        return captured["code"]

    @staticmethod
    def _exec_inspect_py_eval(code: str, *, seg_name, add_func_succeeds: bool):
        state = {"is_func": False}

        def fake_get_func(ea):
            if not state["is_func"]:
                return None
            return SimpleNamespace(start_ea=ea, end_ea=ea + 0x18)

        def fake_add_func(_ea):
            # Mirror IDA: add_func succeeds only on real code, no-ops otherwise.
            if add_func_succeeds:
                state["is_func"] = True
            return add_func_succeeds

        seg_sentinel = object() if seg_name is not None else None
        fake_ida_segment = SimpleNamespace(
            getseg=lambda _ea: seg_sentinel,
            get_segm_name=lambda _seg: seg_name,
        )
        fake_ida_funcs = SimpleNamespace(get_func=fake_get_func)
        fake_idaapi = SimpleNamespace(
            getseg=lambda _ea: seg_sentinel,
            add_func=fake_add_func,
        )

        namespace: dict[str, object] = {}
        with patch.dict(
            "sys.modules",
            {
                "ida_funcs": fake_ida_funcs,
                "ida_segment": fake_ida_segment,
                "idaapi": fake_idaapi,
            },
        ):
            exec(code, namespace)
        return json.loads(namespace["result"])

    async def test_unanalyzed_text_thunk_is_promoted_to_function(self) -> None:
        code = await self._capture_inspect_py_eval("0x5a8d30")
        payload = self._exec_inspect_py_eval(
            code,
            seg_name=".text",
            add_func_succeeds=True,
        )
        self.assertTrue(payload["has_segment"])
        self.assertEqual(".text", payload["segment_name"])
        self.assertTrue(payload["has_function"])
        self.assertEqual("0x5a8d30", payload["function_start"])
        self.assertTrue(payload["is_function_start"])

    async def test_non_function_address_still_reports_missing_function(self) -> None:
        code = await self._capture_inspect_py_eval("0x616050")
        payload = self._exec_inspect_py_eval(
            code,
            seg_name=".text",
            add_func_succeeds=False,
        )
        self.assertTrue(payload["has_segment"])
        self.assertFalse(payload["has_function"])
        self.assertFalse(payload["is_function_start"])


@patch.dict(
    "os.environ",
    {
        "CS2VIBE_LLM_FAKE_AS": "",
        "CS2VIBE_LLM_EFFORT": "",
    },
    clear=False,
)
class TestParseArgsLlmOptions(unittest.TestCase):
    def test_parse_vcall_finder_filter_preserves_order_and_deduplicates(self) -> None:
        selector = ida_analyze_bin.parse_vcall_finder_filter("g_pSecond, g_pFirst, g_pSecond")

        self.assertEqual({"names": ["g_pSecond", "g_pFirst"]}, selector)

    def test_parse_vcall_finder_filter_rejects_wildcard(self) -> None:
        with self.assertRaisesRegex(ValueError, "wildcard is not supported"):
            ida_analyze_bin.parse_vcall_finder_filter("*")

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14171")
    def test_parse_args_requires_explicit_modules_for_vcall_finder(self, _mock_resolve_oldgamever) -> None:
        with (
            patch(
                "sys.argv",
                ["ida_analyze_bin.py", "-gamever", "14172", "-vcall_finder", "g_pNetworkMessages"],
            ),
            patch("sys.stderr", new_callable=io.StringIO) as fake_stderr,
            self.assertRaises(SystemExit) as exc,
        ):
            ida_analyze_bin.parse_args()

        self.assertEqual(2, exc.exception.code)
        self.assertIn("requires explicit -modules", fake_stderr.getvalue())

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14171")
    def test_parse_args_accepts_explicit_vcall_modules_and_objects(self, _mock_resolve_oldgamever) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14172",
                "-modules",
                "server,engine",
                "-vcall_finder",
                "g_pFirst,g_pSecond",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual(["server", "engine"], args.module_filter)
        self.assertEqual({"names": ["g_pFirst", "g_pSecond"]}, args.vcall_finder_filter)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_accepts_skip_error(self, _mock_resolve_oldgamever) -> None:
        with patch(
            "sys.argv",
            ["ida_analyze_bin.py", "-gamever", "14141", "-skip_error"],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertTrue(args.skip_error)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_accepts_skip_pp(self, _mock_resolve_oldgamever) -> None:
        with patch(
            "sys.argv",
            ["ida_analyze_bin.py", "-gamever", "14141", "-skip_pp"],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertTrue(args.skip_pp)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_accepts_process_reporter_configuration(self, _mock_resolve_oldgamever) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-process_reporter",
                "redis",
                "-redis_url",
                "redis://example:6379/2",
                "-redis_prefix",
                "test:analysis",
                "-run_id",
                "scheduler-run",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("redis", args.process_reporter)
        self.assertEqual("redis://example:6379/2", args.redis_url)
        self.assertEqual("test:analysis", args.redis_prefix)
        self.assertEqual("scheduler-run", args.run_id)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_accepts_and_strips_skill(self, _mock_resolve_oldgamever) -> None:
        with patch(
            "sys.argv",
            ["ida_analyze_bin.py", "-gamever", "14141", "-skill", "  find-target  "],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("find-target", args.skill)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_rejects_empty_skill(self, _mock_resolve_oldgamever) -> None:
        with (
            patch(
                "sys.argv",
                ["ida_analyze_bin.py", "-gamever", "14141", "-skill", "   "],
            ),
            self.assertRaises(SystemExit),
        ):
            ida_analyze_bin.parse_args()

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_accepts_agent_model(self, _mock_resolve_oldgamever) -> None:
        with patch(
            "sys.argv",
            ["ida_analyze_bin.py", "-gamever", "14141", "-agent_model", "gpt-5.4"],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("gpt-5.4", args.agent_model)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_uses_agent_model_environment_default(self, _mock_resolve_oldgamever) -> None:
        with (
            patch.dict("os.environ", {"CS2VIBE_AGENT_MODEL": "openai/gpt-5.4"}, clear=False),
            patch("sys.argv", ["ida_analyze_bin.py", "-gamever", "14141"]),
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("openai/gpt-5.4", args.agent_model)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_accepts_llm_options(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-llm_model",
                "gpt-4.1-mini",
                "-llm_apikey",
                "test-api-key",
                "-llm_baseurl",
                "https://example.invalid/v1",
                "-llm_temperature",
                "0.25",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("gpt-4.1-mini", args.llm_model)
        self.assertEqual("test-api-key", args.llm_apikey)
        self.assertEqual("https://example.invalid/v1", args.llm_baseurl)
        self.assertEqual(0.25, args.llm_temperature)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_uses_env_llm_temperature_by_default(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with (
            patch.dict(
                "os.environ",
                {
                    "CS2VIBE_LLM_TEMPERATURE": "0.6",
                    "CS2VIBE_LLM_FAKE_AS": "",
                    "CS2VIBE_LLM_EFFORT": "",
                },
                clear=False,
            ),
            patch(
                "sys.argv",
                [
                    "ida_analyze_bin.py",
                    "-gamever",
                    "14141",
                ],
            ),
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual(0.6, args.llm_temperature)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_prefers_cli_llm_temperature_over_env(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with (
            patch.dict(
                "os.environ",
                {
                    "CS2VIBE_LLM_TEMPERATURE": "0.6",
                    "CS2VIBE_LLM_FAKE_AS": "",
                    "CS2VIBE_LLM_EFFORT": "",
                },
                clear=False,
            ),
            patch(
                "sys.argv",
                [
                    "ida_analyze_bin.py",
                    "-gamever",
                    "14141",
                    "-llm_temperature",
                    "0.3",
                ],
            ),
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual(0.3, args.llm_temperature)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_accepts_llm_fake_as_and_effort(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-llm_fake_as",
                "codex",
                "-llm_effort",
                "high",
                "-llm_temperature",
                "0.25",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("codex", args.llm_fake_as)
        self.assertEqual("high", args.llm_effort)
        self.assertEqual(0.25, args.llm_temperature)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_uses_env_llm_fake_as_and_default_effort(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with (
            patch.dict(
                "os.environ",
                {
                    "CS2VIBE_LLM_FAKE_AS": "codex",
                    "CS2VIBE_LLM_EFFORT": "",
                },
                clear=False,
            ),
            patch(
                "sys.argv",
                [
                    "ida_analyze_bin.py",
                    "-gamever",
                    "14141",
                ],
            ),
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("codex", args.llm_fake_as)
        self.assertEqual("medium", args.llm_effort)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_normalizes_blank_llm_fake_as_to_none(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-llm_fake_as",
                "   ",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertIsNone(args.llm_fake_as)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_normalizes_blank_llm_effort_to_medium(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-llm_effort",
                "   ",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("medium", args.llm_effort)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_prefers_cli_llm_effort_over_env(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with (
            patch.dict(
                "os.environ",
                {
                    "CS2VIBE_LLM_FAKE_AS": "",
                    "CS2VIBE_LLM_EFFORT": "low",
                },
                clear=False,
            ),
            patch(
                "sys.argv",
                [
                    "ida_analyze_bin.py",
                    "-gamever",
                    "14141",
                    "-llm_effort",
                    "xhigh",
                ],
            ),
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("xhigh", args.llm_effort)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_rejects_invalid_llm_fake_as(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with (
            patch(
                "sys.argv",
                [
                    "ida_analyze_bin.py",
                    "-gamever",
                    "14141",
                    "-llm_fake_as",
                    "openai",
                ],
            ),
            patch("sys.stderr", new_callable=io.StringIO) as fake_stderr,
        ):
            with self.assertRaises(SystemExit) as exc:
                ida_analyze_bin.parse_args()

        self.assertEqual(2, exc.exception.code)
        self.assertIn("Invalid LLM fake_as", fake_stderr.getvalue())

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_rejects_invalid_llm_effort(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with (
            patch(
                "sys.argv",
                [
                    "ida_analyze_bin.py",
                    "-gamever",
                    "14141",
                    "-llm_effort",
                    "turbo",
                ],
            ),
            patch("sys.stderr", new_callable=io.StringIO) as fake_stderr,
        ):
            with self.assertRaises(SystemExit) as exc:
                ida_analyze_bin.parse_args()

        self.assertEqual(2, exc.exception.code)
        self.assertIn("Invalid LLM effort", fake_stderr.getvalue())

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_rejects_legacy_vcall_finder_model(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with (
            patch(
                "sys.argv",
                [
                    "ida_analyze_bin.py",
                    "-gamever",
                    "14141",
                    "-vcall_finder_model",
                    "gpt-4o",
                ],
            ),
            patch("sys.stderr", new_callable=io.StringIO) as fake_stderr,
        ):
            with self.assertRaises(SystemExit) as exc:
                ida_analyze_bin.parse_args()

        self.assertEqual(2, exc.exception.code)
        self.assertIn("-vcall_finder_model", fake_stderr.getvalue())

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_defaults_rename_to_false(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertFalse(args.rename)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_accepts_rename(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-rename",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertTrue(args.rename)


class TestProcessBinaryLlmWiring(unittest.TestCase):
    def setUp(self) -> None:
        verify_patcher = patch.object(
            ida_analyze_bin,
            "verify_opened_binary_via_mcp",
            return_value=True,
        )
        self.mock_verify_opened_binary = verify_patcher.start()
        self.addCleanup(verify_patcher.stop)

    @patch("ida_analyze_bin.os.path.exists", return_value=False)
    @patch.object(ida_analyze_bin, "run_skill", return_value=False)
    @patch.object(
        ida_analyze_bin,
        "preprocess_single_skill_via_mcp",
        new_callable=AsyncMock,
        return_value=False,
    )
    @patch.object(ida_analyze_bin, "ensure_mcp_available")
    @patch.object(ida_analyze_bin, "start_idalib_mcp")
    @patch.object(ida_analyze_bin, "quit_ida_gracefully")
    def test_process_binary_passes_unified_llm_options_to_preprocess(
        self,
        _mock_quit_ida,
        mock_start_idalib_mcp,
        mock_ensure_mcp_available,
        mock_preprocess,
        _mock_run_skill,
        _mock_exists,
    ) -> None:
        fake_process = object()
        mock_start_idalib_mcp.return_value = fake_process
        mock_ensure_mcp_available.return_value = (fake_process, True)

        ida_analyze_bin.process_binary(
            binary_path="/tmp/bin/14141/networksystem/networksystem.dll",
            skills=[
                {
                    "name": "find-IGameSystem_vtable",
                    "expected_output": ["IGameSystem_vtable.{platform}.yaml"],
                    "expected_input": [],
                }
            ],
            agent="codex",
            host="127.0.0.1",
            port=13337,
            ida_args="",
            platform="windows",
            debug=False,
            max_retries=1,
            llm_model="gpt-4.1-mini",
            llm_apikey="test-api-key",
            llm_baseurl="https://example.invalid/v1",
            llm_temperature=0.4,
            llm_effort="high",
            llm_fake_as="codex",
        )

        self.assertEqual("gpt-4.1-mini", mock_preprocess.await_args.kwargs["llm_model"])
        self.assertEqual("test-api-key", mock_preprocess.await_args.kwargs["llm_apikey"])
        self.assertEqual(
            "https://example.invalid/v1",
            mock_preprocess.await_args.kwargs["llm_baseurl"],
        )
        self.assertEqual(0.4, mock_preprocess.await_args.kwargs["llm_temperature"])
        self.assertEqual("high", mock_preprocess.await_args.kwargs["llm_effort"])
        self.assertEqual("codex", mock_preprocess.await_args.kwargs["llm_fake_as"])

    @patch("ida_analyze_bin.os.path.exists", return_value=False)
    @patch.object(ida_analyze_bin, "run_skill", return_value=False)
    @patch.object(
        ida_analyze_bin,
        "preprocess_single_skill_via_mcp",
        new_callable=AsyncMock,
        return_value=False,
    )
    @patch.object(ida_analyze_bin, "ensure_mcp_available")
    @patch.object(ida_analyze_bin, "start_idalib_mcp")
    @patch.object(ida_analyze_bin, "quit_ida_gracefully")
    def test_process_binary_passes_skill_max_retries_to_preprocess(
        self,
        _mock_quit_ida,
        mock_start_idalib_mcp,
        mock_ensure_mcp_available,
        mock_preprocess,
        _mock_run_skill,
        _mock_exists,
    ) -> None:
        fake_process = object()
        mock_start_idalib_mcp.return_value = fake_process
        mock_ensure_mcp_available.return_value = (fake_process, True)

        ida_analyze_bin.process_binary(
            binary_path="/tmp/bin/14141/server/server.dll",
            skills=[
                {
                    "name": "find-IGameSystem_DestroyAllGameSystems",
                    "expected_output": ["IGameSystem_DestroyAllGameSystems.{platform}.yaml"],
                    "expected_input": [],
                    "max_retries": 4,
                }
            ],
            agent="codex",
            host="127.0.0.1",
            port=13337,
            ida_args="",
            platform="windows",
            debug=False,
            max_retries=2,
            llm_model="gpt-5.4",
            llm_fake_as="codex",
        )

        self.assertEqual(4, mock_preprocess.await_args.kwargs["llm_max_retries"])


class TestMainReporterLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch.object(ida_analyze_bin, "_load_config_document", return_value={})
        patcher.start()
        self.addCleanup(patcher.stop)

    @patch.object(ida_analyze_bin, "parse_config")
    @patch("ida_analyze_bin.os.path.exists", return_value=True)
    @patch.object(ida_analyze_bin, "parse_args")
    def test_main_finalizes_flushes_and_closes_reporter_after_exception(
        self,
        mock_parse_args,
        _mock_exists,
        mock_parse_config,
    ) -> None:
        mock_parse_args.return_value = SimpleNamespace(
            configyaml="configs/14168.yaml",
            bindir="bin",
            gamever="14141",
            oldgamever=None,
            platforms=["windows"],
            module_filter=None,
            modules="*",
            skill=None,
            agent="codex",
            agent_model="",
            ida_args="",
            debug=False,
            skip_error=False,
            skip_pp=False,
            maxretry=1,
            vcall_finder_filter=None,
            llm_model="gpt-4o",
            llm_apikey=None,
            llm_baseurl=None,
            llm_temperature=None,
            llm_effort="medium",
            llm_fake_as=None,
            rename=False,
            run_id="scheduler-run",
        )
        mock_parse_config.return_value = [
            {
                "stage_index": 3,
                "name": "engine",
                "skills": [{"name": "find-target", "expected_output": [], "expected_input": []}],
                "path_windows": "game/bin/win64/engine2.dll",
            }
        ]
        reporter = MagicMock()
        reporter.initialize_run.return_value = "scheduler-run"
        call_order = []
        reporter.initialize_run.side_effect = lambda *_args, **_kwargs: (
            call_order.append("initialize") or "scheduler-run"
        )

        def fail_processing(*_args, **_kwargs):
            call_order.append("process")
            raise RuntimeError("analysis crashed")

        with (
            patch.object(ida_analyze_bin, "create_process_reporter", return_value=reporter),
            patch.object(ida_analyze_bin, "process_binary", side_effect=fail_processing),
            self.assertRaisesRegex(RuntimeError, "analysis crashed"),
        ):
            ida_analyze_bin.main()

        self.assertEqual(["initialize", "process"], call_order)
        initialized_plan = reporter.initialize_run.call_args.args[0]
        self.assertEqual("stage-0003-engine-windows/find-target", initialized_plan["nodes"][0]["id"])
        self.assertEqual(RunStatus.FAILED, reporter.finalize_run.call_args.args[1])
        reporter.flush.assert_called_once()
        reporter.close.assert_called_once()


class TestMainLlmWiring(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch.object(ida_analyze_bin, "_load_config_document", return_value={})
        patcher.start()
        self.addCleanup(patcher.stop)

    @patch.object(ida_analyze_bin, "process_binary")
    @patch.object(ida_analyze_bin, "parse_config")
    @patch("ida_analyze_bin.os.path.exists", return_value=True)
    @patch.object(ida_analyze_bin, "parse_args")
    def test_main_passes_unified_llm_options_to_vcall_aggregation(
        self,
        mock_parse_args,
        _mock_exists,
        mock_parse_config,
        mock_process_binary,
    ) -> None:
        captured = {}

        def fake_aggregate_vcall_results_for_object(
            *,
            base_dir,
            gamever,
            object_name,
            model,
            api_key=None,
            base_url=None,
            temperature=None,
            effort=None,
            fake_as=None,
            client=None,
            debug=False,
        ):
            captured["kwargs"] = {
                "base_dir": base_dir,
                "gamever": gamever,
                "object_name": object_name,
                "model": model,
                "api_key": api_key,
                "base_url": base_url,
                "temperature": temperature,
                "effort": effort,
                "fake_as": fake_as,
                "client": client,
                "debug": debug,
            }
            return {"status": "success", "processed": 1, "failed": 0}

        mock_parse_args.return_value = SimpleNamespace(
            configyaml="configs/14168.yaml",
            bindir="bin",
            gamever="14141",
            oldgamever=None,
            platforms=["windows"],
            module_filter=["networksystem"],
            modules="networksystem",
            agent="codex",
            ida_args="",
            debug=False,
            maxretry=3,
            vcall_finder_filter={"names": ["g_pNetworkMessages"]},
            llm_model="gpt-4.1-mini",
            llm_apikey="test-api-key",
            llm_baseurl="https://example.invalid/v1",
            llm_temperature=0.5,
            llm_effort="high",
            llm_fake_as="codex",
            rename=False,
        )
        mock_parse_config.return_value = [
            {
                "name": "networksystem",
                "skills": [],
                "path_windows": "game/bin/win64/networksystem.dll",
            }
        ]

        def mark_object_found(*_args, **kwargs):
            kwargs["found_vcall_objects"].add("g_pNetworkMessages")
            return (0, 0, 0)

        mock_process_binary.side_effect = mark_object_found

        with patch.object(
            ida_analyze_bin,
            "aggregate_vcall_results_for_object",
            new=fake_aggregate_vcall_results_for_object,
        ):
            ida_analyze_bin.main()

        self.assertEqual(
            {
                "base_dir": "vcall_finder",
                "gamever": "14141",
                "object_name": "g_pNetworkMessages",
                "model": "gpt-4.1-mini",
                "api_key": "test-api-key",
                "base_url": "https://example.invalid/v1",
                "temperature": 0.5,
                "effort": "high",
                "fake_as": "codex",
                "client": None,
                "debug": False,
            },
            captured["kwargs"],
        )

    def test_vcall_aggregation_fails_when_object_was_not_found(self) -> None:
        args = SimpleNamespace(vcall_finder_filter={"names": ["g_pMissing"]})

        with patch.object(ida_analyze_bin, "_aggregate_vcall_object") as aggregate:
            counts = ida_analyze_bin._run_vcall_aggregation(args, ["g_pMissing"], set())

        self.assertEqual([0, 1, 0], counts)
        aggregate.assert_not_called()

    @patch.object(ida_analyze_bin, "parse_config")
    @patch("ida_analyze_bin.os.path.exists", return_value=True)
    @patch.object(ida_analyze_bin, "parse_args")
    def test_main_aborts_after_process_binary_failure_and_skips_later_work(
        self,
        mock_parse_args,
        _mock_exists,
        mock_parse_config,
    ) -> None:
        mock_parse_args.return_value = SimpleNamespace(
            configyaml="configs/14168.yaml",
            bindir="bin",
            gamever="14141",
            oldgamever=None,
            platforms=["windows"],
            module_filter=["engine", "server"],
            modules="engine,server",
            agent="codex",
            ida_args="",
            debug=False,
            maxretry=3,
            vcall_finder_filter={"names": ["g_pFirst", "g_pSecond"]},
            llm_model="gpt-4.1-mini",
            llm_apikey=None,
            llm_baseurl=None,
            llm_temperature=None,
            llm_effort="high",
            llm_fake_as="codex",
            rename=False,
        )
        mock_parse_config.return_value = [
            {
                "name": "engine",
                "skills": [
                    {
                        "name": "find-first",
                        "expected_output": ["First.{platform}.yaml"],
                        "expected_input": [],
                    }
                ],
                "path_windows": "game/bin/win64/engine2.dll",
            },
            {
                "name": "server",
                "skills": [
                    {
                        "name": "find-second",
                        "expected_output": ["Second.{platform}.yaml"],
                        "expected_input": [],
                    }
                ],
                "path_windows": "game/bin/win64/server.dll",
            },
        ]

        with (
            patch.object(ida_analyze_bin, "process_binary", return_value=(0, 1, 0)) as mock_process,
            patch.object(ida_analyze_bin, "aggregate_vcall_results_for_object") as mock_aggregate,
            self.assertRaises(SystemExit) as exit_context,
        ):
            ida_analyze_bin.main()

        self.assertEqual(1, exit_context.exception.code)
        self.assertEqual(1, mock_process.call_count)
        mock_aggregate.assert_not_called()

    @patch.object(ida_analyze_bin, "parse_config")
    @patch("ida_analyze_bin.os.path.exists", return_value=True)
    @patch.object(ida_analyze_bin, "parse_args")
    def test_main_continues_after_process_binary_failure_when_skip_error_enabled(
        self,
        mock_parse_args,
        _mock_exists,
        mock_parse_config,
    ) -> None:
        mock_parse_args.return_value = SimpleNamespace(
            configyaml="configs/14168.yaml",
            bindir="bin",
            gamever="14141",
            oldgamever=None,
            platforms=["windows"],
            module_filter=["engine", "server"],
            modules="engine,server",
            agent="codex",
            ida_args="",
            debug=False,
            maxretry=3,
            vcall_finder_filter={"names": ["g_pFirst", "g_pSecond"]},
            llm_model="gpt-4.1-mini",
            llm_apikey=None,
            llm_baseurl=None,
            llm_temperature=None,
            llm_effort="high",
            llm_fake_as="codex",
            rename=False,
            skip_error=True,
        )
        mock_parse_config.return_value = [
            {
                "name": "engine",
                "skills": [{"name": "find-first", "expected_output": [], "expected_input": []}],
                "path_windows": "game/bin/win64/engine2.dll",
            },
            {
                "name": "server",
                "skills": [{"name": "find-second", "expected_output": [], "expected_input": []}],
                "path_windows": "game/bin/win64/server.dll",
            },
        ]

        def fail_but_mark_objects_found(*_args, **kwargs):
            kwargs["found_vcall_objects"].update(kwargs["vcall_targets"])
            return (0, 1, 0)

        with (
            patch.object(ida_analyze_bin, "process_binary", side_effect=fail_but_mark_objects_found) as mock_process,
            patch.object(
                ida_analyze_bin,
                "aggregate_vcall_results_for_object",
                return_value={"status": "success", "processed": 1, "failed": 0},
            ) as mock_aggregate,
            self.assertRaises(SystemExit) as exit_context,
        ):
            ida_analyze_bin.main()

        self.assertEqual(1, exit_context.exception.code)
        self.assertEqual(2, mock_process.call_count)
        self.assertEqual(2, mock_aggregate.call_count)


class TestMainPostProcessWiring(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch.object(ida_analyze_bin, "_load_config_document", return_value={})
        patcher.start()
        self.addCleanup(patcher.stop)

    @patch.object(ida_analyze_bin, "parse_config")
    @patch("ida_analyze_bin.os.path.exists", return_value=True)
    @patch.object(ida_analyze_bin, "parse_args")
    def test_main_passes_rename_to_process_binary(
        self,
        mock_parse_args,
        _mock_exists,
        mock_parse_config,
    ) -> None:
        captured = {}

        def fake_process_binary(*args, **kwargs):
            captured["kwargs"] = kwargs
            return (0, 0, 0)

        mock_parse_args.return_value = SimpleNamespace(
            configyaml="configs/14168.yaml",
            bindir="bin",
            gamever="14141",
            oldgamever=None,
            platforms=["windows"],
            module_filter=None,
            modules="*",
            agent="codex",
            ida_args="",
            debug=False,
            maxretry=3,
            vcall_finder_filter=None,
            llm_model="gpt-4.1-mini",
            llm_apikey=None,
            llm_baseurl=None,
            llm_temperature=None,
            llm_effort="high",
            llm_fake_as="codex",
            rename=True,
            skip_pp=True,
        )
        mock_parse_config.return_value = [
            {
                "name": "server",
                "skills": [
                    {
                        "name": "find-CEntFireOutputAutoCompletionFunctor_FireOutput",
                        "expected_output": ["CEntFireOutputAutoCompletionFunctor_FireOutput.{platform}.yaml"],
                        "expected_input": [],
                    }
                ],
                "path_windows": "game/bin/win64/server.dll",
            }
        ]

        with patch.object(ida_analyze_bin, "process_binary", new=fake_process_binary):
            ida_analyze_bin.main()

        self.assertTrue(captured["kwargs"]["rename"])
        self.assertTrue(captured["kwargs"]["skip_pp"])


class TestMainSkillFilterWiring(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch.object(ida_analyze_bin, "_load_config_document", return_value={})
        patcher.start()
        self.addCleanup(patcher.stop)

    @patch.object(ida_analyze_bin, "process_binary", return_value=(1, 0, 0))
    @patch.object(ida_analyze_bin, "parse_config")
    @patch("ida_analyze_bin.os.path.exists", return_value=True)
    @patch.object(ida_analyze_bin, "parse_args")
    def test_main_runs_only_exact_skill_matches(
        self,
        mock_parse_args,
        _mock_exists,
        mock_parse_config,
        mock_process_binary,
    ) -> None:
        mock_parse_args.return_value = SimpleNamespace(
            configyaml="configs/14168.yaml",
            bindir="bin",
            gamever="14141",
            oldgamever=None,
            platforms=["windows"],
            module_filter=None,
            modules="*",
            skill="find-target",
            agent="codex",
            agent_model="gpt-5.4",
            ida_args="",
            debug=False,
            skip_error=False,
            skip_pp=False,
            maxretry=3,
            vcall_finder_filter=None,
            llm_model="gpt-4o",
            llm_apikey=None,
            llm_baseurl=None,
            llm_temperature=None,
            llm_effort="medium",
            llm_fake_as=None,
            rename=False,
        )
        mock_parse_config.return_value = [
            {
                "name": "client",
                "skills": [{"name": "find-other"}],
                "path_windows": "game/bin/win64/client.dll",
            },
            {
                "name": "server",
                "skills": [{"name": "find-target"}, {"name": "find-other"}],
                "path_windows": "game/bin/win64/server.dll",
            },
        ]

        ida_analyze_bin.main()

        mock_process_binary.assert_called_once()
        selected_skills = mock_process_binary.call_args.args[1]
        self.assertEqual(["find-target"], [skill["name"] for skill in selected_skills])


if __name__ == "__main__":
    unittest.main()

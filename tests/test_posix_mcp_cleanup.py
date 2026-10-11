import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import ida_analyze_bin as analysis


@unittest.skipUnless(os.name == "posix", "POSIX process groups")
class TestPosixMcpCleanup(unittest.TestCase):
    def run_tree(self, *, ignore_term=False, parent_exits=False):
        with tempfile.TemporaryDirectory() as temporary:
            port = analysis._allocate_local_port()
            child = (
                "import signal,socket,time; "
                + ("signal.signal(signal.SIGTERM, signal.SIG_IGN); " if ignore_term else "")
                + f"s=socket.socket(); s.bind(('127.0.0.1',{port})); s.listen(); time.sleep(60)"
            )
            parent = (
                "import subprocess,sys,time; "
                + f"subprocess.Popen([sys.executable,'-c',{child!r}]); "
                + ("sys.exit(0)" if parent_exits else "time.sleep(60)")
            )
            child_process = subprocess.Popen([sys.executable, "-c", parent], start_new_session=True)
            process = analysis.ManagedMcpProcess(
                child_process, Path(temporary) / "dummy", "127.0.0.1", port, frozenset(), False, child_process.pid
            )
            unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            try:
                deadline = time.monotonic() + 5
                while not analysis.is_port_in_use("127.0.0.1", port):
                    if time.monotonic() >= deadline:
                        self.fail("test worker did not start")
                    time.sleep(0.02)
                if parent_exits:
                    process.wait(timeout=5)
                with patch.object(analysis, "MCP_SHUTDOWN_TIMEOUT", 0.3):
                    analysis.stop_idalib_mcp_process(process)
                    analysis.stop_idalib_mcp_process(process)
                self.assertFalse(analysis.is_port_in_use("127.0.0.1", port))
                self.assertIsNone(process.pgid)
                self.assertIsNone(unrelated.poll())
            finally:
                try:
                    os.killpg(child_process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child_process.wait(timeout=5)
                unrelated.kill()
                unrelated.wait(timeout=5)

    def test_descendant_listener_is_reclaimed(self):
        self.run_tree()

    def test_sigterm_ignoring_worker_is_reclaimed(self):
        self.run_tree(ignore_term=True)

    def test_exited_supervisor_does_not_hide_live_worker(self):
        self.run_tree(parent_exits=True, ignore_term=True)

    def test_permission_error_fails_without_quarantining_database(self):
        child = Mock()
        process = analysis.ManagedMcpProcess(child, Path("dummy"), "127.0.0.1", 12345, frozenset(), False, 12345)
        with (
            patch.object(os, "killpg", side_effect=PermissionError("denied")),
            patch.object(analysis, "_settle_unpacked_ida_database") as settle,
        ):
            with self.assertRaises(analysis.McpCleanupError):
                analysis.stop_idalib_mcp_process(process)
            settle.assert_not_called()

    def test_start_failure_and_cancellation_clean_the_owned_group(self):
        for failure in (RuntimeError("startup failed"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                child = Mock(pid=12345)
                with (
                    patch.object(analysis, "is_port_in_use", return_value=False),
                    patch.object(analysis.subprocess, "Popen", return_value=child) as launch,
                    patch.object(analysis, "wait_for_port", side_effect=failure),
                    patch.object(analysis, "stop_idalib_mcp_process") as stop,
                ):
                    if isinstance(failure, KeyboardInterrupt):
                        with self.assertRaises(KeyboardInterrupt):
                            analysis.start_idalib_mcp("dummy")
                    else:
                        self.assertIsNone(analysis.start_idalib_mcp("dummy"))
                    self.assertTrue(launch.call_args.kwargs["start_new_session"])
                    self.assertEqual(12345, stop.call_args.args[0].pgid)

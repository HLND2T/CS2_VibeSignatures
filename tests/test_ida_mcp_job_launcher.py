"""Windows Job ownership tests that do not require IDA."""

from __future__ import annotations

import ctypes
import json
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import ida_mcp_job_launcher
from windows_job import Kernel32JobApi


class _FakeJobApi:
    def __init__(self, *, fail_on_assign: bool = False) -> None:
        self.calls: list[str] = []
        self.fail_on_assign = fail_on_assign

    def open_live_process(self, pid):
        self.calls.append(f"parent:{pid}")
        return 11

    def create_job(self):
        self.calls.append("create")
        return 22

    def set_kill_on_close(self, handle):
        self.calls.append("limit")

    def assign_current_process(self, handle):
        self.calls.append("assign")
        if self.fail_on_assign:
            raise OSError("nested Job rejected")

    def close_handle(self, handle):
        self.calls.append("close")


class TestIdaMcpJobLauncher(unittest.TestCase):
    def test_job_is_ready_before_server_is_spawned(self) -> None:
        api = _FakeJobApi()
        child = MagicMock()
        child.wait.return_value = 0

        def spawn(*args, **kwargs):
            api.calls.append("spawn")
            self.assertTrue(kwargs["close_fds"])
            return child

        with (
            patch.object(ida_mcp_job_launcher.threading, "Thread"),
            patch.object(ida_mcp_job_launcher.subprocess, "Popen", side_effect=spawn),
        ):
            result = ida_mcp_job_launcher.run(1234, ["idalib-mcp"], api=api)

        self.assertEqual(0, result)
        self.assertEqual(["parent:1234", "create", "limit", "assign", "spawn", "close"], api.calls)

    def test_job_assignment_failure_never_spawns_server(self) -> None:
        api = _FakeJobApi(fail_on_assign=True)
        with patch.object(ida_mcp_job_launcher.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(OSError, "nested Job rejected"):
                ida_mcp_job_launcher.run(1234, ["idalib-mcp"], api=api)

        popen.assert_not_called()
        self.assertEqual(["parent:1234", "create", "limit", "assign", "close"], api.calls)

    @unittest.skipUnless(os.name == "nt", "Windows Job integration test")
    def test_parent_exit_reaps_owned_worker(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            worker_script = root / "worker.py"
            parent_script = root / "parent.py"
            marker = root / "worker.pid"
            worker_script.write_text(
                "import os, sys, time\nfrom pathlib import Path\n"
                "Path(sys.argv[1]).write_text(str(os.getpid()))\ntime.sleep(60)\n",
                encoding="utf-8",
            )
            parent_script.write_text(
                "import os, subprocess, sys, time\nfrom pathlib import Path\n"
                "launcher, worker, marker = sys.argv[1:4]\n"
                "subprocess.Popen([sys.executable, launcher, '--parent-pid', str(os.getpid()), '--', "
                "sys.executable, worker, marker], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                "deadline = time.monotonic() + 10\n"
                "while not Path(marker).exists() and time.monotonic() < deadline: time.sleep(0.05)\n"
                "assert Path(marker).exists(), 'worker did not start'\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(parent_script),
                    str(Path(ida_mcp_job_launcher.__file__)),
                    str(worker_script),
                    str(marker),
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            worker_pid = int(marker.read_text(encoding="utf-8"))
            try:
                deadline = time.monotonic() + 10
                while _process_alive(worker_pid) and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertFalse(_process_alive(worker_pid), "worker survived its analyzer parent")
            finally:
                if _process_alive(worker_pid):
                    _terminate_test_process(worker_pid)

    @unittest.skipUnless(os.name == "nt", "Windows Job integration test")
    def test_detached_worker_dies_when_supervisor_exits_or_launcher_is_stopped(self) -> None:
        child_source = """
import ctypes, json, os, socket, sys, time
from pathlib import Path
lock_path, marker_path = sys.argv[1:3]
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
kernel32.CreateFileW.restype = ctypes.c_void_p
handle = kernel32.CreateFileW(lock_path, 0xC0000000, 0, None, 4, 0, None)
if handle == ctypes.c_void_p(-1).value:
    raise ctypes.WinError(ctypes.get_last_error())
listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.listen()
Path(marker_path).write_text(json.dumps({'pid': os.getpid(), 'port': listener.getsockname()[1]}))
while True:
    time.sleep(0.2)
"""
        supervisor_source = """
import subprocess, sys, time
from pathlib import Path
mode, child_path, lock_path, marker_path = sys.argv[1:5]
subprocess.Popen([sys.executable, child_path, lock_path, marker_path], creationflags=subprocess.CREATE_NEW_PROCESS_GROUP, close_fds=True)
deadline = time.monotonic() + 10
while not Path(marker_path).exists() and time.monotonic() < deadline:
    time.sleep(0.05)
if not Path(marker_path).exists():
    raise RuntimeError('worker did not start')
if mode == 'hold':
    time.sleep(60)
"""
        for mode in ("early", "hold"):
            with self.subTest(mode=mode), TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                child_script = root / "worker.py"
                supervisor_script = root / "supervisor.py"
                marker = root / "worker.json"
                lock_file = root / "database.id0"
                child_script.write_text(child_source, encoding="utf-8")
                supervisor_script.write_text(supervisor_source, encoding="utf-8")
                launcher = subprocess.Popen(
                    [
                        sys.executable,
                        str(Path(ida_mcp_job_launcher.__file__)),
                        "--parent-pid",
                        str(os.getpid()),
                        "--",
                        sys.executable,
                        str(supervisor_script),
                        mode,
                        str(child_script),
                        str(lock_file),
                        str(marker),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                worker_pid = None
                try:
                    deadline = time.monotonic() + 10
                    while not marker.exists() and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertTrue(marker.exists(), "detached worker never started")
                    details = json.loads(marker.read_text(encoding="utf-8"))
                    worker_pid = int(details["pid"])
                    if mode == "hold":
                        self.assertFalse(_port_available(details["port"]))
                        self.assertFalse(_exclusive_file_available(lock_file))
                        launcher.terminate()
                    launcher.wait(timeout=10)
                    deadline = time.monotonic() + 10
                    while _process_alive(worker_pid) and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertFalse(_process_alive(worker_pid), "detached worker survived its Job")
                    self.assertTrue(_port_available(details["port"]))
                    self.assertTrue(_exclusive_file_available(lock_file))
                finally:
                    if launcher.poll() is None:
                        launcher.terminate()
                        launcher.wait(timeout=5)
                    if worker_pid is not None and _process_alive(worker_pid):
                        _terminate_test_process(worker_pid)


def _process_alive(pid: int) -> bool:
    api = Kernel32JobApi()
    try:
        handle = api.open_live_process(pid)
    except (OSError, ProcessLookupError):
        return False
    api.close_handle(handle)
    return True


def _port_available(port: int) -> bool:
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _exclusive_file_available(path: Path) -> bool:
    import ida_analyze_bin

    return ida_analyze_bin._ida_file_exclusively_available(path)


def _terminate_test_process(pid: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.OpenProcess(0x0001, False, pid)
    if handle:
        try:
            kernel32.TerminateProcess(handle, 1)
        finally:
            kernel32.CloseHandle(handle)

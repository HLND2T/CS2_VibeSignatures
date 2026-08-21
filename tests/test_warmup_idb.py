import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from warmup_memory import MemoryLaunchGate, MemorySnapshot, WindowsJobMemoryController

SCRIPT = Path("warmup_idb.py")
SPEC = importlib.util.spec_from_file_location("warmup_idb", SCRIPT)
warmup_idb = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(warmup_idb)


def _warm_worker_script(source: str) -> Path:
    fd, path = tempfile.mkstemp(prefix="warmup_worker_", suffix=".py")
    with open(fd, "w", encoding="utf-8") as handle:
        handle.write(source)
    return Path(path)


class FakeWindowsJobApi:
    def __init__(self, *, assign_error: OSError | None = None) -> None:
        self.assign_error = assign_error
        self.calls = []

    def create_job(self):
        self.calls.append(("create",))
        return 123

    def set_job_memory_limit(self, handle, budget_bytes):
        self.calls.append(("limit", handle, budget_bytes))

    def assign_current_process(self, handle):
        self.calls.append(("assign", handle))
        if self.assign_error is not None:
            raise self.assign_error

    def query_job_memory(self, handle):
        self.calls.append(("job-memory", handle))
        return 256

    def close_handle(self, handle):
        self.calls.append(("close", handle))


class TestWarmupIdbHelpers(unittest.TestCase):
    def test_main_enables_memory_controller_and_passes_gate_to_workers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "engine2.dll"
            binary.write_bytes(b"MZ")
            controller = MagicMock()
            controller.snapshot.return_value = MemorySnapshot(job_bytes=256 * warmup_idb.MIB)
            gate = MagicMock()
            gate.soft_limit_bytes = int(32768 * warmup_idb.MIB * 0.85)

            with (
                patch.object(warmup_idb.shutil, "which", return_value=sys.executable),
                patch.object(warmup_idb, "resolve_analysis_config", return_value=Path("config.yaml")),
                patch.object(
                    warmup_idb,
                    "iter_configured_binaries",
                    return_value=[("engine", "windows", binary)],
                ),
                patch.object(warmup_idb, "_is_warm", return_value=False),
                patch.object(warmup_idb, "WindowsJobMemoryController", return_value=controller) as controller_type,
                patch.object(warmup_idb, "MemoryLaunchGate", return_value=gate) as gate_type,
                patch.object(warmup_idb, "_warm_one", return_value=True) as warm_one,
            ):
                result = warmup_idb.main(
                    [
                        "14176",
                        "--python",
                        sys.executable,
                        "--worker-script",
                        str(Path("warmup_idb_worker.py").resolve()),
                        "--max-memory-mib",
                        "32768",
                    ]
                )

            self.assertEqual(0, result)
            controller_type.assert_called_once_with(32768 * warmup_idb.MIB)
            self.assertEqual(256 * warmup_idb.MIB, gate_type.call_args.kwargs["baseline_job_bytes"])
            self.assertIs(controller.snapshot, gate_type.call_args.kwargs["snapshot"])
            self.assertEqual(1, warm_one.call_count)
            self.assertIs(gate, warm_one.call_args.args[4])

    def test_main_does_not_launch_workers_when_job_setup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "engine2.dll"
            binary.write_bytes(b"MZ")

            with (
                patch.object(warmup_idb.shutil, "which", return_value=sys.executable),
                patch.object(warmup_idb, "resolve_analysis_config", return_value=Path("config.yaml")),
                patch.object(
                    warmup_idb,
                    "iter_configured_binaries",
                    return_value=[("engine", "windows", binary)],
                ),
                patch.object(warmup_idb, "_is_warm", return_value=False),
                patch.object(
                    warmup_idb,
                    "WindowsJobMemoryController",
                    side_effect=OSError("nested job rejected"),
                ),
                patch.object(warmup_idb, "_warm_one") as warm_one,
            ):
                result = warmup_idb.main(
                    [
                        "14176",
                        "--python",
                        sys.executable,
                        "--worker-script",
                        str(Path("warmup_idb_worker.py").resolve()),
                        "--max-memory-mib",
                        "32768",
                    ]
                )

            self.assertEqual(1, result)
            warm_one.assert_not_called()

    def test_parse_memory_budget_accepts_unset_and_positive_mib(self) -> None:
        self.assertIsNone(warmup_idb._parse_memory_budget_mib(None))
        self.assertIsNone(warmup_idb._parse_memory_budget_mib(""))
        self.assertEqual(32768, warmup_idb._parse_memory_budget_mib(" 32768 "))
        with self.assertRaisesRegex(ValueError, "positive integer"):
            warmup_idb._parse_memory_budget_mib("0")
        with self.assertRaisesRegex(ValueError, "positive integer"):
            warmup_idb._parse_memory_budget_mib("invalid")

    def test_memory_gate_waits_for_job_headroom(self) -> None:
        snapshots = iter(
            [
                MemorySnapshot(job_bytes=80),
                MemorySnapshot(job_bytes=20),
            ]
        )
        gate = MemoryLaunchGate(
            snapshot=lambda: next(snapshots),
            budget_bytes=100,
            baseline_job_bytes=0,
            soft_limit_ratio=0.85,
            initial_worker_reservation_bytes=20,
            poll_interval_seconds=0,
            launch_interval_seconds=0,
        )

        output = StringIO()
        with redirect_stdout(output):
            gate.wait_for_launch("engine2.dll")
            gate.worker_finished()

        self.assertIn("memory pressure; delaying engine2.dll", output.getvalue())
        self.assertIn("memory recovered; launching engine2.dll", output.getvalue())

    def test_windows_job_controller_sets_limit_before_assigning(self) -> None:
        api = FakeWindowsJobApi()
        controller = WindowsJobMemoryController(4096, api=api)

        self.assertEqual(
            [("create",), ("limit", 123, 4096), ("assign", 123)],
            api.calls,
        )
        self.assertEqual(MemorySnapshot(job_bytes=256), controller.snapshot())

    def test_windows_job_controller_closes_unassigned_job_on_failure(self) -> None:
        api = FakeWindowsJobApi(assign_error=OSError("nested job rejected"))

        with self.assertRaisesRegex(OSError, "nested job rejected"):
            WindowsJobMemoryController(4096, api=api)

        self.assertEqual(("close", 123), api.calls[-1])

    @unittest.skipUnless(os.name == "nt", "Windows Job Object integration test")
    def test_windows_job_controller_smoke_in_child_process(self) -> None:
        source = (
            "import subprocess\n"
            "import sys\n"
            "from warmup_memory import WindowsJobMemoryController\n"
            "controller = WindowsJobMemoryController(1024 * 1024 * 1024)\n"
            "baseline = controller.snapshot()\n"
            'child_source = "import time; data = bytearray(64 * 1024 * 1024); print(len(data), flush=True); time.sleep(10)"\n'
            "child = subprocess.Popen([sys.executable, '-c', child_source], stdout=subprocess.PIPE, text=True)\n"
            "try:\n"
            "    assert child.stdout is not None\n"
            "    assert child.stdout.readline().strip() == str(64 * 1024 * 1024)\n"
            "    snapshot = controller.snapshot()\n"
            "    assert snapshot.job_bytes >= baseline.job_bytes + 32 * 1024 * 1024\n"
            "finally:\n"
            "    child.terminate()\n"
            "    child.wait(timeout=5)\n"
            "print('ok', flush=True)\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", source],
            cwd=Path.cwd(),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr or result.stdout)
        self.assertEqual("ok", result.stdout.strip())

    def test_is_warm_requires_packed_db_and_no_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "engine2.dll"
            binary.write_bytes(b"MZ")

            self.assertFalse(warmup_idb._is_warm(binary))

            Path(f"{binary}.i64").write_bytes(b"db")
            self.assertTrue(warmup_idb._is_warm(binary))

            Path(f"{binary}.id0").write_bytes(b"lock")
            self.assertFalse(warmup_idb._is_warm(binary))

    def test_force_invalidates_existing_database_before_warming(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "engine2.dll"
            binary.write_bytes(b"MZ")
            Path(f"{binary}.i64").write_bytes(b"old-db")

            def warm_one(_python, _worker, binary_path, _timeout, _gate):
                Path(f"{binary_path}.i64").write_bytes(b"new-db")
                return True

            with (
                patch.object(warmup_idb.shutil, "which", return_value=sys.executable),
                patch.object(warmup_idb, "resolve_analysis_config", return_value=Path("config.yaml")),
                patch.object(
                    warmup_idb,
                    "iter_configured_binaries",
                    return_value=[("engine", "windows", binary)],
                ),
                patch.object(warmup_idb, "_warm_one", side_effect=warm_one) as warm,
            ):
                result = warmup_idb.main(
                    [
                        "14180",
                        "--python",
                        sys.executable,
                        "--worker-script",
                        str(Path("warmup_idb_worker.py").resolve()),
                        "--force",
                    ]
                )

            self.assertEqual(0, result)
            warm.assert_called_once()
            self.assertEqual(b"new-db", Path(f"{binary}.i64").read_bytes())

    def test_parse_concurrency_defaults_and_clamps(self) -> None:
        self.assertEqual(warmup_idb._parse_concurrency(None), 2)
        self.assertEqual(warmup_idb._parse_concurrency(""), 2)
        self.assertEqual(warmup_idb._parse_concurrency("3"), 3)
        self.assertEqual(warmup_idb._parse_concurrency("0"), 2)
        self.assertEqual(warmup_idb._parse_concurrency("-1"), 2)
        self.assertEqual(warmup_idb._parse_concurrency("abc"), 2)

    def test_invalidate_removes_database_side_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "server.dll"
            binary.write_bytes(b"MZ")
            for suffix in (".i64", ".id0", ".id1"):
                Path(f"{binary}{suffix}").write_bytes(b"x")

            removed, failures = warmup_idb._invalidate_ida_database(binary)

            self.assertCountEqual(
                [str(Path(f"{binary}{suffix}")) for suffix in (".i64", ".id0", ".id1")],
                removed,
            )
            self.assertEqual([], failures)
            self.assertFalse(Path(f"{binary}.i64").exists())
            self.assertFalse(Path(f"{binary}.id0").exists())
            self.assertFalse(Path(f"{binary}.id1").exists())
            self.assertTrue(binary.exists())

    def test_invalidate_retries_and_reports_residual_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "server.dll"
            binary.write_bytes(b"MZ")
            database = Path(f"{binary}.i64")
            database.write_bytes(b"locked")
            original_unlink = Path.unlink

            def fail_database_unlink(path: Path, *args, **kwargs):
                if path == database:
                    raise PermissionError("locked")
                return original_unlink(path, *args, **kwargs)

            with (
                patch.object(Path, "unlink", autospec=True, side_effect=fail_database_unlink) as unlink,
                patch.object(warmup_idb.time, "sleep") as sleep,
            ):
                removed, failures = warmup_idb._invalidate_ida_database(binary)

            self.assertEqual([], removed)
            self.assertEqual(1, len(failures))
            self.assertIn(str(database), failures[0])
            self.assertEqual(
                len(warmup_idb._ida_database_paths(binary)) * warmup_idb.INVALIDATION_MAX_ATTEMPTS,
                unlink.call_count,
            )
            self.assertEqual(warmup_idb.INVALIDATION_MAX_ATTEMPTS - 1, sleep.call_count)

    def test_warm_one_success_leaves_packed_database(self) -> None:
        worker = _warm_worker_script(
            "import sys\nfrom pathlib import Path\nPath(sys.argv[1] + '.i64').write_bytes(b'warm')\n"
        )
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                binary = Path(temp_dir) / "engine2.dll"
                binary.write_bytes(b"MZ")

                self.assertTrue(warmup_idb._warm_one(sys.executable, worker, binary))
                self.assertTrue(Path(f"{binary}.i64").exists())
        finally:
            worker.unlink(missing_ok=True)

    def test_warm_one_failure_invalidates_database(self) -> None:
        worker = _warm_worker_script("import sys\nsys.exit(1)\n")
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                binary = Path(temp_dir) / "engine2.dll"
                binary.write_bytes(b"MZ")
                Path(f"{binary}.i64").write_bytes(b"stale")
                Path(f"{binary}.id0").write_bytes(b"stale-lock")

                self.assertFalse(warmup_idb._warm_one(sys.executable, worker, binary))
                self.assertFalse(Path(f"{binary}.i64").exists())
                self.assertFalse(Path(f"{binary}.id0").exists())
        finally:
            worker.unlink(missing_ok=True)

    def test_warm_one_timeout_invalidates_database(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "engine2.dll"
            binary.write_bytes(b"MZ")
            Path(f"{binary}.id0").write_bytes(b"stale-lock")

            with patch.object(
                warmup_idb.subprocess,
                "run",
                side_effect=warmup_idb.subprocess.TimeoutExpired([sys.executable, "worker.py"], 5),
            ):
                self.assertFalse(warmup_idb._warm_one(sys.executable, Path("worker.py"), binary, timeout_seconds=5))

            self.assertFalse(Path(f"{binary}.id0").exists())

    def test_warm_one_spawn_error_invalidates_database(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "engine2.dll"
            binary.write_bytes(b"MZ")
            Path(f"{binary}.id0").write_bytes(b"stale-lock")

            with patch.object(warmup_idb.subprocess, "run", side_effect=OSError("cannot start process")):
                self.assertFalse(warmup_idb._warm_one(sys.executable, Path("worker.py"), binary))

            self.assertFalse(Path(f"{binary}.id0").exists())


if __name__ == "__main__":
    unittest.main()

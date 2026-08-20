import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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


class TestWarmupIdbHelpers(unittest.TestCase):
    def test_is_warm_requires_packed_db_and_no_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "engine2.dll"
            binary.write_bytes(b"MZ")

            self.assertFalse(warmup_idb._is_warm(binary))

            Path(f"{binary}.i64").write_bytes(b"db")
            self.assertTrue(warmup_idb._is_warm(binary))

            Path(f"{binary}.id0").write_bytes(b"lock")
            self.assertFalse(warmup_idb._is_warm(binary))

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

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

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

            warmup_idb._invalidate_ida_database(binary)

            self.assertFalse(Path(f"{binary}.i64").exists())
            self.assertFalse(Path(f"{binary}.id0").exists())
            self.assertFalse(Path(f"{binary}.id1").exists())
            self.assertTrue(binary.exists())

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


if __name__ == "__main__":
    unittest.main()

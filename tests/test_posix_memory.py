from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path
from types import SimpleNamespace

from posix_memory import (
    CGROUP_CHILD_NAME,
    CGROUP_MEMORY_CURRENT,
    CGROUP_MEMORY_MAX,
    CGROUP_MEMORY_OOM_GROUP,
    CGROUP_MEMORY_SWAP_MAX,
    CGROUP_PROCS,
    CgroupV2MemoryController,
    MINIMUM_ADDRESS_SPACE_LIMIT_MIB,
    ProcessTreeResidentMemoryProbe,
    ReservationMemoryController,
    ResidentMemoryWatchdog,
    apply_address_space_limit,
    build_posix_memory_controller,
    parse_unified_cgroup_path,
    read_process_cgroup_path,
    run_memory_limited_worker,
)
from warmup_memory import MIB, MemorySnapshot, default_memory_controller, parse_worker_reservation_bytes

UNIT_CGROUP = "/unit.service"
INIT_SCOPE = f"{UNIT_CGROUP}/init.scope"
# Injected into the probe so the fabricated /proc tree can be asserted on any host; the probe
# would otherwise read the real page size via os.sysconf, which does not exist on Windows.
PAGE_SIZE = 4096


def write(path: Path, value: str) -> Path:
    path.write_text(value, encoding="ascii")
    return path


def memory_interface(child: Path, *, current: int = 0, procs: str = "") -> Path:
    """Emulate the files the kernel materialises when a memory-enabled child is created."""
    child.mkdir(parents=True, exist_ok=True)
    write(child / CGROUP_MEMORY_MAX, "max")
    write(child / CGROUP_MEMORY_CURRENT, str(current))
    write(child / CGROUP_MEMORY_OOM_GROUP, "0")
    write(child / CGROUP_MEMORY_SWAP_MAX, "max")
    write(child / CGROUP_PROCS, procs)
    return child


class FakeCgroupTree:
    """A cgroupfs-shaped temp tree: `/unit.service/init.scope` under a delegated parent."""

    def __init__(self, root: Path, *, pid: int) -> None:
        self.root = root
        self.pid = pid
        self.parent = root / "unit.service"
        self.source = self.parent / "init.scope"
        self.source.mkdir(parents=True, exist_ok=True)
        write(self.source / CGROUP_PROCS, "")
        self.proc_self_cgroup = write(root / "self.cgroup", f"0::{INIT_SCOPE}\n")

    def reusable_child(self, **kwargs) -> Path:
        return memory_interface(self.parent / f"{CGROUP_CHILD_NAME}.{self.pid}", **kwargs)

    def build(self, budget_bytes: int, **kwargs):
        return build_posix_memory_controller(
            budget_bytes,
            cgroup_root=self.root,
            proc_self_cgroup_path=str(self.proc_self_cgroup),
            pid=self.pid,
            **kwargs,
        )


class ParseUnifiedCgroupPathTests(unittest.TestCase):
    def test_unified_line(self):
        self.assertEqual("/a/b", parse_unified_cgroup_path("0::/a/b\n"))

    def test_v1_hybrid_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_unified_cgroup_path("2:cpu:/\n1:memory:/\n")

    def test_empty_listing_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_unified_cgroup_path("\n")

    def test_multiple_unified_lines_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_unified_cgroup_path("0::/a\n0::/b\n")

    def test_relative_path_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_unified_cgroup_path("0::relative\n")

    def test_namespace_path_outside_visible_hierarchy_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_unified_cgroup_path("0::/../../outside\n")

    def test_unreadable_path_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                read_process_cgroup_path(str(Path(tmp) / "missing"))

    def test_read_injected_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            listing = write(Path(tmp) / "self.cgroup", "0::/unit.service/init.scope\n")
            self.assertEqual(INIT_SCOPE, read_process_cgroup_path(str(listing)))


class ProcessTreeResidentMemoryProbeTests(unittest.TestCase):
    def _stat(self, root: Path, pid: int, ppid: int, rss_pages: int) -> None:
        """Fields after ``comm)``: 0=state, 1=ppid, 2..20=filler, 21=rss (kernel field 24)."""
        directory = root / str(pid)
        directory.mkdir(parents=True, exist_ok=True)
        tail = " ".join(["0"] * 19 + [str(rss_pages)])
        write(directory / "stat", f"{pid} (python3) S {ppid} {tail}\n")

    def test_sums_descendants_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._stat(root, 100, 1, 10)
            self._stat(root, 101, 100, 5)
            self._stat(root, 102, 101, 1)
            self._stat(root, 900, 1, 999)
            probe = ProcessTreeResidentMemoryProbe(proc_root=str(root), pid=100, page_size=PAGE_SIZE)
            self.assertEqual((10 + 5 + 1) * PAGE_SIZE, probe.resident_bytes())

    def test_unreadable_root_returns_zero(self):
        probe = ProcessTreeResidentMemoryProbe(proc_root="/definitely/missing", pid=os.getpid())
        self.assertEqual(0, probe.resident_bytes())

    def test_unreadable_unrelated_pid_preserves_tree_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._stat(root, 100, 1, 10)
            self._stat(root, 101, 100, 5)
            (root / "999").mkdir()  # A process exited after /proc was enumerated.
            probe = ProcessTreeResidentMemoryProbe(proc_root=tmp, pid=100, page_size=PAGE_SIZE)
            self.assertEqual(15 * PAGE_SIZE, probe.resident_bytes())

    def test_malformed_unrelated_pid_preserves_tree_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._stat(root, 100, 1, 10)
            self._stat(root, 999, 1, 1)
            write(root / "999" / "stat", "999 (unrelated) S invalid " + "0 " * 20)
            probe = ProcessTreeResidentMemoryProbe(proc_root=tmp, pid=100, page_size=PAGE_SIZE)
            self.assertEqual(10 * PAGE_SIZE, probe.resident_bytes())

    def test_members_are_descendants_first_even_when_pids_wrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._stat(root, 100, 1, 10)
            self._stat(root, 900, 100, 5)
            self._stat(root, 50, 900, 1)
            probe = ProcessTreeResidentMemoryProbe(proc_root=tmp, pid=100, page_size=PAGE_SIZE)
            self.assertEqual(((50, 900, 100), 16 * PAGE_SIZE), probe.tree_pids_and_rss())

    def test_malformed_stat_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "100"
            directory.mkdir()
            write(directory / "stat", "no closing paren\n")
            self.assertEqual(0, ProcessTreeResidentMemoryProbe(proc_root=str(root), pid=100).resident_bytes())


class ReservationMemoryControllerTests(unittest.TestCase):
    def test_capabilities_and_snapshot_delegate(self):
        probe = unittest.mock.Mock()
        probe.resident_bytes.return_value = 1234
        controller = ReservationMemoryController(MIB, reason="cgroup unavailable", probe=probe)
        self.assertEqual("reservation-only", controller.capabilities.tier)
        self.assertFalse(controller.capabilities.aggregate_hard_cap)
        self.assertEqual("cgroup unavailable", controller.capabilities.detail)
        self.assertEqual(MemorySnapshot(job_bytes=1234), controller.snapshot())
        self.assertEqual(MIB, controller.budget_bytes)


class CgroupV2MemoryControllerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tree = FakeCgroupTree(Path(self._tmp.name), pid=4242)

    def test_reuses_own_empty_child_and_applies_every_knob(self):
        child = self.tree.reusable_child(current=7 * MIB)
        controller = CgroupV2MemoryController(
            512 * MIB,
            cgroup_root=self.tree.root,
            target_cgroup_path=UNIT_CGROUP,
            source_cgroup_path=INIT_SCOPE,
            pid=self.tree.pid,
        )
        self.assertEqual(child, controller.cgroup_path)
        self.assertEqual("cgroup-v2", controller.capabilities.tier)
        self.assertTrue(controller.capabilities.aggregate_hard_cap)
        self.assertIn(str(child), controller.capabilities.detail)
        self.assertEqual(str(512 * MIB), (child / CGROUP_MEMORY_MAX).read_text(encoding="ascii"))
        self.assertEqual("1", (child / CGROUP_MEMORY_OOM_GROUP).read_text(encoding="ascii"))
        self.assertEqual("0", (child / CGROUP_MEMORY_SWAP_MAX).read_text(encoding="ascii"))
        self.assertEqual(str(self.tree.pid), (child / CGROUP_PROCS).read_text(encoding="ascii"))
        write(child / CGROUP_MEMORY_CURRENT, str(9 * MIB))
        self.assertEqual(MemorySnapshot(job_bytes=9 * MIB), controller.snapshot())

    def test_close_restores_producer_to_source_cgroup(self):
        self.tree.reusable_child(current=MIB)
        controller = self.tree.build(512 * MIB)
        controller.close()
        self.assertEqual(str(self.tree.pid), (self.tree.source / CGROUP_PROCS).read_text(encoding="ascii"))

    def test_other_producer_group_is_never_reused(self):
        other = memory_interface(self.tree.parent / f"{CGROUP_CHILD_NAME}.999", current=MIB)
        controller = self.tree.build(512 * MIB)
        self.assertEqual("reservation-only", controller.capabilities.tier)
        self.assertEqual("", (other / CGROUP_PROCS).read_text(encoding="ascii"))
        self.assertEqual("max", (other / CGROUP_MEMORY_MAX).read_text(encoding="ascii"))

    def test_occupied_own_child_is_rejected(self):
        self.tree.reusable_child(procs="4242")
        with self.assertRaisesRegex(ValueError, "already in use"):
            CgroupV2MemoryController(
                512 * MIB,
                cgroup_root=self.tree.root,
                target_cgroup_path=UNIT_CGROUP,
                source_cgroup_path=INIT_SCOPE,
                pid=self.tree.pid,
            )

    def test_missing_memory_interface_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            CgroupV2MemoryController(
                512 * MIB,
                cgroup_root=self.tree.root,
                target_cgroup_path=UNIT_CGROUP,
                source_cgroup_path=INIT_SCOPE,
                pid=self.tree.pid,
            )
        self.assertIn("memory controller not enabled", str(ctx.exception))
        self.assertFalse((self.tree.parent / f"{CGROUP_CHILD_NAME}.{self.tree.pid}").exists())

    def test_missing_target_directory_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            CgroupV2MemoryController(
                512 * MIB,
                cgroup_root=self.tree.root,
                target_cgroup_path="/absent",
                source_cgroup_path=INIT_SCOPE,
                pid=self.tree.pid,
            )
        self.assertIn("not a directory", str(ctx.exception))

    def test_budget_below_live_usage_moves_the_process_back(self):
        child = self.tree.reusable_child(current=600 * MIB)
        with self.assertRaises(ValueError) as ctx:
            CgroupV2MemoryController(
                512 * MIB,
                cgroup_root=self.tree.root,
                target_cgroup_path=UNIT_CGROUP,
                source_cgroup_path=INIT_SCOPE,
                pid=self.tree.pid,
            )
        self.assertIn("is not above current usage", str(ctx.exception))
        self.assertEqual(str(self.tree.pid), (self.tree.source / CGROUP_PROCS).read_text(encoding="ascii"))
        self.assertEqual("max", (child / CGROUP_MEMORY_MAX).read_text(encoding="ascii"))
        self.assertTrue(child.is_dir())

    def test_failed_read_after_migration_moves_the_process_back(self):
        child = self.tree.reusable_child(current=MIB)
        (child / CGROUP_MEMORY_CURRENT).unlink()
        (child / CGROUP_MEMORY_CURRENT).mkdir()
        with self.assertRaises(OSError):
            CgroupV2MemoryController(
                512 * MIB,
                cgroup_root=self.tree.root,
                target_cgroup_path=UNIT_CGROUP,
                source_cgroup_path=INIT_SCOPE,
                pid=self.tree.pid,
            )
        self.assertEqual(str(self.tree.pid), (self.tree.source / CGROUP_PROCS).read_text(encoding="ascii"))
        self.assertTrue(child.is_dir())


class BuildPosixMemoryControllerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tree = FakeCgroupTree(Path(self._tmp.name), pid=4242)

    def test_selects_cgroup_tier(self):
        self.tree.reusable_child(current=MIB)
        controller = self.tree.build(512 * MIB)
        self.assertEqual("cgroup-v2", controller.capabilities.tier)
        self.assertEqual(self.tree.parent / f"{CGROUP_CHILD_NAME}.{self.tree.pid}", controller.cgroup_path)

    def test_falls_back_when_no_candidate_is_usable(self):
        probe = unittest.mock.Mock()
        probe.resident_bytes.return_value = 42
        controller = self.tree.build(512 * MIB, probe_factory=lambda: probe)
        self.assertEqual("reservation-only", controller.capabilities.tier)
        self.assertIn("memory controller not enabled", controller.capabilities.detail)
        self.assertEqual(MemorySnapshot(job_bytes=42), controller.snapshot())

    def test_parent_candidate_cannot_bypass_source_leaf_memory_limit(self):
        for name in (CGROUP_MEMORY_MAX, "memory.high", CGROUP_MEMORY_SWAP_MAX):
            with self.subTest(name=name):
                self.tree.reusable_child(current=MIB)
                source_limit = write(self.tree.source / name, str(128 * MIB))
                controller = self.tree.build(512 * MIB)
                self.assertEqual("reservation-only", controller.capabilities.tier)
                self.assertIn(f"local {name} restriction", controller.capabilities.detail)
                source_limit.unlink()

    def test_falls_back_when_cgroup_listing_is_unreadable(self):
        controller = build_posix_memory_controller(
            512 * MIB,
            cgroup_root=self.tree.root,
            proc_self_cgroup_path=str(self.tree.root / "absent"),
            pid=self.tree.pid,
        )
        self.assertEqual("reservation-only", controller.capabilities.tier)
        self.assertIn("unable to read", controller.capabilities.detail)

    def test_root_only_cgroup_path_falls_back(self):
        listing = write(self.tree.root / "root.cgroup", "0::/\n")
        controller = build_posix_memory_controller(
            512 * MIB,
            cgroup_root=self.tree.root,
            proc_self_cgroup_path=str(listing),
            pid=self.tree.pid,
        )
        self.assertEqual("reservation-only", controller.capabilities.tier)

    def test_does_not_move_producer_out_of_systemd_unit(self):
        unit = self.tree.root / "app.slice" / "runner.scope"
        unit.mkdir(parents=True)
        write(unit / CGROUP_PROCS, "4242")
        sibling = memory_interface(unit.parent / f"{CGROUP_CHILD_NAME}.4242", current=MIB)
        listing = write(self.tree.root / "scope.cgroup", "0::/app.slice/runner.scope\n")
        controller = build_posix_memory_controller(
            512 * MIB,
            cgroup_root=self.tree.root,
            proc_self_cgroup_path=str(listing),
            pid=4242,
        )
        self.assertEqual("reservation-only", controller.capabilities.tier)
        self.assertEqual("", (sibling / CGROUP_PROCS).read_text())
        self.assertEqual("4242", (unit / CGROUP_PROCS).read_text())


class ApplyAddressSpaceLimitTests(unittest.TestCase):
    def test_below_floor_is_rejected(self):
        with self.assertRaises(ValueError):
            apply_address_space_limit(MINIMUM_ADDRESS_SPACE_LIMIT_MIB - 1)

    @unittest.skipUnless(os.name == "posix", "requires POSIX resource limits")
    def test_applies_rlimit_as_in_a_child_process(self):
        script = (
            "import resource, sys;"
            "sys.path.insert(0, %r);"
            "from posix_memory import apply_address_space_limit;"
            "apply_address_space_limit(512);"
            "print(resource.getrlimit(resource.RLIMIT_AS)[0])"
        ) % str(Path(__file__).resolve().parent.parent)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(str(512 * MIB), result.stdout.strip())

    @unittest.skipUnless(os.name == "posix", "requires POSIX resource limits")
    def test_start_process_tree_limits_installs_both_limits(self):
        script = (
            "import resource, sys;"
            "sys.path.insert(0, %r);"
            "from posix_memory import start_process_tree_limits;"
            "w = start_process_tree_limits(address_space_limit_mib=512, resident_cap_bytes=256 * 1048576);"
            "print(resource.getrlimit(resource.RLIMIT_AS)[0], w.cap_bytes)"
        ) % str(Path(__file__).resolve().parent.parent)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(f"{512 * MIB} {256 * MIB}", result.stdout.strip())

    @unittest.skipUnless(sys.platform == "linux", "requires Linux resource limits")
    def test_preserves_stricter_inherited_hard_limit(self):
        source = (
            "import resource; from posix_memory import apply_address_space_limit; "
            "resource.setrlimit(resource.RLIMIT_AS, (256 * 1048576, 256 * 1048576)); "
            "apply_address_space_limit(512); print(resource.getrlimit(resource.RLIMIT_AS)[0])"
        )
        result = subprocess.run([sys.executable, "-c", source], capture_output=True, text=True, check=True, timeout=10)
        self.assertEqual(str(256 * MIB), result.stdout.strip())

    @unittest.skipUnless(sys.platform == "linux", "requires Linux resource limits")
    def test_preserves_stricter_inherited_soft_limit(self):
        source = (
            "import resource; from posix_memory import apply_address_space_limit; "
            "resource.setrlimit(resource.RLIMIT_AS, (256 * 1048576, resource.RLIM_INFINITY)); "
            "apply_address_space_limit(512); print(resource.getrlimit(resource.RLIMIT_AS)[0])"
        )
        result = subprocess.run([sys.executable, "-c", source], capture_output=True, text=True, check=True, timeout=10)
        self.assertEqual(str(256 * MIB), result.stdout.strip())


class MemoryControllerSelectionTests(unittest.TestCase):
    def test_windows_factory_keeps_job_controller(self):
        import warmup_memory

        with (
            unittest.mock.patch.object(warmup_memory, "os", SimpleNamespace(name="nt")),
            unittest.mock.patch.object(warmup_memory, "WindowsJobMemoryController") as factory,
        ):
            self.assertIs(factory.return_value, default_memory_controller(MIB))
        factory.assert_called_once_with(MIB)

    def test_posix_factory_uses_posix_controller(self):
        import warmup_memory

        with (
            unittest.mock.patch.object(warmup_memory, "os", SimpleNamespace(name="posix")),
            unittest.mock.patch("posix_memory.build_posix_memory_controller") as factory,
        ):
            self.assertIs(factory.return_value, default_memory_controller(MIB))
        factory.assert_called_once_with(MIB)

    def test_reservation_rejects_invalid_values(self):
        for value in ("0", "-1", "1.5", "nan", "１２"):
            with (
                self.subTest(value=value),
                unittest.mock.patch.dict(os.environ, {"IDB_WARMUP_INITIAL_WORKER_RESERVATION_MIB": value}),
            ):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    parse_worker_reservation_bytes()


@unittest.skipUnless(sys.platform == "linux", "requires Linux /proc and resource limits")
class MemoryLimitedWorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.worker = Path(self.tmp.name) / "worker with spaces.py"

    def run_worker(self, source, *, limit_mib=256, timeout=10):
        self.worker.write_text(source, encoding="utf-8")
        return run_memory_limited_worker(
            [sys.executable, str(self.worker), "argument with spaces"],
            limit_bytes=limit_mib * MIB,
            timeout_seconds=timeout,
        )

    def test_limit_is_installed_before_script_and_argv_imports_are_preserved(self):
        (self.worker.parent / "sibling.py").write_text("VALUE = 'imported'\n", encoding="utf-8")
        result = self.run_worker(
            "import resource, sys, sibling\n"
            "print(resource.getrlimit(resource.RLIMIT_AS)[0], sys.argv[1], sibling.VALUE)\n"
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(f"{256 * MIB} argument with spaces imported", result.stdout.strip())

    def test_address_space_limit_rejects_large_allocation(self):
        result = self.run_worker("data = bytearray(512 * 1024 * 1024)\n")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("MemoryError", result.stderr)

    def test_rss_watchdog_enforces_small_cap(self):
        result = self.run_worker("import time\ndata = bytearray(96 * 1024 * 1024)\ntime.sleep(30)\n", limit_mib=64)
        self.assertEqual(-9, result.returncode)
        self.assertIn("Resident memory limit exceeded", result.stderr)

    def test_timeout_kills_worker_descendants(self):
        import signal

        pid_file = self.worker.parent / "child.pid"
        source = (
            "import subprocess, sys, time\nfrom pathlib import Path\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
            f"Path({str(pid_file)!r}).write_text(str(child.pid))\n"
            "time.sleep(30)\n"
        )
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_worker(source, timeout=1)
            child_pid = int(pid_file.read_text())
            stat_path = Path(f"/proc/{child_pid}/stat")
            deadline = time.monotonic() + 5
            while stat_path.exists():
                try:
                    stat = stat_path.read_text()
                except (FileNotFoundError, ProcessLookupError):
                    break
                if stat[stat.rfind(")") + 2 :].split()[0] == "Z":
                    break
                self.assertLess(time.monotonic(), deadline, "worker descendant survived timeout")
                time.sleep(0.01)
        finally:
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass


@unittest.skipUnless(
    sys.platform == "linux" and os.environ.get("CS2_TEST_CGROUP_V2") == "1",
    "opt-in test requires a delegated cgroup v2 test scope",
)
class LiveCgroupTests(unittest.TestCase):
    def test_kernel_enforces_aggregate_cap_on_isolated_child(self):
        source = """
from posix_memory import build_posix_memory_controller
controller = build_posix_memory_controller(128 * 1048576)
assert controller.capabilities.tier == 'cgroup-v2', controller.capabilities.detail
print(controller.cgroup_path, flush=True)
data = bytearray(256 * 1048576)
raise AssertionError('allocation exceeded the cgroup cap')
"""
        result = subprocess.run(
            [sys.executable, "-c", source],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(-9, result.returncode, result.stderr)
        child = Path(result.stdout.strip())
        try:
            self.assertEqual(str(128 * MIB), (child / CGROUP_MEMORY_MAX).read_text().strip())
            events = dict(line.split() for line in (child / "memory.events").read_text().splitlines())
            self.assertGreater(int(events["oom_kill"]), 0)
        finally:
            child.rmdir()

    def test_controller_close_restores_cgroup_and_removes_child(self):
        source = """
from pathlib import Path
from posix_memory import build_posix_memory_controller
before = Path('/proc/self/cgroup').read_text()
controller = build_posix_memory_controller(512 * 1048576)
assert controller.capabilities.tier == 'cgroup-v2', controller.capabilities.detail
child = controller.cgroup_path
controller.close()
assert before == Path('/proc/self/cgroup').read_text()
assert not child.exists(), child
print('restored')
"""
        result = subprocess.run(
            [sys.executable, "-c", source],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("restored", result.stdout.strip())


class ResidentMemoryWatchdogTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "requires Linux /proc and SIGKILL")
    def test_self_watchdog_kills_its_descendant_before_exiting(self):
        import signal

        script = """
import subprocess, sys, time
from posix_memory import start_process_tree_limits
child = subprocess.Popen(
    [sys.executable, '-c', 'import time; time.sleep(30)'],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
print(child.pid, flush=True)
start_process_tree_limits(address_space_limit_mib=512, resident_cap_bytes=1)
time.sleep(30)
"""
        worker = subprocess.Popen(
            [sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parent.parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        child_pid = None
        try:
            output, error = worker.communicate(timeout=10)
            child_pid = int(output.splitlines()[0])
            self.assertEqual(-signal.SIGKILL, worker.returncode, error)

            def descendant_exited():
                try:
                    stat = Path(f"/proc/{child_pid}/stat").read_text(encoding="ascii")
                except (FileNotFoundError, ProcessLookupError):
                    # A task reaped after open() can make procfs read() return ESRCH.
                    return True
                return stat[stat.rfind(")") + 2 :].split()[0] == "Z"

            self.assertTrue(self._wait_for(descendant_exited), "watchdog left its descendant alive")
        finally:
            if worker.poll() is None:
                worker.kill()
                output, _ = worker.communicate(timeout=5)
                if output.splitlines():
                    child_pid = int(output.splitlines()[0])
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def _watchdog(self, probe, killed, cap_bytes):
        return ResidentMemoryWatchdog(
            cap_bytes,
            probe_factory=unittest.mock.Mock(return_value=probe),
            interval_seconds=0.01,
            kill=killed.extend,
        )

    def _wait_for(self, predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        return False

    def test_trips_and_kills_the_tree_above_the_cap(self):
        probe = unittest.mock.Mock()
        probe.tree_pids_and_rss.return_value = ((11, 12), 300 * MIB)
        killed = []
        watchdog = self._watchdog(probe, killed, 200 * MIB)
        watchdog.start(pid=11)
        self.addCleanup(watchdog.stop)
        self.assertTrue(self._wait_for(lambda: bool(killed)))
        self.assertEqual([11, 12], killed)
        self.assertEqual(300 * MIB, watchdog.stop())

    def test_stays_quiet_below_the_cap(self):
        probe = unittest.mock.Mock()
        probe.tree_pids_and_rss.return_value = ((11,), 100 * MIB)
        killed = []
        watchdog = self._watchdog(probe, killed, 200 * MIB)
        watchdog.start(pid=11)
        self.addCleanup(watchdog.stop)
        time.sleep(0.05)
        self.assertEqual([], killed)
        self.assertEqual(0, watchdog.stop())
        self.assertGreaterEqual(probe.tree_pids_and_rss.call_count, 1)

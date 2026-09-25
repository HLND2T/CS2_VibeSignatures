"""POSIX aggregate memory controls for concurrent IDA workers (cgroup v2 or per-worker caps).

``warmup_memory`` imports this module lazily so the Windows ctypes path stays untouched; the
dependency is one-way (``posix_memory`` imports ``warmup_memory`` at module level).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
from pathlib import Path, PurePosixPath
from typing import Callable

from warmup_memory import MIB, MemoryControllerCapabilities, MemorySnapshot

DEFAULT_CGROUP_ROOT = "/sys/fs/cgroup"
PROC_SELF_CGROUP_PATH = "/proc/self/cgroup"
DEFAULT_PROC_ROOT = "/proc"
CGROUP_CHILD_NAME = "cs2vibe-memory"
CGROUP_MEMORY_MAX = "memory.max"
CGROUP_MEMORY_CURRENT = "memory.current"
CGROUP_MEMORY_OOM_GROUP = "memory.oom.group"
CGROUP_MEMORY_SWAP_MAX = "memory.swap.max"
CGROUP_MEMORY_HIGH = "memory.high"
CGROUP_PROCS = "cgroup.procs"
CGROUP_MAX_VALUE = "max"
CGROUP_USAGE_MARGIN_BYTES = 64 * MIB
MINIMUM_ADDRESS_SPACE_LIMIT_MIB = 256
DEFAULT_WATCHDOG_INTERVAL_SECONDS = 2.0
# Fields after the ``comm`` field of /proc/<pid>/stat: 0=state, 1=ppid, 21=rss (kernel field 24).
_PROC_STAT_PPID_FIELD_INDEX = 1
_PROC_STAT_RSS_FIELD_INDEX = 21


def parse_unified_cgroup_path(text: str) -> str:
    """Return the cgroup v2 path from ``/proc/self/cgroup`` contents."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty cgroup listing")
    for line in lines:
        if not line.startswith("0::"):
            raise ValueError(f"not a unified cgroup v2 hierarchy: {line!r}")
    if len(lines) != 1:
        raise ValueError(f"expected exactly one cgroup line, found {len(lines)}")
    path = lines[0][3:]
    if not path.startswith("/") or ".." in PurePosixPath(path).parts:
        raise ValueError(f"cgroup path is not an absolute path within the hierarchy: {path!r}")
    return path


def read_process_cgroup_path(proc_self_cgroup_path: str = PROC_SELF_CGROUP_PATH) -> str:
    try:
        text = Path(proc_self_cgroup_path).read_text(encoding="ascii")
    except OSError as exc:
        raise ValueError(f"unable to read {proc_self_cgroup_path}: {exc}") from exc
    try:
        return parse_unified_cgroup_path(text)
    except ValueError as exc:
        raise ValueError(f"{proc_self_cgroup_path}: {exc}") from exc


def _read_text(path: Path) -> str:
    return path.read_text(encoding="ascii")


def _write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="ascii")


class ProcessTreeResidentMemoryProbe:
    """Sum the resident set of this process tree from ``/proc`` without ever raising."""

    def __init__(
        self,
        *,
        proc_root: str = DEFAULT_PROC_ROOT,
        pid: int | None = None,
        page_size: int | None = None,
    ) -> None:
        self._proc_root = Path(proc_root)
        self._pid = os.getpid() if pid is None else pid
        self._page_size = page_size

    def tree_pids_and_rss(self) -> tuple[tuple[int, ...], int]:
        """Return descendants before ancestors, followed by their summed resident bytes."""
        try:
            page_size = self._page_size if self._page_size is not None else os.sysconf("SC_PAGE_SIZE")
            entries = os.listdir(self._proc_root)
        except (AttributeError, OSError, ValueError):
            return (), 0
        children_by_pid: dict[int, list[int]] = {}
        rss_by_pid: dict[int, int] = {}
        for entry in entries:
            if not entry.isdigit():
                continue
            try:
                pid = int(entry)
                stat = (_read_text(self._proc_root / entry / "stat")).strip()
                closer = stat.rfind(")")
                if closer < 0:
                    continue
                fields = stat[closer + 2 :].split()
                if len(fields) <= _PROC_STAT_RSS_FIELD_INDEX:
                    continue
                parent = int(fields[_PROC_STAT_PPID_FIELD_INDEX])
                rss = int(fields[_PROC_STAT_RSS_FIELD_INDEX])
            except (OSError, ValueError):
                # /proc is a live view: an unrelated process may exit or be unreadable.
                continue
            children_by_pid.setdefault(parent, []).append(pid)
            rss_by_pid[pid] = rss
        members: set[int] = set()
        ancestors_first: list[int] = []
        pending = [self._pid]
        while pending:
            pid = pending.pop()
            if pid in members:
                continue
            members.add(pid)
            ancestors_first.append(pid)
            pending.extend(children_by_pid.get(pid, ()))
        # The watchdog may run inside the root itself. It must signal every descendant
        # before killing that root; PID ordering does not encode ancestry (PID wrap).
        ordered = tuple(reversed(ancestors_first))
        return ordered, sum(rss_by_pid.get(pid, 0) for pid in ordered) * page_size

    def tree_pids(self) -> tuple[int, ...]:
        return self.tree_pids_and_rss()[0]

    def resident_bytes(self) -> int:
        return self.tree_pids_and_rss()[1]


class ReservationMemoryController:
    """Account for real usage but delegate enforcement to per-worker hard caps."""

    def __init__(
        self,
        budget_bytes: int,
        *,
        reason: str,
        probe: ProcessTreeResidentMemoryProbe | None = None,
    ) -> None:
        if budget_bytes < 1:
            raise ValueError("budget_bytes must be positive")
        self.budget_bytes = budget_bytes
        self._probe = probe or ProcessTreeResidentMemoryProbe()
        self.capabilities = MemoryControllerCapabilities(
            tier="reservation-only",
            aggregate_hard_cap=False,
            detail=reason,
        )

    def snapshot(self) -> MemorySnapshot:
        return MemorySnapshot(job_bytes=self._probe.resident_bytes())

    def close(self) -> None:
        pass


class CgroupV2MemoryController:
    """Bind this process to one cgroup v2 child capped at the aggregate budget.

    Only ever creates a new directory under the target cgroup and writes interface files inside
    it; ``cgroup.subtree_control`` is never written, because a cgroup with delegated controllers
    can no longer accept processes and would break its owner.
    """

    def __init__(
        self,
        budget_bytes: int,
        *,
        cgroup_root: str | Path = DEFAULT_CGROUP_ROOT,
        target_cgroup_path: str,
        source_cgroup_path: str,
        pid: int | None = None,
        oom_group: bool = True,
    ) -> None:
        if budget_bytes < 1:
            raise ValueError("budget_bytes must be positive")
        self.budget_bytes = budget_bytes
        self._pid = os.getpid() if pid is None else pid
        target = Path(cgroup_root) / target_cgroup_path.lstrip("/")
        if not target.is_dir():
            raise ValueError(f"cgroup target is not a directory: {target}")
        self._source_procs = Path(cgroup_root) / source_cgroup_path.lstrip("/") / CGROUP_PROCS
        child, created = self._claim_child_directory(target)
        self.cgroup_path = child
        self._created = created
        self._migrated = False
        try:
            self._require_memory_interface(child, target)
            self._enter(child, oom_group)
        except (OSError, ValueError):
            self._unwind()
            raise
        self.capabilities = MemoryControllerCapabilities(
            tier="cgroup-v2",
            aggregate_hard_cap=True,
            detail=f"cgroup v2 hard cap at {child}",
        )

    def _claim_child_directory(self, target: Path) -> tuple[Path, bool]:
        # Producers for different GAMEVERs can run concurrently. Never reuse
        # another producer's empty-looking group between its mkdir and attach.
        preferred = target / f"{CGROUP_CHILD_NAME}.{self._pid}"
        if self._is_reusable(preferred):
            return preferred, False
        if not preferred.exists():
            return self._create_child_directory(preferred, target), True
        raise ValueError(f"cgroup child already in use: {preferred}")

    @staticmethod
    def _create_child_directory(child: Path, target: Path) -> Path:
        try:
            child.mkdir()
        except OSError as exc:
            raise ValueError(f"unable to create a cgroup under {target}: {exc}") from exc
        return child

    @staticmethod
    def _is_reusable(child: Path) -> bool:
        if not child.is_dir():
            return False
        procs = child / CGROUP_PROCS
        if not procs.exists() or not os.access(procs, os.W_OK):
            return False
        try:
            return not _read_text(procs).strip()
        except OSError:
            return False

    @staticmethod
    def _require_memory_interface(child: Path, target: Path) -> None:
        missing = [
            name for name in (CGROUP_MEMORY_MAX, CGROUP_MEMORY_CURRENT, CGROUP_PROCS) if not (child / name).exists()
        ]
        if missing:
            raise ValueError(f"memory controller not enabled for children of {target}: missing {', '.join(missing)}")

    def _enter(self, child: Path, oom_group: bool) -> None:
        _write_text(child / CGROUP_MEMORY_MAX, CGROUP_MAX_VALUE)
        if oom_group and (child / CGROUP_MEMORY_OOM_GROUP).exists():
            self._best_effort(child / CGROUP_MEMORY_OOM_GROUP, "1")
        if (child / CGROUP_MEMORY_SWAP_MAX).exists():
            self._best_effort(child / CGROUP_MEMORY_SWAP_MAX, "0")
        _write_text(child / CGROUP_PROCS, str(self._pid))
        self._migrated = True
        used = int(_read_text(child / CGROUP_MEMORY_CURRENT).strip())
        if used + CGROUP_USAGE_MARGIN_BYTES >= self.budget_bytes:
            raise ValueError(f"budget {self.budget_bytes // MIB} MiB is not above current usage {used // MIB} MiB")
        _write_text(child / CGROUP_MEMORY_MAX, str(self.budget_bytes))

    @staticmethod
    def _best_effort(path: Path, value: str) -> None:
        try:
            _write_text(path, value)
        except OSError:
            pass

    def _unwind(self) -> None:
        if self._migrated:
            try:
                _write_text(self._source_procs, str(self._pid))
            except OSError as exc:
                raise RuntimeError("cannot restore producer to its original cgroup") from exc
            self._migrated = False
        if self._created:
            try:
                self.cgroup_path.rmdir()
            except OSError:
                pass

    def close(self) -> None:
        self._unwind()

    def snapshot(self) -> MemorySnapshot:
        return MemorySnapshot(job_bytes=int(_read_text(self.cgroup_path / CGROUP_MEMORY_CURRENT).strip()))


def apply_address_space_limit(limit_mib: int) -> None:
    """Cap this process's address space; the last-resort per-worker bound on Linux."""
    if limit_mib < MINIMUM_ADDRESS_SPACE_LIMIT_MIB:
        raise ValueError(f"address-space limit must be at least {MINIMUM_ADDRESS_SPACE_LIMIT_MIB} MiB")
    import resource

    limit_bytes = limit_mib * MIB
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    for inherited in (soft, hard):
        if inherited != resource.RLIM_INFINITY:
            limit_bytes = min(limit_bytes, inherited)
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def kill_process_tree(pids: tuple[int, ...]) -> None:
    """Signal the probe's descendants-first snapshot, with the root last."""
    import signal

    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


class ResidentMemoryWatchdog:
    """Kill a process tree that exceeds a resident-memory cap.

    ``RLIMIT_AS`` bounds address mappings rather than the memory a worker actually holds, so the
    degraded tier adds this sampler for the real cap.
    """

    def __init__(
        self,
        cap_bytes: int,
        *,
        probe_factory: Callable[..., ProcessTreeResidentMemoryProbe] = ProcessTreeResidentMemoryProbe,
        interval_seconds: float = DEFAULT_WATCHDOG_INTERVAL_SECONDS,
        kill: Callable[[tuple[int, ...]], None] = kill_process_tree,
    ) -> None:
        if cap_bytes < 1:
            raise ValueError("cap_bytes must be positive")
        self.cap_bytes = cap_bytes
        self.exceeded_bytes = 0
        self._probe_factory = probe_factory
        self._interval_seconds = interval_seconds
        self._kill = kill
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, pid: int) -> None:
        self._thread = threading.Thread(target=self._watch, args=(pid,), daemon=True)
        self._thread.start()

    def stop(self) -> int:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval_seconds * 2)
            self._thread = None
        return self.exceeded_bytes

    def _watch(self, pid: int) -> None:
        probe = self._probe_factory(pid=pid)
        while not self._stop.wait(self._interval_seconds):
            pids, resident = probe.tree_pids_and_rss()
            if resident <= self.cap_bytes:
                continue
            self.exceeded_bytes = resident
            print(
                f"Resident memory watchdog: {resident // MIB} MiB exceeds the "
                f"{self.cap_bytes // MIB} MiB cap; killing {len(pids)} process(es)",
                flush=True,
            )
            self._kill(pids)
            return


def start_process_tree_limits(*, address_space_limit_mib: int, resident_cap_bytes: int) -> ResidentMemoryWatchdog:
    """Install both degraded-tier per-worker limits on this process and start the watchdog."""
    apply_address_space_limit(address_space_limit_mib)
    watchdog = ResidentMemoryWatchdog(resident_cap_bytes)
    watchdog.start(os.getpid())
    return watchdog


def run_memory_limited_worker(command: list[str], *, limit_bytes: int, timeout_seconds: float):
    """Set RLIMIT_AS before loading IDA and monitor RSS from the producer process.

    A fresh interpreter avoids preexec_fn in the threaded warmup producer. The
    watchdog runs outside IDA so native code holding the worker GIL cannot stall it.
    """
    limit_mib = max(MINIMUM_ADDRESS_SPACE_LIMIT_MIB, (limit_bytes + MIB - 1) // MIB)
    wrapper = [command[0], str(Path(__file__).resolve()), str(limit_mib), *command[1:]]
    with subprocess.Popen(
        wrapper,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        start_new_session=True,
    ) as process:
        watchdog = ResidentMemoryWatchdog(limit_bytes)
        try:
            watchdog.start(process.pid)
            output, error = process.communicate(timeout=timeout_seconds)
        finally:
            watchdog.stop()
            kill_process_tree(ProcessTreeResidentMemoryProbe(pid=process.pid).tree_pids())
            # Also catch descendants reparented after the worker exited. Only
            # this newly created session belongs to the worker.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
        if watchdog.exceeded_bytes:
            error += f"\nResident memory limit exceeded: {watchdog.exceeded_bytes} > {limit_bytes} bytes"
            return subprocess.CompletedProcess(command, -signal.SIGKILL, output, error)
        return subprocess.CompletedProcess(command, process.returncode, output, error)


def _worker_main() -> None:
    import runpy

    limit_mib = int(sys.argv[1])
    worker_script = str(Path(sys.argv[2]).resolve())
    apply_address_space_limit(limit_mib)
    sys.argv = [worker_script, *sys.argv[3:]]
    sys.path.insert(0, str(Path(worker_script).parent))
    runpy.run_path(worker_script, run_name="__main__")


def build_posix_memory_controller(
    budget_bytes: int,
    *,
    cgroup_root: str | Path = DEFAULT_CGROUP_ROOT,
    proc_self_cgroup_path: str = PROC_SELF_CGROUP_PATH,
    pid: int | None = None,
    probe_factory: Callable[[], ProcessTreeResidentMemoryProbe] | None = None,
) -> ReservationMemoryController | CgroupV2MemoryController:
    """Return the strongest controller this host allows; never raise for environment reasons."""
    probe = probe_factory or ProcessTreeResidentMemoryProbe
    try:
        current = read_process_cgroup_path(proc_self_cgroup_path)
    except ValueError as exc:
        return ReservationMemoryController(budget_bytes, reason=str(exc), probe=probe())
    parent = str(PurePosixPath(current).parent)
    candidates = [current] if current != "/" else []
    # Never move a runner out of its systemd unit into the containing slice.
    # The manager can destroy the now-empty unit (including the restore path).
    # A sibling is useful only inside a delegated unit, e.g. service/worker.
    if parent not in ("", "/", ".") and not PurePosixPath(parent).name.endswith(".slice"):
        candidates.append(parent)
    reason = "no usable cgroup v2 parent"
    for target in dict.fromkeys(candidates):
        try:
            if target != current:
                # A sibling under a delegated parent must not escape a memory
                # restriction placed specifically on the producer's source leaf.
                for name in (CGROUP_MEMORY_MAX, CGROUP_MEMORY_HIGH, CGROUP_MEMORY_SWAP_MAX):
                    source_limit = Path(cgroup_root) / current.lstrip("/") / name
                    if source_limit.exists() and _read_text(source_limit).strip() != CGROUP_MAX_VALUE:
                        raise ValueError(f"cannot leave source cgroup with a local {name} restriction")
            return CgroupV2MemoryController(
                budget_bytes,
                cgroup_root=cgroup_root,
                target_cgroup_path=target,
                source_cgroup_path=current,
                pid=pid,
            )
        except (OSError, ValueError) as exc:
            reason = f"{target}: {exc}"
    return ReservationMemoryController(budget_bytes, reason=reason, probe=probe())


if __name__ == "__main__":
    _worker_main()

"""Platform-aware memory controls for concurrent IDB warmup workers."""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol

from windows_job import Kernel32JobApi as _Kernel32JobApi

MIB = 1024 * 1024
DEFAULT_SOFT_LIMIT_RATIO = 0.85
DEFAULT_INITIAL_WORKER_RESERVATION_BYTES = 4 * 1024 * MIB
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
DEFAULT_LAUNCH_INTERVAL_SECONDS = 5.0
WARMUP_RESERVATION_ENV = "IDB_WARMUP_INITIAL_WORKER_RESERVATION_MIB"


class _WindowsJobApi(Protocol):
    def create_job(self): ...

    def set_job_memory_limit(self, handle, budget_bytes: int) -> None: ...

    def assign_current_process(self, handle) -> None: ...

    def query_job_memory(self, handle) -> int: ...

    def close_handle(self, handle) -> None: ...


@dataclass(frozen=True)
class MemorySnapshot:
    job_bytes: int


@dataclass(frozen=True)
class MemoryControllerCapabilities:
    tier: str
    aggregate_hard_cap: bool
    detail: str


class MemoryController(Protocol):
    capabilities: MemoryControllerCapabilities

    def snapshot(self) -> MemorySnapshot: ...

    def close(self) -> None: ...


def default_memory_controller(budget_bytes: int) -> MemoryController:
    if os.name == "nt":
        return WindowsJobMemoryController(budget_bytes)
    from posix_memory import build_posix_memory_controller

    return build_posix_memory_controller(budget_bytes)


def parse_worker_reservation_bytes() -> int:
    raw = os.environ.get(WARMUP_RESERVATION_ENV, "").strip()
    if not raw:
        return DEFAULT_INITIAL_WORKER_RESERVATION_BYTES
    if not raw.isascii() or not raw.isdecimal() or int(raw) < 1:
        raise ValueError(f"{WARMUP_RESERVATION_ENV} must be a positive integer MiB value")
    return int(raw) * MIB


class WindowsJobMemoryController:
    """Apply one aggregate Job memory limit and sample current pressure."""

    def __init__(self, budget_bytes: int, *, api: _WindowsJobApi | None = None) -> None:
        if budget_bytes < 1:
            raise ValueError("budget_bytes must be positive")
        self._api = api or _Kernel32JobApi()
        handle = self._api.create_job()
        try:
            self._api.set_job_memory_limit(handle, budget_bytes)
            self._api.assign_current_process(handle)
        except Exception:
            self._api.close_handle(handle)
            raise
        self._handle = handle
        self.budget_bytes = budget_bytes
        self.capabilities = MemoryControllerCapabilities(
            tier="windows-job", aggregate_hard_cap=True, detail="Windows Job aggregate hard cap"
        )

    def snapshot(self) -> MemorySnapshot:
        return MemorySnapshot(job_bytes=self._api.query_job_memory(self._handle))

    def close(self) -> None:
        # Windows cannot detach a process from its Job. Retain the handle until
        # process exit: closing a kill-on-close Job here would kill the producer.
        pass


class MemoryLaunchGate:
    """Delay worker admission until the aggregate memory budget has headroom."""

    def __init__(
        self,
        *,
        snapshot: Callable[[], MemorySnapshot],
        budget_bytes: int,
        baseline_job_bytes: int,
        soft_limit_ratio: float = DEFAULT_SOFT_LIMIT_RATIO,
        initial_worker_reservation_bytes: int = DEFAULT_INITIAL_WORKER_RESERVATION_BYTES,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        launch_interval_seconds: float = DEFAULT_LAUNCH_INTERVAL_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
        worker_memory_limit_bytes: int | None = None,
    ) -> None:
        if budget_bytes < 1:
            raise ValueError("budget_bytes must be positive")
        if not 0 < soft_limit_ratio < 1:
            raise ValueError("soft_limit_ratio must be between zero and one")
        if initial_worker_reservation_bytes < 1:
            raise ValueError("initial_worker_reservation_bytes must be positive")
        self.worker_memory_limit_bytes = worker_memory_limit_bytes
        self._snapshot = snapshot
        self._budget_bytes = budget_bytes
        self._baseline_job_bytes = baseline_job_bytes
        self._soft_limit_bytes = int(budget_bytes * soft_limit_ratio)
        self._initial_worker_reservation_bytes = initial_worker_reservation_bytes
        self._poll_interval_seconds = poll_interval_seconds
        self._launch_interval_seconds = launch_interval_seconds
        self._monotonic = monotonic
        self._condition = threading.Condition()
        self._active_workers = 0
        self._observed_worker_bytes = 0
        self._last_launch_time: float | None = None

    @property
    def soft_limit_bytes(self) -> int:
        return self._soft_limit_bytes

    def _worker_reservation(self, snapshot: MemorySnapshot) -> int:
        if self._active_workers:
            active_usage = max(0, snapshot.job_bytes - self._baseline_job_bytes)
            observed = (active_usage + self._active_workers - 1) // self._active_workers
            self._observed_worker_bytes = max(self._observed_worker_bytes, observed)
        return max(self._initial_worker_reservation_bytes, self._observed_worker_bytes)

    def _admission_state(self, snapshot: MemorySnapshot, now: float) -> tuple[bool, str]:
        reservation = self._worker_reservation(snapshot)
        accounted_job = max(
            snapshot.job_bytes,
            self._baseline_job_bytes + self._active_workers * reservation,
        )
        projected_job = accounted_job + reservation
        interval_remaining = 0.0
        if self._last_launch_time is not None:
            interval_remaining = self._last_launch_time + self._launch_interval_seconds - now
        if interval_remaining > 0:
            return False, f"launch ramp-up ({interval_remaining:.1f}s remaining)"
        if projected_job > self._soft_limit_bytes:
            return (
                False,
                f"job={_format_mib(snapshot.job_bytes)}, projected={_format_mib(projected_job)}, "
                f"soft={_format_mib(self._soft_limit_bytes)}",
            )
        return True, ""

    def wait_for_launch(self, worker_name: str, *, timeout_seconds: float | None = None) -> None:
        announced = False
        with self._condition:
            deadline = None if timeout_seconds is None else self._monotonic() + timeout_seconds
            while True:
                snapshot = self._snapshot()
                now = self._monotonic()
                admitted, reason = self._admission_state(snapshot, now)
                if admitted:
                    self._active_workers += 1
                    self._last_launch_time = now
                    if announced:
                        print(f"warmup: memory recovered; launching {worker_name}")
                    return
                if not announced:
                    print(f"warmup: memory pressure; delaying {worker_name}: {reason}")
                    announced = True
                if deadline is not None and now >= deadline:
                    raise TimeoutError(f"memory pressure did not recover within {timeout_seconds}s")
                wait_seconds = self._poll_interval_seconds
                if deadline is not None:
                    wait_seconds = min(wait_seconds, max(0, deadline - now))
                self._condition.wait(timeout=wait_seconds)

    def worker_finished(self) -> None:
        with self._condition:
            if self._active_workers < 1:
                raise RuntimeError("memory launch gate has no active worker")
            self._active_workers -= 1
            self._condition.notify_all()


def _format_mib(value: int) -> str:
    return f"{value / MIB:.1f} MiB"

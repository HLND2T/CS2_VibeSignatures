"""Windows Job Object memory controls for concurrent IDB warmup workers."""

from __future__ import annotations

import ctypes
import os
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Callable, Protocol

MIB = 1024 * 1024
DEFAULT_SOFT_LIMIT_RATIO = 0.85
DEFAULT_INITIAL_WORKER_RESERVATION_BYTES = 4 * 1024 * MIB
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
DEFAULT_LAUNCH_INTERVAL_SECONDS = 5.0

_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
_JOB_OBJECT_LIMIT_VIOLATION_INFORMATION_CLASS = 13
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobObjectBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _JobObjectLimitViolationInformation(ctypes.Structure):
    _fields_ = [
        ("LimitFlags", wintypes.DWORD),
        ("ViolationLimitFlags", wintypes.DWORD),
        ("IoReadBytes", ctypes.c_ulonglong),
        ("IoReadBytesLimit", ctypes.c_ulonglong),
        ("IoWriteBytes", ctypes.c_ulonglong),
        ("IoWriteBytesLimit", ctypes.c_ulonglong),
        ("PerJobUserTime", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("JobMemory", ctypes.c_ulonglong),
        ("JobMemoryLimit", ctypes.c_ulonglong),
        ("RateControlTolerance", ctypes.c_int),
        ("RateControlToleranceLimit", ctypes.c_int),
    ]


class _WindowsJobApi(Protocol):
    def create_job(self): ...

    def set_job_memory_limit(self, handle, budget_bytes: int) -> None: ...

    def assign_current_process(self, handle) -> None: ...

    def query_job_memory(self, handle) -> int: ...

    def close_handle(self, handle) -> None: ...


class _Kernel32JobApi:
    def __init__(self) -> None:
        if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
            raise OSError("Windows Job Objects require Windows")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_signatures()

    def _configure_signatures(self) -> None:
        self._kernel32.CreateJobObjectW.argtypes = [
            ctypes.POINTER(_SecurityAttributes),
            wintypes.LPCWSTR,
        ]
        self._kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self._kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        self._kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self._kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self._kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self._kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.LPDWORD,
        ]
        self._kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        self._kernel32.GetCurrentProcess.argtypes = []
        self._kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL

    @staticmethod
    def _raise_last_error() -> None:
        raise ctypes.WinError(ctypes.get_last_error())

    def create_job(self):
        handle = self._kernel32.CreateJobObjectW(None, None)
        if not handle:
            self._raise_last_error()
        return handle

    def set_job_memory_limit(self, handle, budget_bytes: int) -> None:
        limits = _JobObjectExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_JOB_MEMORY | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        limits.JobMemoryLimit = budget_bytes
        if not self._kernel32.SetInformationJobObject(
            handle,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            self._raise_last_error()

    def assign_current_process(self, handle) -> None:
        if not self._kernel32.AssignProcessToJobObject(handle, self._kernel32.GetCurrentProcess()):
            self._raise_last_error()

    def query_job_memory(self, handle) -> int:
        usage = _JobObjectLimitViolationInformation()
        returned_length = wintypes.DWORD()
        if not self._kernel32.QueryInformationJobObject(
            handle,
            _JOB_OBJECT_LIMIT_VIOLATION_INFORMATION_CLASS,
            ctypes.byref(usage),
            ctypes.sizeof(usage),
            ctypes.byref(returned_length),
        ):
            self._raise_last_error()
        return int(usage.JobMemory)

    def close_handle(self, handle) -> None:
        if not self._kernel32.CloseHandle(handle):
            self._raise_last_error()


@dataclass(frozen=True)
class MemorySnapshot:
    job_bytes: int


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

    def snapshot(self) -> MemorySnapshot:
        return MemorySnapshot(job_bytes=self._api.query_job_memory(self._handle))


class MemoryLaunchGate:
    """Delay worker admission until aggregate Job headroom is safe."""

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
    ) -> None:
        if budget_bytes < 1:
            raise ValueError("budget_bytes must be positive")
        if not 0 < soft_limit_ratio < 1:
            raise ValueError("soft_limit_ratio must be between zero and one")
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

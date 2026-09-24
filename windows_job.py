"""Small Windows Job Object API shared by IDA launchers and warmup memory limits."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
JOB_OBJECT_LIMIT_VIOLATION_INFORMATION_CLASS = 13
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102
INFINITE = 0xFFFFFFFF


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


class Kernel32JobApi:
    """Own Job handles without adding a pywin32 dependency."""

    def __init__(self) -> None:
        if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
            raise OSError("Windows Job Objects require Windows")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_signatures()

    def _configure_signatures(self) -> None:
        kernel32 = self._kernel32
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.LPDWORD,
        ]
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

    @staticmethod
    def _raise_last_error() -> None:
        raise ctypes.WinError(ctypes.get_last_error())

    def create_job(self):
        handle = self._kernel32.CreateJobObjectW(None, None)
        if not handle:
            self._raise_last_error()
        return handle

    def _set_limits(self, handle, flags: int, *, budget_bytes: int = 0) -> None:
        limits = _JobObjectExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = flags
        limits.JobMemoryLimit = budget_bytes
        if not self._kernel32.SetInformationJobObject(
            handle,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            self._raise_last_error()

    def set_job_memory_limit(self, handle, budget_bytes: int) -> None:
        self._set_limits(
            handle, JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, budget_bytes=budget_bytes
        )

    def set_kill_on_close(self, handle) -> None:
        self._set_limits(handle, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)

    def assign_current_process(self, handle) -> None:
        if not self._kernel32.AssignProcessToJobObject(handle, self._kernel32.GetCurrentProcess()):
            self._raise_last_error()

    def query_job_memory(self, handle) -> int:
        usage = _JobObjectLimitViolationInformation()
        returned_length = wintypes.DWORD()
        if not self._kernel32.QueryInformationJobObject(
            handle,
            JOB_OBJECT_LIMIT_VIOLATION_INFORMATION_CLASS,
            ctypes.byref(usage),
            ctypes.sizeof(usage),
            ctypes.byref(returned_length),
        ):
            self._raise_last_error()
        return int(usage.JobMemory)

    def open_live_process(self, pid: int):
        handle = self._kernel32.OpenProcess(SYNCHRONIZE, False, pid)
        if not handle:
            self._raise_last_error()
        try:
            if self.wait_for_process(handle, 0):
                raise ProcessLookupError(f"Parent process {pid} already exited")
        except Exception:
            self.close_handle(handle)
            raise
        return handle

    def wait_for_process(self, handle, timeout_ms: int) -> bool:
        result = self._kernel32.WaitForSingleObject(handle, timeout_ms)
        if result == WAIT_OBJECT_0:
            return True
        if result == WAIT_TIMEOUT:
            return False
        self._raise_last_error()

    def close_handle(self, handle) -> None:
        if not self._kernel32.CloseHandle(handle):
            self._raise_last_error()

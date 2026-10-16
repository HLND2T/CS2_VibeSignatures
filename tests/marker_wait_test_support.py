"""Support for tests that read markers published by a child process.

``Path.write_text`` creates the file before its contents land, so a reader that
checks ``exists()`` and then reads can observe an empty or partial file. The
helpers here publish a marker atomically and read one robustly.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, TypeVar

T = TypeVar("T")


def atomic_publish_source(target: str, payload: str) -> str:
    """Return child-process source that publishes ``payload`` at ``target``.

    ``target`` is an expression evaluating to a ``Path``; ``payload`` is an
    expression whose ``str`` is written. The sibling ``.tmp`` file is renamed
    into place, so a reader never sees a truncated marker.
    """
    return (
        f"_marker_target = {target}\n"
        f"_marker_tmp = _marker_target.with_name(_marker_target.name + '.tmp')\n"
        f"_marker_tmp.write_text(str({payload}), encoding='utf-8')\n"
        f"_marker_tmp.replace(_marker_target)\n"
    )


def read_until_parsed(path: Path, parse: Callable[[str], T], *, timeout: float = 10.0) -> T:
    """Read ``path`` and parse it, retrying until the payload is complete.

    Guards against a marker that another process published non-atomically: a
    single read can race an empty or partial file. Retries until ``parse``
    succeeds or the deadline passes, then surfaces the last error.
    """
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while True:
        try:
            return parse(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                raise AssertionError(f"marker {path} never parsed: {last_error}")
            time.sleep(0.05)

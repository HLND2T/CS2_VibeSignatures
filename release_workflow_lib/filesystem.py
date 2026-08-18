import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Callable


RemoveFunction = Callable[[str], object]


def _retry_readonly(function: RemoveFunction, path: str, exception: BaseException) -> None:
    if not isinstance(exception, PermissionError):
        raise exception
    os.chmod(path, stat.S_IWRITE)
    function(path)


def remove_tree(path: Path) -> None:
    path = Path(path)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_retry_readonly)
        return

    def retry_readonly_legacy(function: RemoveFunction, child: str, exc_info: tuple) -> None:
        _retry_readonly(function, child, exc_info[1])

    shutil.rmtree(path, onerror=retry_readonly_legacy)

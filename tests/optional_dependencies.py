"""Skip tests whose optional release tools are absent from this environment."""

import importlib.util
import shutil
import unittest


def requires_7z(test):
    return unittest.skipUnless(shutil.which("7z"), "7z executable is required on PATH")(test)


def requires_binsync(test):
    return unittest.skipUnless(
        importlib.util.find_spec("binsync") is not None, "binsync Python package is required"
    )(test)


def require_binsync() -> None:
    """Also guard fixtures called directly by tests outside the BinSync suites."""
    if importlib.util.find_spec("binsync") is None:
        raise unittest.SkipTest("binsync Python package is required")

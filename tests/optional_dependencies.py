"""Skip tests whose optional release tools are absent from this environment."""

import shutil
import unittest


def requires_7z(test):
    return unittest.skipUnless(shutil.which("7z"), "7z executable is required on PATH")(test)

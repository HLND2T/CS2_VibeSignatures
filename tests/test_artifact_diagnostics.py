from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from artifact_diagnostics import content_diff, read_artifact_bytes


class ArtifactDiagnosticsTests(unittest.TestCase):
    def test_text_facts_and_diff(self):
        result = content_diff("a.yaml", b"value: old\n", b"value: new\n")
        for expected in ("size=11 sha256=sha256:", "-value: old", "+value: new"):
            self.assertIn(expected, result)

    def test_missing_binary_and_newline_only(self):
        self.assertIn("expected: missing", content_diff("a", None, b"new\n"))
        self.assertIn("+new", content_diff("a", None, b"new\n"))
        self.assertIn("actual:   missing", content_diff("a", b"old\n", None))
        self.assertIn("not UTF-8", content_diff("a", b"\xff", b"\xfe"))
        self.assertIn("binary data", content_diff("a", b"\0a", b"\0b"))
        self.assertIn("line endings", content_diff("a", b"a\r\n", b"a\n"))

    def test_bounded_diff(self):
        result = content_diff("a", b"old\n" * 100, b"new\n" * 100, max_diff_lines=5)
        self.assertIn("truncated", result)
        self.assertLess(len(result.splitlines()), 15)
        result = content_diff("a", b"a" * 100000, b"b" * 100000)
        self.assertLess(len(result), 20000)

    def test_unreadable_file_is_a_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "a"
            target.write_bytes(b"a")
            with patch.object(Path, "read_bytes", side_effect=PermissionError("denied")):
                raw, error = read_artifact_bytes(target)
            self.assertIsNone(raw)
            self.assertIn("denied", error)


if __name__ == "__main__":
    unittest.main()

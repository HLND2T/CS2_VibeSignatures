import json
import ntpath
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ida_analyze_util import build_remote_text_export_py_eval


class TestBuildRemoteTextExportPyEval(unittest.TestCase):
    def test_build_remote_text_export_py_eval_rejects_relative_output_path(self) -> None:
        with self.assertRaises(ValueError):
            build_remote_text_export_py_eval(
                output_path="relative/detail.yaml",
                producer_code="payload_text = 'ok'",
                content_var="payload_text",
            )

    def test_build_remote_text_export_py_eval_contains_atomic_write_and_small_ack(self) -> None:
        script = build_remote_text_export_py_eval(
            output_path="/tmp/vcall-detail.yaml",
            producer_code="payload_text = 'ok'",
            content_var="payload_text",
            format_name="yaml",
        )
        self.assertIn("os.path.isabs(output_path)", script)
        self.assertIn("tmp_path = output_path + '.tmp'", script)
        self.assertIn("os.replace(tmp_path, output_path)", script)
        self.assertIn("'bytes_written'", script)
        self.assertIn("'format': format_name", script)

    def test_build_remote_text_export_py_eval_runs_with_separate_exec_namespaces(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "detail.txt"
            script = build_remote_text_export_py_eval(
                output_path=output_path,
                producer_code="payload_text = 'ok'",
                content_var="payload_text",
            )
            namespace = {}

            exec(script, {}, namespace)

            ack = json.loads(namespace["result"])
            self.assertTrue(ack["ok"])
            self.assertEqual(str(output_path), ack["output_path"])
            self.assertEqual("ok", output_path.read_text(encoding="utf-8"))

    def test_build_remote_text_export_py_eval_accepts_posix_absolute_path(self) -> None:
        # Simulate a non-POSIX host: on POSIX platforms ``os.path`` *is*
        # ``posixpath``, so patching ``os.path.isabs`` would also disable the
        # POSIX fallback this test is meant to exercise. Swapping ``os.path``
        # for ``ntpath`` keeps ``posixpath`` intact; the explicit ``ntpath``
        # patch keeps the case interpreter-independent (``ntpath.isabs``
        # stopped treating single-slash paths as absolute in Python 3.13).
        with (
            patch("ida_analyze_util.os.path", ntpath),
            patch("ida_analyze_util.ntpath.isabs", return_value=False),
        ):
            script = build_remote_text_export_py_eval(
                output_path="/tmp/vcall-detail.yaml",
                producer_code="payload_text = 'ok'",
                content_var="payload_text",
            )
            self.assertIn("posixpath.isabs(output_path)", script)

            with self.assertRaises(ValueError):
                build_remote_text_export_py_eval(
                    output_path="relative/detail.yaml",
                    producer_code="payload_text = 'ok'",
                    content_var="payload_text",
                )


if __name__ == "__main__":
    unittest.main()

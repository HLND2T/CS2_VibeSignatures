import argparse
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import run_cpp_tests as cpp


class TestCppPlatformSelection(unittest.TestCase):
    def run_case(self, tests, *, allow_empty=True, supported=True, outcome=None):
        with tempfile.TemporaryDirectory() as temporary:
            result_path = Path(temporary) / "result.json"
            args = argparse.Namespace(
                jobs=1,
                gamever="14190",
                configyaml="configs/14190.yaml",
                snapshot="unused.yaml",
                platform="linux",
                allow_empty=allow_empty,
                result_json=result_path,
                clang="clang++",
                std="c++20",
                debug=False,
            )
            store = SimpleNamespace(
                candidate_sha256="sha256:snapshot", config_sha256="sha256:config", game_version="14190", file_count=1
            )
            with (
                patch.object(cpp, "parse_args", return_value=args),
                patch.object(cpp, "open_snapshot_store", return_value=store),
                patch.object(cpp, "parse_config", return_value=tests),
                patch.object(cpp, "get_default_target_triple", return_value="x86_64-pc-linux-gnu"),
                patch.object(cpp, "probe_target_support", return_value={"supported": supported, "output": ""}),
                patch.object(cpp, "run_one_test", return_value=outcome or {"status": "ok", "output": ""}) as run,
            ):
                code = cpp.main()
                return code, json.loads(result_path.read_text()), run.call_count

    def test_only_requested_abi_executes(self):
        code, result, count = self.run_case(
            [
                {"target": "x86_64-pc-windows-msvc"},
                {"target": "x86_64-pc-linux-gnu"},
            ]
        )
        self.assertEqual((0, "passed", 1, 1), (code, result["status"], result["executed"], count))

    def test_legacy_empty_abi_is_explicit_and_requires_opt_in(self):
        tests = [{"target": "x86_64-pc-windows-msvc"}]
        code, result, count = self.run_case(tests)
        self.assertEqual((0, "no-tests", 0), (code, result["status"], count))
        self.assertEqual(1, self.run_case(tests, allow_empty=False)[0])

    def test_configured_unsupported_target_cannot_pass_as_empty(self):
        code, result, count = self.run_case([{"target": "x86_64-pc-linux-gnu"}], supported=False)
        self.assertEqual((1, "failed", 0), (code, result["status"], count))

    def test_compile_failure_and_invalid_target_fail(self):
        self.assertEqual(
            1,
            self.run_case(
                [{"target": "x86_64-pc-linux-gnu"}],
                outcome={"status": "compile_failed", "command": [], "output": "failed"},
            )[0],
        )
        self.assertEqual(1, self.run_case([{"target": "typo"}])[0])

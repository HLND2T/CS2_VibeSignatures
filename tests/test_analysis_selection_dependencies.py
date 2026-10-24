from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from ida_analyze_bin import _validate_selected_module_dependencies


class TestAnalysisSelectionDependencies(unittest.TestCase):
    def test_reports_scope_gap_before_execution_and_includes_transitive_consumer(self):
        modules = [
            {
                "name": "engine",
                "skills": [
                    {
                        "name": "inherit",
                        "expected_input": ["../server/base.{platform}.yaml"],
                        "expected_output": ["derived.{platform}.yaml"],
                    },
                    {"name": "consume", "expected_input": ["derived.{platform}.yaml"]},
                ],
            }
        ]
        with TemporaryDirectory() as root:
            args = SimpleNamespace(
                module_filter=["engine"], skill=None, artifactdir=root, gamever="test", platforms=["windows"]
            )
            with self.assertRaisesRegex(ValueError, "selected analysis scope.*missing producer") as error:
                _validate_selected_module_dependencies(modules, args)
            self.assertIn("engine/inherit", str(error.exception))
            self.assertIn("server/base.windows.yaml", str(error.exception))
            self.assertNotIn("linux", str(error.exception))

    def test_accepts_seeded_cross_module_dependency_and_local_downstream(self):
        modules = [
            {
                "name": "engine",
                "skills": [
                    {
                        "name": "inherit",
                        "expected_input": ["../server/base.{platform}.yaml"],
                        "expected_output": ["derived.{platform}.yaml"],
                    },
                    {"name": "consume", "expected_input": ["derived.{platform}.yaml"]},
                ],
            }
        ]
        with TemporaryDirectory() as root:
            artifact = Path(root) / "test/server/base.windows.yaml"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("func_name: base\n", encoding="utf-8")
            args = SimpleNamespace(
                module_filter=["engine"], skill=None, artifactdir=root, gamever="test", platforms=["windows"]
            )
            _validate_selected_module_dependencies(modules, args)

    def test_accepts_producer_in_selected_modules_without_cached_artifacts(self):
        modules = [
            {"name": "server", "skills": [{"name": "base", "expected_output": ["base.{platform}.yaml"]}]},
            {"name": "engine", "skills": [{"name": "inherit", "expected_input": ["../server/base.{platform}.yaml"]}]},
        ]
        with TemporaryDirectory() as root:
            args = SimpleNamespace(
                module_filter=["server", "engine"],
                skill=None,
                artifactdir=root,
                gamever="test",
                platforms=["windows", "linux"],
            )
            _validate_selected_module_dependencies(modules, args)
